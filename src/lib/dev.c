/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * API for applications
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/local-dev.h>
#include <ouroboros/sockets.h>
#include <ouroboros/fcntl.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/shm_flow_set.h>
#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/shm_rbuff.h>
#include <ouroboros/utils.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/qoscube.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define BUF_SIZE 1500

struct flow_set {
        size_t idx;
};

struct fqueue {
        int    fqueue[SHM_BUFFER_SIZE]; /* safe copy from shm */
        size_t fqsize;
        size_t next;
};

enum port_state {
        PORT_NULL = 0,
        PORT_INIT,
        PORT_ID_PENDING,
        PORT_ID_ASSIGNED,
        PORT_DESTROY
};

struct port {
        int             fd;

        enum port_state state;
        pthread_mutex_t state_lock;
        pthread_cond_t  state_cond;
};

struct flow {
        struct shm_rbuff *    rx_rb;
        struct shm_rbuff *    tx_rb;
        struct shm_flow_set * set;
        int                   port_id;
        int                   oflags;
        qoscube_t             cube;
        qosspec_t             spec;

        pid_t                 api;

        bool                  timesout;
        struct timespec       rcv_timeo;
};

struct {
        char *                ap_name;
        char *                daf_name;
        pid_t                 api;

        struct shm_rdrbuff *  rdrb;
        struct shm_flow_set * fqset;

        struct bmp *          fds;
        struct bmp *          fqueues;
        struct flow *         flows;
        struct port *         ports;

        pthread_rwlock_t      flows_lock;
} ai;

static void port_destroy(struct port * p)
{
        pthread_mutex_lock(&p->state_lock);

        if (p->state == PORT_DESTROY) {
                pthread_mutex_unlock(&p->state_lock);
                return;
        }

        if (p->state == PORT_ID_PENDING)
                p->state = PORT_DESTROY;
        else
                p->state = PORT_NULL;

        pthread_cond_signal(&p->state_cond);

        while (p->state != PORT_NULL)
                pthread_cond_wait(&p->state_cond, &p->state_lock);

        p->fd = -1;
        p->state = PORT_INIT;

        pthread_mutex_unlock(&p->state_lock);
}

static void port_set_state(struct port *   p,
                           enum port_state state)
{
        pthread_mutex_lock(&p->state_lock);

        if (p->state == PORT_DESTROY) {
                pthread_mutex_unlock(&p->state_lock);
                return;
        }

        p->state = state;
        pthread_cond_broadcast(&p->state_cond);

        pthread_mutex_unlock(&p->state_lock);
}

static enum port_state port_wait_assign(int port_id)
{
        enum port_state state;
        struct port *   p;

        pthread_rwlock_rdlock(&ai.flows_lock);

        p = &ai.ports[port_id];

        pthread_rwlock_unlock(&ai.flows_lock);

        pthread_mutex_lock(&p->state_lock);

        if (p->state == PORT_ID_ASSIGNED) {
                pthread_mutex_unlock(&p->state_lock);
                return PORT_ID_ASSIGNED;
        }

        if (p->state == PORT_INIT)
                p->state = PORT_ID_PENDING;

        while (p->state == PORT_ID_PENDING)
                pthread_cond_wait(&p->state_cond, &p->state_lock);

        if (p->state == PORT_DESTROY) {
                p->state = PORT_NULL;
                pthread_cond_broadcast(&p->state_cond);
        }

        state = p->state;

        assert(state != PORT_INIT);

        pthread_mutex_unlock(&p->state_lock);

        return state;
}

static int api_announce(char * ap_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code    = IRM_MSG_CODE__IRM_API_ANNOUNCE;
        msg.has_api = true;

        msg.api = ai.api;
        msg.ap_name = ap_name;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -EIRMD;
        }

        if (!recv_msg->has_result || (ret = recv_msg->result)) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return ret;
        }

        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

static void init_flow(int fd)
{
        assert(!(fd < 0));

        memset(&ai.flows[fd], 0, sizeof(ai.flows[fd]));

        ai.flows[fd].port_id  = -1;
        ai.flows[fd].api      = -1;
        ai.flows[fd].cube     = QOS_CUBE_BE;
}

static void reset_flow(int fd)
{
        assert (!(fd < 0));

        if (ai.flows[fd].port_id != -1)
                port_destroy(&ai.ports[ai.flows[fd].port_id]);

        if (ai.flows[fd].rx_rb != NULL)
                shm_rbuff_close(ai.flows[fd].rx_rb);

        if (ai.flows[fd].tx_rb != NULL)
                shm_rbuff_close(ai.flows[fd].tx_rb);

        if (ai.flows[fd].set != NULL)
                shm_flow_set_close(ai.flows[fd].set);

        init_flow(fd);
}

int ouroboros_init(const char * ap_name)
{
        int i = 0;

        assert(ai.ap_name == NULL);

        ai.api = getpid();
        ai.daf_name = NULL;

        ai.fds = bmp_create(AP_MAX_FLOWS - AP_RES_FDS, AP_RES_FDS);
        if (ai.fds == NULL)
                return -ENOMEM;

        ai.fqueues = bmp_create(AP_MAX_FQUEUES, 0);
        if (ai.fqueues == NULL) {
                bmp_destroy(ai.fds);
                return -ENOMEM;
        }

        ai.fqset = shm_flow_set_create();
        if (ai.fqset == NULL) {
                bmp_destroy(ai.fqueues);
                bmp_destroy(ai.fds);
                return -ENOMEM;
        }

        ai.rdrb = shm_rdrbuff_open();
        if (ai.rdrb == NULL) {
                shm_flow_set_destroy(ai.fqset);
                bmp_destroy(ai.fqueues);
                bmp_destroy(ai.fds);
                return -EIRMD;
        }

        ai.flows = malloc(sizeof(*ai.flows) * AP_MAX_FLOWS);
        if (ai.flows == NULL) {
                shm_rdrbuff_close(ai.rdrb);
                shm_flow_set_destroy(ai.fqset);
                bmp_destroy(ai.fqueues);
                bmp_destroy(ai.fds);
                return -ENOMEM;
        }

        for (i = 0; i < AP_MAX_FLOWS; ++i)
                init_flow(i);

        ai.ports = malloc(sizeof(*ai.ports) * IRMD_MAX_FLOWS);
        if (ai.ports == NULL) {
                free(ai.flows);
                shm_rdrbuff_close(ai.rdrb);
                shm_flow_set_destroy(ai.fqset);
                bmp_destroy(ai.fqueues);
                bmp_destroy(ai.fds);
                return -ENOMEM;
        }

        if (ap_name != NULL) {
                ai.ap_name = strdup(path_strip((char *) ap_name));
                if (ai.ap_name == NULL) {
                        free(ai.flows);
                        shm_rdrbuff_close(ai.rdrb);
                        shm_flow_set_destroy(ai.fqset);
                        bmp_destroy(ai.fqueues);
                        bmp_destroy(ai.fds);
                        return -ENOMEM;
                }

                if (api_announce((char *) ai.ap_name)) {
                        free(ai.ap_name);
                        free(ai.flows);
                        shm_rdrbuff_close(ai.rdrb);
                        shm_flow_set_destroy(ai.fqset);
                        bmp_destroy(ai.fqueues);
                        bmp_destroy(ai.fds);
                        return -EIRMD;
                }
        }

        for (i = 0; i < IRMD_MAX_FLOWS; ++i) {
                ai.ports[i].state = PORT_INIT;
                pthread_mutex_init(&ai.ports[i].state_lock, NULL);
                pthread_cond_init(&ai.ports[i].state_cond, NULL);
        }

        pthread_rwlock_init(&ai.flows_lock, NULL);

        return 0;
}

void ouroboros_fini()
{
        int i = 0;

        bmp_destroy(ai.fds);
        bmp_destroy(ai.fqueues);

        shm_flow_set_destroy(ai.fqset);

        if (ai.daf_name != NULL)
                free(ai.daf_name);

        if (ai.ap_name != NULL)
                free(ai.ap_name);

        pthread_rwlock_rdlock(&ai.flows_lock);

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                if (ai.flows[i].port_id != -1) {
                        ssize_t idx;
                        while ((idx = shm_rbuff_read(ai.flows[i].rx_rb)) >= 0)
                                shm_rdrbuff_remove(ai.rdrb, idx);
                        reset_flow(i);
                }
        }

        for (i = 0; i < IRMD_MAX_FLOWS; ++i) {
                pthread_mutex_destroy(&ai.ports[i].state_lock);
                pthread_cond_destroy(&ai.ports[i].state_cond);
        }

        shm_rdrbuff_close(ai.rdrb);

        free(ai.flows);
        free(ai.ports);

        pthread_rwlock_unlock(&ai.flows_lock);

        pthread_rwlock_destroy(&ai.flows_lock);
}

int flow_accept(qosspec_t *             qs,
                const struct timespec * timeo)
{
        irm_msg_t           msg      = IRM_MSG__INIT;
        irm_msg_t *         recv_msg = NULL;
        int                 fd       = -1;
        frct_enroll_msg_t * frct_enroll;
        qosspec_t           spec;
        uint8_t             data[BUF_SIZE];
        ssize_t             n;

        msg.code    = IRM_MSG_CODE__IRM_FLOW_ACCEPT;
        msg.has_api = true;
        msg.api     = ai.api;

        if (timeo != NULL) {
                msg.has_timeo_sec = true;
                msg.has_timeo_nsec = true;
                msg.timeo_sec  = timeo->tv_sec;
                msg.timeo_nsec = timeo->tv_nsec;
        }

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EIRMD;
        }

        if (recv_msg->result !=  0) {
                int res = recv_msg->result;
                irm_msg__free_unpacked(recv_msg, NULL);
                return res;
        }

        if (!recv_msg->has_api || !recv_msg->has_port_id ||
            !recv_msg->has_qoscube) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EIRMD;
        }

        pthread_rwlock_wrlock(&ai.flows_lock);

        fd = bmp_allocate(ai.fds);
        if (!bmp_is_id_valid(ai.fds, fd)) {
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EBADF;
        }

        ai.flows[fd].rx_rb = shm_rbuff_open(ai.api, recv_msg->port_id);
        if (ai.flows[fd].rx_rb == NULL) {
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -ENOMEM;
        }

        ai.flows[fd].tx_rb = shm_rbuff_open(recv_msg->api, recv_msg->port_id);
        if (ai.flows[fd].tx_rb == NULL) {
                reset_flow(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -ENOMEM;
        }

        ai.flows[fd].set = shm_flow_set_open(recv_msg->api);
        if (ai.flows[fd].set == NULL) {
                reset_flow(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -ENOMEM;
        }

        ai.flows[fd].port_id = recv_msg->port_id;
        ai.flows[fd].oflags  = FLOW_O_DEFAULT;
        ai.flows[fd].api     = recv_msg->api;
        ai.flows[fd].cube    = recv_msg->qoscube;

        assert(ai.ports[ai.flows[fd].port_id].state == PORT_INIT);

        spec = qos_cube_to_spec(recv_msg->qoscube);

        ai.ports[recv_msg->port_id].fd    = fd;
        ai.ports[recv_msg->port_id].state = PORT_ID_ASSIGNED;

        pthread_rwlock_unlock(&ai.flows_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        n = flow_read(fd, data, BUF_SIZE);
        if (n < 0) {
                flow_dealloc(fd);
                return n;
        }

        frct_enroll = frct_enroll_msg__unpack(NULL, n, data);
        if (frct_enroll == NULL) {
                flow_dealloc(fd);
                return -1;
        }

        spec.resource_control = frct_enroll->resource_control;
        spec.reliable = frct_enroll->reliable;
        spec.error_check = frct_enroll->error_check;
        spec.ordered = frct_enroll->ordered;
        spec.partial = frct_enroll->partial;

        frct_enroll_msg__free_unpacked(frct_enroll, NULL);

        pthread_rwlock_wrlock(&ai.flows_lock);
        ai.flows[fd].spec = spec;
        pthread_rwlock_unlock(&ai.flows_lock);

        if (qs != NULL)
                *qs = spec;

        return fd;
}

int flow_alloc(const char *            dst_name,
               qosspec_t *             qs,
               const struct timespec * timeo)
{
        irm_msg_t         msg         = IRM_MSG__INIT;
        frct_enroll_msg_t frct_enroll = FRCT_ENROLL_MSG__INIT;
        irm_msg_t *       recv_msg    = NULL;
        qoscube_t         qc          = QOS_CUBE_BE;
        int               fd;
        ssize_t           len;
        uint8_t *         data;
        int               ret;

        msg.code        = IRM_MSG_CODE__IRM_FLOW_ALLOC;
        msg.dst_name    = (char *) dst_name;
        msg.has_api     = true;
        msg.has_qoscube = true;
        msg.api         = ai.api;

        if (qs != NULL) {
                frct_enroll.resource_control = qs->resource_control;
                frct_enroll.reliable = qs->reliable;
                frct_enroll.error_check = qs->error_check;
                frct_enroll.ordered = qs->ordered;
                frct_enroll.partial = qs->partial;

                qc = qos_spec_to_cube(*qs);
        }

        msg.qoscube = qc;

        if (timeo != NULL) {
                msg.has_timeo_sec = true;
                msg.has_timeo_nsec = true;
                msg.timeo_sec  = timeo->tv_sec;
                msg.timeo_nsec = timeo->tv_nsec;
        }

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EIRMD;
        }

        if (recv_msg->result !=  0) {
                int res =  recv_msg->result;
                irm_msg__free_unpacked(recv_msg, NULL);
                return res;
        }

        if (!recv_msg->has_api || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EIRMD;
        }

        pthread_rwlock_wrlock(&ai.flows_lock);

        fd = bmp_allocate(ai.fds);
        if (!bmp_is_id_valid(ai.fds, fd)) {
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EBADF;
        }

        ai.flows[fd].rx_rb = shm_rbuff_open(ai.api, recv_msg->port_id);
        if (ai.flows[fd].rx_rb == NULL) {
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -ENOMEM;
        }

        ai.flows[fd].tx_rb = shm_rbuff_open(recv_msg->api, recv_msg->port_id);
        if (ai.flows[fd].tx_rb == NULL) {
                reset_flow(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -ENOMEM;
        }

        ai.flows[fd].set = shm_flow_set_open(recv_msg->api);
        if (ai.flows[fd].set == NULL) {
                reset_flow(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -ENOMEM;
        }

        ai.flows[fd].port_id = recv_msg->port_id;
        ai.flows[fd].oflags  = FLOW_O_DEFAULT;
        ai.flows[fd].api     = recv_msg->api;
        ai.flows[fd].cube    = recv_msg->qoscube;

        assert(ai.ports[recv_msg->port_id].state == PORT_INIT);

        ai.ports[recv_msg->port_id].fd    = fd;
        ai.ports[recv_msg->port_id].state = PORT_ID_ASSIGNED;

        irm_msg__free_unpacked(recv_msg, NULL);

        pthread_rwlock_unlock(&ai.flows_lock);

        len = frct_enroll_msg__get_packed_size(&frct_enroll);
        if (len < 0) {
                flow_dealloc(fd);
                return -1;
        }

        data = malloc(len);
        if (data == NULL) {
                flow_dealloc(fd);
                return -ENOMEM;
        }

        frct_enroll_msg__pack(&frct_enroll, data);

        ret = flow_write(fd, data, len);
        if (ret < 0) {
                flow_dealloc(fd);
                free(data);
                return ret;
        }

        free(data);

        return fd;
}

int flow_dealloc(int fd)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;

        if (fd < 0)
                return -EINVAL;

        msg.code         = IRM_MSG_CODE__IRM_FLOW_DEALLOC;
        msg.has_port_id  = true;
        msg.has_api      = true;
        msg.api          = ai.api;

        pthread_rwlock_rdlock(&ai.flows_lock);

        assert(!(ai.flows[fd].port_id < 0));

        msg.port_id = ai.flows[fd].port_id;

        pthread_rwlock_unlock(&ai.flows_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                assert(false);
                return -1;
        }

        irm_msg__free_unpacked(recv_msg, NULL);

        pthread_rwlock_wrlock(&ai.flows_lock);

        reset_flow(fd);
        bmp_release(ai.fds, fd);

        pthread_rwlock_unlock(&ai.flows_lock);

        return 0;
}

int flow_set_flags(int fd,
                   int flags)
{
        int old;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_wrlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -ENOTALLOC;
        }

        old = ai.flows[fd].oflags;

        ai.flows[fd].oflags = flags;
        if (flags & FLOW_O_WRONLY)
                shm_rbuff_block(ai.flows[fd].rx_rb);
        if (flags & FLOW_O_RDWR)
                shm_rbuff_unblock(ai.flows[fd].rx_rb);

        pthread_rwlock_unlock(&ai.flows_lock);

        return old;
}

int flow_get_flags(int fd)
{
        int old;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_wrlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -ENOTALLOC;
        }

        old = ai.flows[fd].oflags;

        pthread_rwlock_unlock(&ai.flows_lock);

        return old;
}

int flow_get_timeout(int               fd,
                     struct timespec * timeo)
{
        int ret = 0;

        if (fd < 0 || fd >= AP_MAX_FLOWS || timeo == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -ENOTALLOC;
        }

        if (ai.flows[fd].timesout)
                *timeo = ai.flows[fd].rcv_timeo;
        else
                ret = -EPERM;

        pthread_rwlock_unlock(&ai.flows_lock);

        return ret;
}

int flow_set_timeout(int                     fd,
                     const struct timespec * timeo)
{
        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EINVAL;

        pthread_rwlock_wrlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -ENOTALLOC;
        }

        if (timeo == NULL) {
                ai.flows[fd].timesout = false;
        } else {
                ai.flows[fd].timesout = true;
                ai.flows[fd].rcv_timeo = *timeo;
        }

        pthread_rwlock_unlock(&ai.flows_lock);

        return 0;
}

int flow_get_qosspec(int         fd,
                     qosspec_t * qs)
{
        if (fd < 0 || fd >= AP_MAX_FLOWS || qs == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -ENOTALLOC;
        }

        *qs = ai.flows[fd].spec;

        pthread_rwlock_unlock(&ai.flows_lock);

        return 0;
}

ssize_t flow_write(int          fd,
                   const void * buf,
                   size_t       count)
{
        ssize_t idx;

        if (buf == NULL)
                return 0;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -ENOTALLOC;
        }

        if ((ai.flows[fd].oflags & FLOW_O_ACCMODE) == FLOW_O_RDONLY) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -EPERM;
        }

        if (ai.flows[fd].oflags & FLOW_O_NONBLOCK) {
                idx = shm_rdrbuff_write(ai.rdrb,
                                       DU_BUFF_HEADSPACE,
                                       DU_BUFF_TAILSPACE,
                                       buf,
                                       count);
                if (idx < 0) {
                        pthread_rwlock_unlock(&ai.flows_lock);
                        return idx;
                }

                if (shm_rbuff_write(ai.flows[fd].tx_rb, idx) < 0) {
                        shm_rdrbuff_remove(ai.rdrb, idx);
                        pthread_rwlock_unlock(&ai.flows_lock);
                        return -ENOTALLOC;
                }
        } else { /* blocking */
                struct shm_rdrbuff * rdrb = ai.rdrb;
                struct shm_rbuff * tx_rb  = ai.flows[fd].tx_rb;

                pthread_rwlock_unlock(&ai.flows_lock);

                assert(tx_rb);

                idx = shm_rdrbuff_write_b(rdrb,
                                          DU_BUFF_HEADSPACE,
                                          DU_BUFF_TAILSPACE,
                                          buf,
                                          count);

                if (shm_rbuff_write(tx_rb, idx) < 0) {
                        shm_rdrbuff_remove(rdrb, idx);
                        return -ENOTALLOC;
                }

                pthread_rwlock_rdlock(&ai.flows_lock);
        }

        shm_flow_set_notify(ai.flows[fd].set, ai.flows[fd].port_id);

        pthread_rwlock_unlock(&ai.flows_lock);

        return 0;
}

ssize_t flow_read(int    fd,
                  void * buf,
                  size_t count)
{
        ssize_t idx = -1;
        ssize_t n;
        uint8_t * sdu;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -ENOTALLOC;
        }

        if (ai.flows[fd].oflags & FLOW_O_NONBLOCK) {
                idx = shm_rbuff_read(ai.flows[fd].rx_rb);
                pthread_rwlock_unlock(&ai.flows_lock);
        } else {
                struct shm_rbuff * rb   = ai.flows[fd].rx_rb;
                bool timeo = ai.flows[fd].timesout;
                struct timespec timeout = ai.flows[fd].rcv_timeo;

                pthread_rwlock_unlock(&ai.flows_lock);

                if (timeo)
                        idx = shm_rbuff_read_b(rb, &timeout);
                else
                        idx = shm_rbuff_read_b(rb, NULL);
        }

        if (idx < 0) {
                assert(idx == -EAGAIN || idx == -ETIMEDOUT);
                return idx;
        }

        n = shm_rdrbuff_read(&sdu, ai.rdrb, idx);
        if (n < 0)
                return -1;

        memcpy(buf, sdu, MIN((size_t) n, count));

        shm_rdrbuff_remove(ai.rdrb, idx);

        return n;
}

/* fqueue functions */

struct flow_set * flow_set_create()
{
        struct flow_set * set = malloc(sizeof(*set));
        if (set == NULL)
                return NULL;

        assert(ai.fqueues);

        set->idx = bmp_allocate(ai.fqueues);
        if (!bmp_is_id_valid(ai.fqueues, set->idx)) {
                free(set);
                return NULL;
        }

        return set;
}

void flow_set_destroy(struct flow_set * set)
{
        if (set == NULL)
                return;

        flow_set_zero(set);
        bmp_release(ai.fqueues, set->idx);
        free(set);
}

struct fqueue * fqueue_create()
{
        struct fqueue * fq = malloc(sizeof(*fq));
        if (fq == NULL)
                return NULL;

        memset(fq->fqueue, -1, (SHM_BUFFER_SIZE) * sizeof(*fq->fqueue));
        fq->fqsize = 0;
        fq->next   = 0;

        return fq;
}

void fqueue_destroy(struct fqueue * fq)
{
        if (fq == NULL)
                return;

        free(fq);
}

void flow_set_zero(struct flow_set * set)
{
        if (set == NULL)
                return;

        shm_flow_set_zero(ai.fqset, set->idx);
}

int flow_set_add(struct flow_set * set,
                 int               fd)
{
        int ret;
        size_t sdus;
        size_t i;

        if (set == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&ai.flows_lock);

        ret = shm_flow_set_add(ai.fqset, set->idx, ai.flows[fd].port_id);

        sdus = shm_rbuff_queued(ai.flows[fd].rx_rb);
        for (i = 0; i < sdus; i++)
                shm_flow_set_notify(ai.fqset, ai.flows[fd].port_id);

        pthread_rwlock_unlock(&ai.flows_lock);

        return ret;
}

void flow_set_del(struct flow_set * set,
                  int               fd)
{
        if (set == NULL)
                return;

        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].port_id >= 0)
                shm_flow_set_del(ai.fqset, set->idx, ai.flows[fd].port_id);

        pthread_rwlock_unlock(&ai.flows_lock);
}

bool flow_set_has(const struct flow_set * set,
                  int                     fd)
{
        bool ret = false;

        if (set == NULL || fd < 0)
                return false;

        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return false;
        }

        ret = (shm_flow_set_has(ai.fqset, set->idx, ai.flows[fd].port_id) == 1);

        pthread_rwlock_unlock(&ai.flows_lock);

        return ret;
}

int fqueue_next(struct fqueue * fq)
{
        int fd;

        if (fq == NULL)
                return -EINVAL;

        if (fq->fqsize == 0)
                return -EPERM;

        pthread_rwlock_rdlock(&ai.flows_lock);

        fd = ai.ports[fq->fqueue[fq->next++]].fd;

        pthread_rwlock_unlock(&ai.flows_lock);

        if (fq->next == fq->fqsize) {
                fq->fqsize = 0;
                fq->next = 0;
        }

        return fd;
}

int flow_event_wait(struct flow_set *       set,
                    struct fqueue *         fq,
                    const struct timespec * timeout)
{
        ssize_t ret;

        if (set == NULL || fq == NULL)
                return -EINVAL;

        if (fq->fqsize > 0)
                return fq->fqsize;

        assert(!fq->next);

        ret = shm_flow_set_wait(ai.fqset, set->idx, fq->fqueue, timeout);
        if (ret == -ETIMEDOUT) {
                fq->fqsize = 0;
                return -ETIMEDOUT;
        }

        fq->fqsize = ret;

        assert(ret);

        return ret;
}

/* ipcp-dev functions */

int np1_flow_alloc(pid_t n_api,
                   int   port_id)
{
        int fd;

        pthread_rwlock_wrlock(&ai.flows_lock);

        fd = bmp_allocate(ai.fds);
        if (!bmp_is_id_valid(ai.fds, fd)) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -1;
        }

        ai.flows[fd].rx_rb = shm_rbuff_open(ai.api, port_id);
        if (ai.flows[fd].rx_rb == NULL) {
                reset_flow(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                return -1;
        }

        ai.flows[fd].tx_rb = shm_rbuff_open(n_api, port_id);
        if (ai.flows[fd].tx_rb == NULL) {
                reset_flow(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                return -1;
        }

        ai.flows[fd].set = shm_flow_set_open(n_api);
        if (ai.flows[fd].set == NULL) {
                reset_flow(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                return -1;
        }

        ai.flows[fd].port_id = port_id;
        ai.flows[fd].oflags  = FLOW_O_DEFAULT;
        ai.flows[fd].api     = n_api;

        ai.ports[port_id].fd    = fd;
        ai.ports[port_id].state = PORT_ID_ASSIGNED;

        pthread_rwlock_unlock(&ai.flows_lock);

        return fd;
}

int np1_flow_dealloc(int port_id)
{
        int fd;

        pthread_rwlock_rdlock(&ai.flows_lock);

        fd = ai.ports[port_id].fd;

        pthread_rwlock_unlock(&ai.flows_lock);

        return fd;
}

int np1_flow_resp(int port_id)
{
        int fd;

        if (port_wait_assign(port_id) != PORT_ID_ASSIGNED)
                return -1;

        pthread_rwlock_rdlock(&ai.flows_lock);

        fd = ai.ports[port_id].fd;

        pthread_rwlock_unlock(&ai.flows_lock);

        return fd;
}

int ipcp_create_r(pid_t api,
                  int   result)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code       = IRM_MSG_CODE__IPCP_CREATE_R;
        msg.has_api    = true;
        msg.api        = api;
        msg.has_result = true;
        msg.result     = result;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_req_arr(pid_t           api,
                      const uint8_t * dst,
                      size_t          len,
                      qoscube_t       cube)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int port_id = -1;
        int fd = -1;

        if (dst == NULL)
                return -EINVAL;

        msg.code        = IRM_MSG_CODE__IPCP_FLOW_REQ_ARR;
        msg.has_api     = true;
        msg.api         = api;
        msg.has_hash    = true;
        msg.hash.len    = len;
        msg.hash.data   = (uint8_t *) dst;
        msg.has_qoscube = true;
        msg.qoscube     = cube;

        pthread_rwlock_wrlock(&ai.flows_lock);

        fd = bmp_allocate(ai.fds);
        if (!bmp_is_id_valid(ai.fds, fd)) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -1; /* -ENOMOREFDS */
        }

        pthread_rwlock_unlock(&ai.flows_lock);

        recv_msg = send_recv_irm_msg(&msg);

        pthread_rwlock_wrlock(&ai.flows_lock);

        if (recv_msg == NULL) {
                ai.ports[fd].state = PORT_INIT;
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                return -EIRMD;
        }

        if (!recv_msg->has_port_id || !recv_msg->has_api) {
                ai.ports[fd].state = PORT_INIT;
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        if (recv_msg->has_result && recv_msg->result) {
                ai.ports[fd].state = PORT_INIT;
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        port_id = recv_msg->port_id;
        if (port_id < 0) {
                ai.ports[fd].state = PORT_INIT;
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ai.flows[fd].rx_rb = shm_rbuff_open(ai.api, port_id);
        if (ai.flows[fd].rx_rb == NULL) {
                reset_flow(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ai.flows[fd].tx_rb = shm_rbuff_open(recv_msg->api, port_id);
        if (ai.flows[fd].tx_rb == NULL) {
                reset_flow(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ai.flows[fd].set = shm_flow_set_open(recv_msg->api);
        if (ai.flows[fd].set == NULL) {
                reset_flow(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ai.flows[fd].port_id = port_id;
        ai.flows[fd].oflags  = FLOW_O_DEFAULT;

        ai.ports[port_id].fd = fd;
        port_set_state(&ai.ports[port_id], PORT_ID_ASSIGNED);

        pthread_rwlock_unlock(&ai.flows_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;
}

int ipcp_flow_alloc_reply(int fd,
                          int response)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code         = IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY;
        msg.has_port_id  = true;

        pthread_rwlock_rdlock(&ai.flows_lock);

        msg.port_id = ai.flows[fd].port_id;

        pthread_rwlock_unlock(&ai.flows_lock);

        msg.has_response = true;
        msg.response     = response;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;

        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_read(int                   fd,
                   struct shm_du_buff ** sdb)
{
        ssize_t idx = -1;
        int port_id = -1;
        struct shm_rbuff * rb;

        assert(fd >=0);
        assert(sdb);

        pthread_rwlock_rdlock(&ai.flows_lock);

        if ((port_id = ai.flows[fd].port_id) < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -ENOTALLOC;
        }

        rb = ai.flows[fd].rx_rb;

        pthread_rwlock_unlock(&ai.flows_lock);

        idx = shm_rbuff_read(rb);
        if (idx < 0)
                return idx;

        *sdb = shm_rdrbuff_get(ai.rdrb, idx);

        return 0;
}

int ipcp_flow_write(int                  fd,
                    struct shm_du_buff * sdb)
{
        size_t idx;

        if (sdb == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -ENOTALLOC;
        }

        if ((ai.flows[fd].oflags & FLOW_O_ACCMODE) == FLOW_O_RDONLY) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -EPERM;
        }

        assert(ai.flows[fd].tx_rb);

        idx = shm_du_buff_get_idx(sdb);

        shm_rbuff_write(ai.flows[fd].tx_rb, idx);
        shm_flow_set_notify(ai.flows[fd].set, ai.flows[fd].port_id);

        pthread_rwlock_unlock(&ai.flows_lock);

        return 0;
}

int ipcp_sdb_reserve(struct shm_du_buff ** sdb,
                     size_t                len)
{
        struct shm_rdrbuff * rdrb;
        ssize_t              idx;

        rdrb = ai.rdrb;

        idx = shm_rdrbuff_write_b(rdrb,
                                  DU_BUFF_HEADSPACE,
                                  DU_BUFF_TAILSPACE,
                                  NULL,
                                  len);

        if (idx < 0)
                return -1;

        *sdb = shm_rdrbuff_get(rdrb, idx);

        return 0;
}

void ipcp_flow_fini(int fd)
{
        struct shm_rbuff * rx_rb;

        flow_set_flags(fd, FLOW_O_WRONLY);

        pthread_rwlock_rdlock(&ai.flows_lock);

        rx_rb = ai.flows[fd].rx_rb;

        pthread_rwlock_unlock(&ai.flows_lock);

        shm_rbuff_fini(rx_rb);
}

int ipcp_flow_get_qoscube(int         fd,
                          qoscube_t * cube)
{
        if (fd < 0 || fd >= AP_MAX_FLOWS || cube == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -ENOTALLOC;
        }

        *cube = ai.flows[fd].cube;

        pthread_rwlock_unlock(&ai.flows_lock);

        return 0;
}

ssize_t local_flow_read(int fd)
{
        ssize_t ret;

        assert(fd >= 0);

        pthread_rwlock_rdlock(&ai.flows_lock);

        ret = shm_rbuff_read(ai.flows[fd].rx_rb);

        pthread_rwlock_unlock(&ai.flows_lock);

        return ret;
}

int local_flow_write(int    fd,
                     size_t idx)
{
        if (fd < 0)
                return -EINVAL;

        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -ENOTALLOC;
        }

        shm_rbuff_write(ai.flows[fd].tx_rb, idx);

        shm_flow_set_notify(ai.flows[fd].set, ai.flows[fd].port_id);

        pthread_rwlock_unlock(&ai.flows_lock);

        return 0;
}

int ipcp_read_shim(int                   fd,
                   struct shm_du_buff ** sdb)
{
        ssize_t idx;

        pthread_rwlock_rdlock(&ai.flows_lock);

        assert(ai.flows[fd].rx_rb);

        idx = shm_rbuff_read(ai.flows[fd].rx_rb);
        if (idx < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                return -EAGAIN;
        }

        *sdb = shm_rdrbuff_get(ai.rdrb, idx);

        pthread_rwlock_unlock(&ai.flows_lock);

        return 0;
}

void ipcp_sdb_release(struct shm_du_buff * sdb)
{
        shm_rdrbuff_remove(ai.rdrb, shm_du_buff_get_idx(sdb));
}
