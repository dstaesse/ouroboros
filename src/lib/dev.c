/*
 * Ouroboros - Copyright (C) 2016
 *
 * API for applications
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/sockets.h>
#include <ouroboros/fcntl.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/shm_ap_rbuff.h>
#include <ouroboros/utils.h>
#include <ouroboros/select.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

struct flow_set {
        bool dirty;
        bool b[IRMD_MAX_FLOWS]; /* working copy */
        bool s[IRMD_MAX_FLOWS]; /* safe copy */
        pthread_rwlock_t lock;
};

enum port_state {
        PORT_NULL = 0,
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
        p->state = PORT_ID_PENDING;

        pthread_mutex_unlock(&p->state_lock);
}

static void port_set_state(struct port * p, enum port_state state)
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

enum port_state port_wait_assign(struct port * p)
{
        enum port_state state;

        pthread_mutex_lock(&p->state_lock);

        if (p->state != PORT_ID_PENDING) {
                pthread_mutex_unlock(&p->state_lock);
                return -1;
        }

        while (!(p->state == PORT_ID_ASSIGNED || p->state == PORT_DESTROY))
                pthread_cond_wait(&p->state_cond, &p->state_lock);

        if (p->state == PORT_DESTROY) {
                p->state = PORT_NULL;
                pthread_cond_broadcast(&p->state_cond);
        }

        state = p->state;

        pthread_mutex_unlock(&p->state_lock);

        return state;
}

struct flow {
        struct shm_ap_rbuff * rb;
        int                   port_id;
        int                   oflags;

        pid_t                 api;

        struct timespec *     timeout;
};

struct {
        char *                ap_name;
        char *                daf_name;
        pid_t                 api;

        struct shm_rdrbuff *  rdrb;
        struct shm_ap_rbuff * rb;
        pthread_rwlock_t      data_lock;

        struct bmp *          fds;
        struct flow *         flows;
        struct port *         ports;

        pthread_rwlock_t      flows_lock;
} ai;

static int api_announce(char * ap_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code    = IRM_MSG_CODE__IRM_API_ANNOUNCE;
        msg.has_api = true;

        pthread_rwlock_rdlock(&ai.data_lock);

        msg.api = ai.api;
        msg.ap_name = ap_name;

        pthread_rwlock_unlock(&ai.data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (!recv_msg->has_result || (ret = recv_msg->result)) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return ret;
        }

        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ap_init(char * ap_name)
{
        int i = 0;

        ap_name = path_strip(ap_name);

        ai.api = getpid();
        ai.ap_name = ap_name;
        ai.daf_name = NULL;

        ai.fds = bmp_create(AP_MAX_FLOWS, 0);
        if (ai.fds == NULL)
                return -ENOMEM;

        ai.rdrb = shm_rdrbuff_open();
        if (ai.rdrb == NULL) {
                bmp_destroy(ai.fds);
                return -1;
        }

        ai.rb = shm_ap_rbuff_create();
        if (ai.rb == NULL) {
                shm_rdrbuff_close(ai.rdrb);
                bmp_destroy(ai.fds);
                return -1;
        }

        ai.flows = malloc(sizeof(*ai.flows) * AP_MAX_FLOWS);
        if (ai.flows == NULL) {
                shm_ap_rbuff_destroy(ai.rb);
                shm_rdrbuff_close(ai.rdrb);
                bmp_destroy(ai.fds);
                return -1;
        }

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                ai.flows[i].rb = NULL;
                ai.flows[i].port_id = -1;
                ai.flows[i].oflags = 0;
                ai.flows[i].api = -1;
                ai.flows[i].timeout = NULL;
        }

        ai.ports = malloc(sizeof(*ai.ports) * IRMD_MAX_FLOWS);
        if (ai.flows == NULL) {
                free(ai.flows);
                shm_ap_rbuff_destroy(ai.rb);
                shm_rdrbuff_close(ai.rdrb);
                bmp_destroy(ai.fds);
                return -1;
        }

        for (i = 0; i < IRMD_MAX_FLOWS; ++i) {
                ai.ports[i].state = PORT_ID_PENDING;
                pthread_mutex_init(&ai.ports[i].state_lock, NULL);
                pthread_cond_init(&ai.ports[i].state_cond, NULL);
        }

        pthread_rwlock_init(&ai.flows_lock, NULL);
        pthread_rwlock_init(&ai.data_lock, NULL);

        if (ap_name != NULL)
                return api_announce(ap_name);

        return 0;
}

void ap_fini()
{
        int i = 0;

        pthread_rwlock_wrlock(&ai.data_lock);

        /* remove all remaining sdus */
        while ((i = shm_ap_rbuff_pop_idx(ai.rb)) >= 0)
                shm_rdrbuff_remove(ai.rdrb, i);

        if (ai.fds != NULL)
                bmp_destroy(ai.fds);
        if (ai.rb != NULL)
                shm_ap_rbuff_destroy(ai.rb);
        if (ai.rdrb != NULL)
                shm_rdrbuff_close(ai.rdrb);

        if (ai.daf_name != NULL)
                free(ai.daf_name);

        pthread_rwlock_rdlock(&ai.flows_lock);

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                if (ai.flows[i].rb != NULL)
                        shm_ap_rbuff_close(ai.flows[i].rb);
                if (ai.flows[i].timeout != NULL)
                        free(ai.flows[i].timeout);
        }

        for (i = 0; i < IRMD_MAX_FLOWS; ++i) {
                ai.ports[i].state = PORT_NULL;
                pthread_mutex_destroy(&ai.ports[i].state_lock);
                pthread_cond_destroy(&ai.ports[i].state_cond);
        }

        free(ai.flows);
        free(ai.ports);

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        pthread_rwlock_destroy(&ai.flows_lock);
        pthread_rwlock_destroy(&ai.data_lock);
}


int flow_accept(char ** ae_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int fd = -1;

        msg.code    = IRM_MSG_CODE__IRM_FLOW_ACCEPT;
        msg.has_api = true;

        pthread_rwlock_rdlock(&ai.data_lock);

        msg.api     = ai.api;

        pthread_rwlock_unlock(&ai.data_lock);

        recv_msg = send_recv_irm_msg_b(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_api || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_wrlock(&ai.flows_lock);

        fd = bmp_allocate(ai.fds);
        if (!bmp_is_id_valid(ai.fds, fd)) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ai.flows[fd].rb = shm_ap_rbuff_open(recv_msg->api);
        if (ai.flows[fd].rb == NULL) {
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        if (ae_name != NULL) {
                *ae_name = strdup(recv_msg->ae_name);
                if (*ae_name == NULL) {
                        shm_ap_rbuff_close(ai.flows[fd].rb);
                        bmp_release(ai.fds, fd);
                        pthread_rwlock_unlock(&ai.flows_lock);
                        pthread_rwlock_unlock(&ai.data_lock);
                        irm_msg__free_unpacked(recv_msg, NULL);
                        return -ENOMEM;
                }
        }

        ai.flows[fd].port_id = recv_msg->port_id;
        ai.flows[fd].oflags  = FLOW_O_DEFAULT;
        ai.flows[fd].api     = recv_msg->api;

        ai.ports[recv_msg->port_id].fd    = fd;
        ai.ports[recv_msg->port_id].state = PORT_ID_ASSIGNED;

        shm_ap_rbuff_open_port(ai.rb, recv_msg->port_id);

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;
}

int flow_alloc_resp(int fd, int response)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        msg.code         = IRM_MSG_CODE__IRM_FLOW_ALLOC_RESP;
        msg.has_api      = true;
        msg.api          = ai.api;
        msg.has_port_id  = true;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -ENOTALLOC;
        }

        msg.port_id      = ai.flows[fd].port_id;

        pthread_rwlock_unlock(&ai.flows_lock);

        msg.has_response = true;
        msg.response     = response;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                pthread_rwlock_unlock(&ai.data_lock);
                return -1;
        }

        if (!recv_msg->has_result) {
                pthread_rwlock_unlock(&ai.data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;

        pthread_rwlock_unlock(&ai.data_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int flow_alloc(char * dst_name, char * src_ae_name, struct qos_spec * qos)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int fd = -1;

        if (dst_name == NULL)
                return -EINVAL;

        if (src_ae_name == NULL)
                src_ae_name  = UNKNOWN_AE;

        msg.code        = IRM_MSG_CODE__IRM_FLOW_ALLOC;
        msg.dst_name    = dst_name;
        msg.ae_name     = src_ae_name;
        msg.has_api     = true;

        pthread_rwlock_rdlock(&ai.data_lock);

        msg.api         = ai.api;

        pthread_rwlock_unlock(&ai.data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (!recv_msg->has_api || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_wrlock(&ai.flows_lock);

        fd = bmp_allocate(ai.fds);
        if (!bmp_is_id_valid(ai.fds, fd)) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ai.flows[fd].rb = shm_ap_rbuff_open(recv_msg->api);
        if (ai.flows[fd].rb == NULL) {
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ai.flows[fd].port_id = recv_msg->port_id;
        ai.flows[fd].oflags  = FLOW_O_DEFAULT;
        ai.flows[fd].api     = recv_msg->api;

        ai.ports[recv_msg->port_id].fd    = fd;
        ai.ports[recv_msg->port_id].state = PORT_ID_ASSIGNED;

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        shm_ap_rbuff_open_port(ai.rb, recv_msg->port_id);

        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;
}

int flow_alloc_res(int fd)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int result = 0;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        msg.code         = IRM_MSG_CODE__IRM_FLOW_ALLOC_RES;
        msg.has_port_id  = true;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -ENOTALLOC;
        }

        msg.port_id = ai.flows[fd].port_id;

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        recv_msg = send_recv_irm_msg_b(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        result = recv_msg->result;

        irm_msg__free_unpacked(recv_msg, NULL);

        return result;
}

int flow_dealloc(int fd)
{
        irm_msg_t msg = IRM_MSG__INIT;

        msg.code         = IRM_MSG_CODE__IRM_FLOW_DEALLOC;
        msg.has_port_id  = true;
        msg.has_api      = true;
        msg.api          = getpid();

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_wrlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -ENOTALLOC;
        }

        if (shm_ap_rbuff_close_port(ai.rb, ai.flows[fd].port_id) == -EBUSY) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -EBUSY;
        }

        msg.port_id = ai.flows[fd].port_id;

        port_destroy(&ai.ports[msg.port_id]);

        ai.flows[fd].port_id = -1;
        shm_ap_rbuff_close(ai.flows[fd].rb);
        ai.flows[fd].rb = NULL;
        ai.flows[fd].api = -1;
        if (ai.flows[fd].timeout != NULL) {
                free(ai.flows[fd].timeout);
                ai.flows[fd].timeout = NULL;
        }

        bmp_release(ai.fds, fd);

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        send_irm_msg(&msg);

        return 0;
}

int flow_cntl(int fd, int cmd, int oflags)
{
        int old;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_wrlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -ENOTALLOC;
        }

        old = ai.flows[fd].oflags;

        switch (cmd) {
        case FLOW_F_GETFL: /* GET FLOW FLAGS */
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return old;
        case FLOW_F_SETFL: /* SET FLOW FLAGS */
                ai.flows[fd].oflags = oflags;
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return old;
        default:
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return FLOW_O_INVALID; /* unknown command */
        }
}

ssize_t flow_write(int fd, void * buf, size_t count)
{
        ssize_t idx;
        struct rb_entry e;

        if (buf == NULL)
                return 0;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -ENOTALLOC;
        }

        if (ai.flows[fd].oflags & FLOW_O_NONBLOCK) {
                idx = shm_rdrbuff_write(ai.rdrb,
                                       ai.flows[fd].api,
                                       DU_BUFF_HEADSPACE,
                                       DU_BUFF_TAILSPACE,
                                       buf,
                                       count);
                if (idx < 0) {
                        pthread_rwlock_unlock(&ai.flows_lock);
                        pthread_rwlock_unlock(&ai.data_lock);
                        return -idx;
                }

                e.index   = idx;
                e.port_id = ai.flows[fd].port_id;

                if (shm_ap_rbuff_write(ai.flows[fd].rb, &e) < 0) {
                        shm_rdrbuff_remove(ai.rdrb, idx);
                        pthread_rwlock_unlock(&ai.flows_lock);
                        pthread_rwlock_unlock(&ai.data_lock);
                        return -ENOTALLOC;
                }
        } else { /* blocking */
                struct shm_rdrbuff * rdrb = ai.rdrb;
                pid_t                api = ai.flows[fd].api;
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);

                idx = shm_rdrbuff_write_b(rdrb,
                                          api,
                                          DU_BUFF_HEADSPACE,
                                          DU_BUFF_TAILSPACE,
                                          buf,
                                          count);

                pthread_rwlock_rdlock(&ai.data_lock);
                pthread_rwlock_rdlock(&ai.flows_lock);

                e.index   = idx;
                e.port_id = ai.flows[fd].port_id;

                if (shm_ap_rbuff_write(ai.flows[fd].rb, &e) < 0) {
                        shm_rdrbuff_remove(ai.rdrb, e.index);
                        pthread_rwlock_unlock(&ai.flows_lock);
                        pthread_rwlock_unlock(&ai.data_lock);
                        return -ENOTALLOC;
                }
        }

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        return 0;
}

ssize_t flow_read(int fd, void * buf, size_t count)
{
        int idx = -1;
        int n;
        uint8_t * sdu;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -ENOTALLOC;
        }

        if (ai.flows[fd].oflags & FLOW_O_NONBLOCK) {
                idx = shm_ap_rbuff_read_port(ai.rb, ai.flows[fd].port_id);
                pthread_rwlock_unlock(&ai.flows_lock);
        } else {
                struct shm_ap_rbuff * rb      = ai.rb;
                int                   port_id = ai.flows[fd].port_id;
                struct timespec *     timeout = ai.flows[fd].timeout;
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                idx = shm_ap_rbuff_read_port_b(rb, port_id, timeout);
                pthread_rwlock_rdlock(&ai.data_lock);
        }

        if (idx < 0) {
                pthread_rwlock_unlock(&ai.data_lock);
                return -EAGAIN;
        }

        n = shm_rdrbuff_read(&sdu, ai.rdrb, idx);
        if (n < 0) {
                pthread_rwlock_unlock(&ai.data_lock);
                return -1;
        }

        memcpy(buf, sdu, MIN(n, count));

        shm_rdrbuff_remove(ai.rdrb, idx);

        pthread_rwlock_unlock(&ai.data_lock);

        return n;
}

/* select functions */

struct flow_set * flow_set_create()
{
        struct flow_set * set = malloc(sizeof(*set));
        if (set == NULL)
                return NULL;

        if (pthread_rwlock_init(&set->lock, NULL)) {
                free(set);
                return NULL;
        }

        memset(set->b, 0, IRMD_MAX_FLOWS);
        memset(set->s, 0, IRMD_MAX_FLOWS);

        set->dirty = true;

        return set;
}

void flow_set_zero(struct flow_set * set)
{
        pthread_rwlock_wrlock(&set->lock);
        memset(set->b, 0, IRMD_MAX_FLOWS);
        set->dirty = true;
        pthread_rwlock_unlock(&set->lock);
}

void flow_set_add(struct flow_set * set, int fd)
{
        pthread_rwlock_wrlock(&set->lock);
        set->b[ai.flows[fd].port_id] = true;
        set->dirty = true;
        pthread_rwlock_unlock(&set->lock);
}

void flow_set_del(struct flow_set * set, int fd)
{
        pthread_rwlock_wrlock(&set->lock);
        set->b[ai.flows[fd].port_id] = false;
        set->dirty = true;
        pthread_rwlock_unlock(&set->lock);
}

bool flow_set_has(struct flow_set * set, int fd)
{
        bool ret;
        pthread_rwlock_rdlock(&set->lock);
        ret = set->b[ai.flows[fd].port_id];
        pthread_rwlock_unlock(&set->lock);
        return ret;
}

void flow_set_destroy(struct flow_set * set)
{
        pthread_rwlock_destroy(&set->lock);
        free(set);
}

static void flow_set_cpy(struct flow_set * set)
{
        pthread_rwlock_rdlock(&set->lock);
        if (set->dirty)
                memcpy(set->s, set->b, IRMD_MAX_FLOWS);
        set->dirty = false;
        pthread_rwlock_unlock(&set->lock);
}

int flow_select(struct flow_set * set, const struct timespec * timeout)
{
        int port_id;
        if (set == NULL) {
                port_id = shm_ap_rbuff_peek_b(ai.rb, NULL, timeout);
        } else {
                flow_set_cpy(set);
                port_id = shm_ap_rbuff_peek_b(ai.rb, (bool *) set->s, timeout);
        }
        if (port_id < 0)
                return port_id;
        return ai.ports[port_id].fd;
}

/* ipcp-dev functions */

int np1_flow_alloc(pid_t n_api, int port_id)
{
        int fd;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_wrlock(&ai.flows_lock);

        fd = bmp_allocate(ai.fds);
        if (!bmp_is_id_valid(ai.fds, fd)) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -1;
        }

        ai.flows[fd].rb = shm_ap_rbuff_open(n_api);
        if (ai.flows[fd].rb == NULL) {
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -1;
        }

        ai.flows[fd].port_id = port_id;
        ai.flows[fd].oflags  = FLOW_O_DEFAULT;
        ai.flows[fd].api     = n_api;

        ai.ports[port_id].fd = fd;
        port_set_state(&ai.ports[port_id], PORT_ID_ASSIGNED);

        shm_ap_rbuff_open_port(ai.rb, port_id);

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        return fd;
}

int np1_flow_dealloc(int port_id)
{
        int fd;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_wrlock(&ai.flows_lock);

        fd = ai.ports[port_id].fd;

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        return fd;
}


int np1_flow_resp(pid_t n_api, int port_id)
{
        int fd;
        struct shm_ap_rbuff * rb;

        port_wait_assign(&ai.ports[port_id]);

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_wrlock(&ai.flows_lock);

        fd = ai.ports[port_id].fd;
        if (fd < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return fd;
        }

        rb = shm_ap_rbuff_open(n_api);
        if (rb == NULL) {
                ai.flows[fd].port_id = -1;
                port_destroy(&ai.ports[port_id]);
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -1;
        }

        ai.flows[fd].rb = rb;

        shm_ap_rbuff_open_port(ai.rb, port_id);

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        return fd;
}

int ipcp_create_r(pid_t api)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code         = IRM_MSG_CODE__IPCP_CREATE_R;
        msg.has_api      = true;
        msg.api          = api;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_req_arr(pid_t  api, char * dst_name, char * src_ae_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int port_id = -1;
        int fd = -1;

        if (dst_name == NULL || src_ae_name == NULL)
                return -EINVAL;

        msg.code          = IRM_MSG_CODE__IPCP_FLOW_REQ_ARR;
        msg.has_api       = true;
        msg.api           = api;
        msg.dst_name      = dst_name;
        msg.ae_name       = src_ae_name;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_wrlock(&ai.flows_lock);

        fd = bmp_allocate(ai.fds);
        if (!bmp_is_id_valid(ai.fds, fd)) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -1; /* -ENOMOREFDS */
        }

        ai.flows[fd].rb    = NULL;

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        port_id = recv_msg->port_id;
        irm_msg__free_unpacked(recv_msg, NULL);
        if (port_id < 0)
                return -1;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_wrlock(&ai.flows_lock);

        ai.flows[fd].port_id = port_id;
        ai.flows[fd].rb      = NULL;

        ai.ports[port_id].fd = fd;
        port_set_state(&(ai.ports[port_id]), PORT_ID_ASSIGNED);

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        return fd;
}

int ipcp_flow_alloc_reply(int fd, int response)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code         = IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY;
        msg.has_port_id  = true;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_rdlock(&ai.flows_lock);
        msg.port_id      = ai.flows[fd].port_id;
        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        msg.has_response = true;
        msg.response     = response;

        if (response)
                shm_ap_rbuff_open_port(ai.rb, msg.port_id);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_read(int fd, struct shm_du_buff ** sdb)
{
        int idx = -1;
        int port_id = -1;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_rdlock(&ai.flows_lock);

        if ((port_id = ai.flows[fd].port_id) < 0) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -ENOTALLOC;
        }

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        idx = shm_ap_rbuff_read_port(ai.rb, port_id);
        if (idx < 0) {
                pthread_rwlock_rdlock(&ai.data_lock);
                pthread_rwlock_rdlock(&ai.flows_lock);
                return idx;
        }

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_rdlock(&ai.flows_lock);

        *sdb = shm_rdrbuff_get(ai.rdrb, idx);

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        return 0;
}

int ipcp_flow_write(int fd, struct shm_du_buff * sdb)
{
        struct rb_entry e;

        if (sdb == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].rb == NULL) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -EPERM;
        }

        e.index = shm_du_buff_get_idx(sdb);
        e.port_id = ai.flows[fd].port_id;

        shm_ap_rbuff_write(ai.flows[fd].rb, &e);

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        return 0;
}

struct rb_entry * local_flow_read(int fd)
{
        int port_id;
        struct rb_entry * e = NULL;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_rdlock(&ai.flows_lock);

        port_id = ai.flows[fd].port_id;

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        if (port_id != -1) {
                e = malloc(sizeof(*e));
                if (e == NULL)
                        return NULL;
                e->index = shm_ap_rbuff_read_port(ai.rb, port_id);
        }

        return e;
}

int local_flow_write(int fd, struct rb_entry * e)
{
        if (e == NULL || fd < 0)
                return -EINVAL;

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_rdlock(&ai.flows_lock);

        if (ai.flows[fd].rb == NULL) {
                pthread_rwlock_unlock(&ai.flows_lock);
                pthread_rwlock_unlock(&ai.data_lock);
                return -EPERM;
        }

        e->port_id = ai.flows[fd].port_id;

        shm_ap_rbuff_write(ai.flows[fd].rb, e);

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        return 0;
}

int ipcp_read_shim(struct shm_du_buff ** sdb)
{
        int fd;
        struct rb_entry * e = shm_ap_rbuff_read(ai.rb);

        pthread_rwlock_rdlock(&ai.data_lock);
        pthread_rwlock_rdlock(&ai.flows_lock);

        fd = ai.ports[e->port_id].fd;

        *sdb = shm_rdrbuff_get(ai.rdrb, e->index);

        pthread_rwlock_unlock(&ai.flows_lock);
        pthread_rwlock_unlock(&ai.data_lock);

        return fd;
}

void ipcp_flow_del(struct shm_du_buff * sdb)
{
        shm_rdrbuff_remove(ai.rdrb, shm_du_buff_get_idx(sdb));
}
