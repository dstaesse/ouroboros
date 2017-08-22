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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 200809L

#include "config.h"

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
#include <ouroboros/timerwheel.h>
#include <ouroboros/frct_pci.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define BUF_SIZE 1500

#define TW_ELEMENTS   6000
#define TW_RESOLUTION 1   /* ms */

#define MPL 2000 /* ms */

struct flow_set {
        size_t idx;
        bool   np1_set;
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

struct frcti {
        bool          used;

        struct tw_f * snd_inact;
        bool          snd_drf;
        uint64_t      snd_lwe;
        uint64_t      snd_rwe;

        struct tw_f * rcv_inact;
        bool          rcv_drf;
        uint64_t      rcv_lwe;
        uint64_t      rcv_rwe;

        uint8_t       conf_flags;
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
        pid_t                 api;

        struct shm_rdrbuff *  rdrb;
        struct shm_flow_set * fqset;

        struct timerwheel *   tw;

        struct bmp *          fds;
        struct bmp *          fqueues;
        struct flow *         flows;
        struct port *         ports;
        struct frcti *        frcti;

        pthread_rwlock_t      lock;
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

        pthread_rwlock_rdlock(&ai.lock);

        p = &ai.ports[port_id];

        pthread_rwlock_unlock(&ai.lock);

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

/* Call under flows lock */
static int finalize_write(int    fd,
                          size_t idx)
{
        if (shm_rbuff_write(ai.flows[fd].tx_rb, idx) < 0)
                return -ENOTALLOC;

        shm_flow_set_notify(ai.flows[fd].set, ai.flows[fd].port_id);

        return 0;
}

static int frcti_init(int fd)
{
        struct frcti * frcti;

        frcti = &(ai.frcti[fd]);

        frcti->used = true;

        frcti->snd_drf = true;
        frcti->snd_lwe = 0;
        frcti->snd_rwe = 0;

        frcti->rcv_drf = true;
        frcti->rcv_lwe = 0;
        frcti->rcv_rwe = 0;

        frcti->conf_flags = CONF_ERROR_CHECK;

        return 0;
}

static void frcti_clear(int fd)
{
        struct frcti * frcti;

        frcti = &(ai.frcti[fd]);

        frcti->used = false;
        frcti->snd_inact = NULL;
        frcti->rcv_inact = NULL;
}

static void frcti_fini(int fd)
{
        struct frcti * frcti;

        frcti = &(ai.frcti[fd]);

        /* FIXME: We actually need to wait until these timers become NULL. */
        if (frcti->snd_inact != NULL)
                timerwheel_stop(ai.tw, frcti->snd_inact);

        if (frcti->rcv_inact != NULL)
                timerwheel_stop(ai.tw, frcti->rcv_inact);

        frcti_clear(fd);
}

static int frcti_configure(int         fd,
                           qosspec_t * qos)
{
        /* FIXME: Send configuration message here to other side. */

        (void) fd;
        (void) qos;

        return 0;
}

static void frcti_snd_inactivity(void * arg)
{
        struct frcti *  frcti;

        pthread_rwlock_wrlock(&ai.lock);

        frcti = (struct frcti * ) arg;

        frcti->snd_drf = true;
        frcti->snd_inact = NULL;

        pthread_rwlock_unlock(&ai.lock);
}

/* Called under flows lock */
static int frcti_write(int                  fd,
                       struct shm_du_buff * sdb)
{
        struct frcti *  frcti;
        struct frct_pci pci;

        memset(&pci, 0, sizeof(pci));

        frcti = &(ai.frcti[fd]);

        pthread_rwlock_unlock(&ai.lock);

        timerwheel_move(ai.tw);

        pthread_rwlock_rdlock(&ai.lock);

        /*
         * Set the DRF in the first packet of a new run of SDUs,
         * otherwise simply recharge the timer.
         */
        if (frcti->snd_drf) {
                frcti->snd_inact = timerwheel_start(ai.tw, frcti_snd_inactivity,
                                                    frcti, 2 * MPL);
                if (frcti->snd_inact == NULL)
                        return -1;

                pci.flags |= FLAG_DATA_RUN;
                frcti->snd_drf = false;
        } else {
                if (timerwheel_restart(ai.tw, frcti->snd_inact, 2 * MPL))
                        return -1;
        }

        pci.seqno = frcti->snd_lwe++;
        pci.type |= PDU_TYPE_DATA;

        if (frct_pci_ser(sdb, &pci, frcti->conf_flags & CONF_ERROR_CHECK))
                return -1;

        if (finalize_write(fd, shm_du_buff_get_idx(sdb)))
                return -ENOTALLOC;

        return 0;
}

static void frcti_rcv_inactivity(void * arg)
{
        struct frcti *  frcti;

        pthread_rwlock_wrlock(&ai.lock);

        frcti = (struct frcti * ) arg;

        frcti->rcv_drf = true;
        frcti->rcv_inact = NULL;

        pthread_rwlock_unlock(&ai.lock);
}

static ssize_t frcti_read(int fd)
{
        ssize_t              idx = -1;
        struct timespec      abstime;
        struct frcti *       frcti;
        struct frct_pci      pci;
        struct shm_du_buff * sdb;

        timerwheel_move(ai.tw);

        pthread_rwlock_rdlock(&ai.lock);

        if (ai.flows[fd].oflags & FLOW_O_NONBLOCK) {
                idx = shm_rbuff_read(ai.flows[fd].rx_rb);
                pthread_rwlock_unlock(&ai.lock);
        } else {
                struct shm_rbuff * rb   = ai.flows[fd].rx_rb;
                bool timeo = ai.flows[fd].timesout;
                struct timespec timeout = ai.flows[fd].rcv_timeo;

                pthread_rwlock_unlock(&ai.lock);

                if (timeo) {
                        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                        ts_add(&abstime, &timeout, &abstime);
                        idx = shm_rbuff_read_b(rb, &abstime);
                } else {
                        idx = shm_rbuff_read_b(rb, NULL);
                }
        }

        if (idx < 0)
                return idx;

        pthread_rwlock_rdlock(&ai.lock);

        frcti = &(ai.frcti[fd]);

        sdb = shm_rdrbuff_get(ai.rdrb, idx);

        /* SDU may be corrupted. */
        if (frct_pci_des(sdb, &pci, frcti->conf_flags & CONF_ERROR_CHECK)) {
                pthread_rwlock_unlock(&ai.lock);
                shm_rdrbuff_remove(ai.rdrb, idx);
                return -EAGAIN;
        }

        /* We don't accept packets when there is no inactivity timer. */
        if (frcti->rcv_drf && !(pci.flags & FLAG_DATA_RUN)) {
                pthread_rwlock_unlock(&ai.lock);
                shm_rdrbuff_remove(ai.rdrb, idx);
                return -EAGAIN;
        }

        /*
         * If there is an inactivity timer and the DRF is set,
         * reset the state of the connection.
         */
        if (pci.flags & FLAG_DATA_RUN) {
                frcti->rcv_drf = true;
                if (frcti->rcv_inact != NULL)
                        timerwheel_stop(ai.tw, frcti->rcv_inact);
                frcti->rcv_lwe = pci.seqno;
        }

        /*
         * Start receiver inactivity if this packet has the DRF,
         * otherwise simply restart it.
         */
        if (frcti->rcv_drf) {
                frcti->rcv_inact = timerwheel_start(ai.tw, frcti_rcv_inactivity,
                                                    frcti, 3 * MPL);
                if (frcti->rcv_inact == NULL) {
                        pthread_rwlock_unlock(&ai.lock);
                        shm_rdrbuff_remove(ai.rdrb, idx);
                        return -EAGAIN;
                }

                frcti->rcv_drf = false;
        } else {
                if (timerwheel_restart(ai.tw, frcti->rcv_inact, 3 * MPL)) {
                        pthread_rwlock_unlock(&ai.lock);
                        shm_rdrbuff_remove(ai.rdrb, idx);
                        return -EAGAIN;
                }
        }

        pthread_rwlock_unlock(&ai.lock);

        return idx;
}

static int frcti_event_wait(struct flow_set *       set,
                            struct fqueue *         fq,
                            const struct timespec * timeout)
{
        int ret;

        assert(set);
        assert(fq);
        assert(timeout);

        timerwheel_move(ai.tw);

        /*
         * FIXME: Return the fq only if a data SDU
         * for the application is available.
         */

        ret = shm_flow_set_wait(ai.fqset, set->idx, fq->fqueue, timeout);
        if (ret == -ETIMEDOUT) {
                fq->fqsize = 0;
                return -ETIMEDOUT;
        }

        return ret;
}

static void flow_clear(int fd)
{
        assert(!(fd < 0));

        memset(&ai.flows[fd], 0, sizeof(ai.flows[fd]));

        ai.flows[fd].port_id  = -1;
        ai.flows[fd].api      = -1;
        ai.flows[fd].cube     = QOS_CUBE_BE;
}

static void flow_fini(int fd)
{
        assert(!(fd < 0));

        if (ai.flows[fd].port_id != -1)
                port_destroy(&ai.ports[ai.flows[fd].port_id]);

        if (ai.flows[fd].rx_rb != NULL)
                shm_rbuff_close(ai.flows[fd].rx_rb);

        if (ai.flows[fd].tx_rb != NULL)
                shm_rbuff_close(ai.flows[fd].tx_rb);

        if (ai.flows[fd].set != NULL)
                shm_flow_set_close(ai.flows[fd].set);

        if (ai.frcti[fd].used)
                frcti_clear(fd);

        flow_clear(fd);
}

static int flow_init(int       port_id,
                     pid_t     api,
                     qoscube_t qc)
{
        int fd;

        pthread_rwlock_wrlock(&ai.lock);

        fd = bmp_allocate(ai.fds);
        if (!bmp_is_id_valid(ai.fds, fd)) {
                pthread_rwlock_unlock(&ai.lock);
                return -EBADF;
        }

        ai.flows[fd].rx_rb = shm_rbuff_open(ai.api, port_id);
        if (ai.flows[fd].rx_rb == NULL) {
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.lock);
                return -ENOMEM;
        }

        ai.flows[fd].tx_rb = shm_rbuff_open(api, port_id);
        if (ai.flows[fd].tx_rb == NULL) {
                flow_fini(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.lock);
                return -ENOMEM;
        }

        ai.flows[fd].set = shm_flow_set_open(api);
        if (ai.flows[fd].set == NULL) {
                flow_fini(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.lock);
                return -ENOMEM;
        }

        ai.flows[fd].port_id = port_id;
        ai.flows[fd].oflags  = FLOW_O_DEFAULT;
        ai.flows[fd].api     = api;
        ai.flows[fd].cube    = qc;
        ai.flows[fd].spec    = qos_cube_to_spec(qc);

        ai.ports[port_id].fd = fd;

        port_set_state(&ai.ports[port_id], PORT_ID_ASSIGNED);

        pthread_rwlock_unlock(&ai.lock);

        return fd;
}

int ouroboros_init(const char * ap_name)
{
        int i   = 0;
        int ret = -ENOMEM;

        assert(ai.ap_name == NULL);

        ai.api = getpid();

        ai.fds = bmp_create(AP_MAX_FLOWS - AP_RES_FDS, AP_RES_FDS);
        if (ai.fds == NULL)
                goto fail_fds;

        ai.fqueues = bmp_create(AP_MAX_FQUEUES, 0);
        if (ai.fqueues == NULL)
                goto fail_fqueues;

        ai.fqset = shm_flow_set_create();
        if (ai.fqset == NULL)
                goto fail_fqset;

        ai.rdrb = shm_rdrbuff_open();
        if (ai.rdrb == NULL) {
                ret = -EIRMD;
                goto fail_rdrb;
        }

        ai.flows = malloc(sizeof(*ai.flows) * AP_MAX_FLOWS);
        if (ai.flows == NULL)
                goto fail_flows;

        ai.frcti = malloc(sizeof(*ai.frcti) * AP_MAX_FLOWS);
        if (ai.frcti == NULL)
                goto fail_frcti;

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                flow_clear(i);
                frcti_fini(i);
        }

        ai.ports = malloc(sizeof(*ai.ports) * SYS_MAX_FLOWS);
        if (ai.ports == NULL)
                goto fail_ports;

        if (ap_name != NULL) {
                ai.ap_name = strdup(path_strip((char *) ap_name));
                if (ai.ap_name == NULL)
                        goto fail_ap_name;

                if (api_announce((char *) ai.ap_name)) {
                        ret = -EIRMD;
                        goto fail_announce;
                }
        }

        for (i = 0; i < SYS_MAX_FLOWS; ++i) {
                ai.ports[i].state = PORT_INIT;
                if (pthread_mutex_init(&ai.ports[i].state_lock, NULL)) {
                        int j;
                        for (j = 0; j < i; ++j)
                                pthread_mutex_destroy(&ai.ports[j].state_lock);
                        goto fail_announce;
                }
                if (pthread_cond_init(&ai.ports[i].state_cond, NULL)) {
                        int j;
                        for (j = 0; j < i; ++j)
                                pthread_cond_destroy(&ai.ports[j].state_cond);
                        goto fail_state_cond;
                }
        }

        if (pthread_rwlock_init(&ai.lock, NULL))
                goto fail_lock;

        ai.tw = timerwheel_create(TW_RESOLUTION,
                                  TW_RESOLUTION * TW_ELEMENTS);
        if (ai.tw == NULL)
                goto fail_timerwheel;

        return 0;

 fail_timerwheel:
        pthread_rwlock_destroy(&ai.lock);
 fail_lock:
        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                pthread_cond_destroy(&ai.ports[i].state_cond);
 fail_state_cond:
        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                pthread_mutex_destroy(&ai.ports[i].state_lock);
 fail_announce:
        free(ai.ap_name);
 fail_ap_name:
        free(ai.ports);
 fail_ports:
        free(ai.frcti);
 fail_frcti:
        free(ai.flows);
 fail_flows:
        shm_rdrbuff_close(ai.rdrb);
 fail_rdrb:
        shm_flow_set_destroy(ai.fqset);
 fail_fqset:
        bmp_destroy(ai.fqueues);
 fail_fqueues:
        bmp_destroy(ai.fds);
 fail_fds:
        return ret;
}

void ouroboros_fini()
{
        int i = 0;

        bmp_destroy(ai.fds);
        bmp_destroy(ai.fqueues);

        shm_flow_set_destroy(ai.fqset);

        if (ai.ap_name != NULL)
                free(ai.ap_name);

        pthread_rwlock_rdlock(&ai.lock);

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                if (ai.flows[i].port_id != -1) {
                        ssize_t idx;
                        while ((idx = shm_rbuff_read(ai.flows[i].rx_rb)) >= 0)
                                shm_rdrbuff_remove(ai.rdrb, idx);
                        flow_fini(i);
                }
        }

        for (i = 0; i < SYS_MAX_FLOWS; ++i) {
                pthread_mutex_destroy(&ai.ports[i].state_lock);
                pthread_cond_destroy(&ai.ports[i].state_cond);
        }

        shm_rdrbuff_close(ai.rdrb);

        if (ai.tw != NULL)
                timerwheel_destroy(ai.tw);

        free(ai.flows);
        free(ai.ports);

        pthread_rwlock_unlock(&ai.lock);

        pthread_rwlock_destroy(&ai.lock);
}

int flow_accept(qosspec_t *             qs,
                const struct timespec * timeo)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         fd       = -1;

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

        fd = flow_init(recv_msg->port_id, recv_msg->api, recv_msg->qoscube);

        irm_msg__free_unpacked(recv_msg, NULL);

        if (fd < 0)
                return fd;

        pthread_rwlock_wrlock(&ai.lock);

        frcti_init(fd);

        if (qs != NULL)
                *qs = ai.flows[fd].spec;

        pthread_rwlock_unlock(&ai.lock);

        return fd;
}

int flow_alloc(const char *            dst_name,
               qosspec_t *             qs,
               const struct timespec * timeo)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        qoscube_t   qc       = QOS_CUBE_BE;
        int         fd;

        msg.code        = IRM_MSG_CODE__IRM_FLOW_ALLOC;
        msg.dst_name    = (char *) dst_name;
        msg.has_api     = true;
        msg.has_qoscube = true;
        msg.api         = ai.api;

        if (qs != NULL)
                qc = qos_spec_to_cube(*qs);

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

        if (recv_msg->result != 0) {
                int res =  recv_msg->result;
                irm_msg__free_unpacked(recv_msg, NULL);
                return res;
        }

        if (!recv_msg->has_api || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EIRMD;
        }

        fd = flow_init(recv_msg->port_id, recv_msg->api, qc);

        irm_msg__free_unpacked(recv_msg, NULL);

        if (fd < 0)
                return fd;

        pthread_rwlock_wrlock(&ai.lock);

        frcti_init(fd);

        if (frcti_configure(fd, qs)) {
                flow_fini(fd);
                bmp_release(ai.fds, fd);
                pthread_rwlock_unlock(&ai.lock);
                return -1;
        }

        pthread_rwlock_unlock(&ai.lock);

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

        pthread_rwlock_rdlock(&ai.lock);

        assert(!(ai.flows[fd].port_id < 0));

        msg.port_id = ai.flows[fd].port_id;

        pthread_rwlock_unlock(&ai.lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                assert(false);
                return -1;
        }

        irm_msg__free_unpacked(recv_msg, NULL);

        pthread_rwlock_wrlock(&ai.lock);

        flow_fini(fd);
        bmp_release(ai.fds, fd);

        pthread_rwlock_unlock(&ai.lock);

        return 0;
}

int flow_set_flags(int fd,
                   int flags)
{
        int old;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_wrlock(&ai.lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        old = ai.flows[fd].oflags;

        ai.flows[fd].oflags = flags;
        if (flags & FLOW_O_WRONLY)
                shm_rbuff_block(ai.flows[fd].rx_rb);
        if (flags & FLOW_O_RDWR)
                shm_rbuff_unblock(ai.flows[fd].rx_rb);

        pthread_rwlock_unlock(&ai.lock);

        return old;
}

int flow_get_flags(int fd)
{
        int old;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_wrlock(&ai.lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        old = ai.flows[fd].oflags;

        pthread_rwlock_unlock(&ai.lock);

        return old;
}

int flow_get_timeout(int               fd,
                     struct timespec * timeo)
{
        int ret = 0;

        if (fd < 0 || fd >= AP_MAX_FLOWS || timeo == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&ai.lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        if (ai.flows[fd].timesout)
                *timeo = ai.flows[fd].rcv_timeo;
        else
                ret = -EPERM;

        pthread_rwlock_unlock(&ai.lock);

        return ret;
}

int flow_set_timeout(int                     fd,
                     const struct timespec * timeo)
{
        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EINVAL;

        pthread_rwlock_wrlock(&ai.lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        if (timeo == NULL) {
                ai.flows[fd].timesout = false;
        } else {
                ai.flows[fd].timesout = true;
                ai.flows[fd].rcv_timeo = *timeo;
        }

        pthread_rwlock_unlock(&ai.lock);

        return 0;
}

int flow_get_qosspec(int         fd,
                     qosspec_t * qs)
{
        if (fd < 0 || fd >= AP_MAX_FLOWS || qs == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&ai.lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        *qs = ai.flows[fd].spec;

        pthread_rwlock_unlock(&ai.lock);

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

        pthread_rwlock_rdlock(&ai.lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        if ((ai.flows[fd].oflags & FLOW_O_ACCMODE) == FLOW_O_RDONLY) {
                pthread_rwlock_unlock(&ai.lock);
                return -EPERM;
        }

        if (ai.flows[fd].oflags & FLOW_O_NONBLOCK) {
                idx = shm_rdrbuff_write(ai.rdrb,
                                       DU_BUFF_HEADSPACE,
                                       DU_BUFF_TAILSPACE,
                                       buf,
                                       count);
                if (idx < 0) {
                        pthread_rwlock_unlock(&ai.lock);
                        return idx;
                }

        } else { /* blocking */
                pthread_rwlock_unlock(&ai.lock);

                idx = shm_rdrbuff_write_b(ai.rdrb,
                                          DU_BUFF_HEADSPACE,
                                          DU_BUFF_TAILSPACE,
                                          buf,
                                          count);

                pthread_rwlock_rdlock(&ai.lock);
        }

        if (!ai.frcti[fd].used) {
                if (finalize_write(fd, idx)) {
                        pthread_rwlock_unlock(&ai.lock);
                        shm_rdrbuff_remove(ai.rdrb, idx);
                        return -ENOTALLOC;
                }
        } else {
                if (frcti_write(fd, shm_rdrbuff_get(ai.rdrb, idx))) {
                        pthread_rwlock_unlock(&ai.lock);
                        shm_rdrbuff_remove(ai.rdrb, idx);
                        return -1;
                }
        }

        pthread_rwlock_unlock(&ai.lock);

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

        pthread_rwlock_rdlock(&ai.lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        pthread_rwlock_unlock(&ai.lock);

        if (!ai.frcti[fd].used)
                idx = shm_rbuff_read(ai.flows[fd].rx_rb);
        else
                idx = frcti_read(fd);

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

        pthread_rwlock_wrlock(&ai.lock);

        set->idx = bmp_allocate(ai.fqueues);
        if (!bmp_is_id_valid(ai.fqueues, set->idx)) {
                pthread_rwlock_unlock(&ai.lock);
                free(set);
                return NULL;
        }

        set->np1_set = false;

        pthread_rwlock_unlock(&ai.lock);

        return set;
}

void flow_set_destroy(struct flow_set * set)
{
        if (set == NULL)
                return;

        flow_set_zero(set);

        pthread_rwlock_wrlock(&ai.lock);

        bmp_release(ai.fqueues, set->idx);

        pthread_rwlock_unlock(&ai.lock);

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

        pthread_rwlock_rdlock(&ai.lock);

        ret = shm_flow_set_add(ai.fqset, set->idx, ai.flows[fd].port_id);

        sdus = shm_rbuff_queued(ai.flows[fd].rx_rb);
        for (i = 0; i < sdus; i++)
                shm_flow_set_notify(ai.fqset, ai.flows[fd].port_id);

        if (ai.frcti[fd].used)
                set->np1_set = true;

        pthread_rwlock_unlock(&ai.lock);

        return ret;
}

void flow_set_del(struct flow_set * set,
                  int               fd)
{
        if (set == NULL)
                return;

        pthread_rwlock_rdlock(&ai.lock);

        if (ai.flows[fd].port_id >= 0)
                shm_flow_set_del(ai.fqset, set->idx, ai.flows[fd].port_id);

        pthread_rwlock_unlock(&ai.lock);
}

bool flow_set_has(const struct flow_set * set,
                  int                     fd)
{
        bool ret = false;

        if (set == NULL || fd < 0)
                return false;

        pthread_rwlock_rdlock(&ai.lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return false;
        }

        ret = (shm_flow_set_has(ai.fqset, set->idx, ai.flows[fd].port_id) == 1);

        pthread_rwlock_unlock(&ai.lock);

        return ret;
}

int fqueue_next(struct fqueue * fq)
{
        int fd;

        if (fq == NULL)
                return -EINVAL;

        if (fq->fqsize == 0)
                return -EPERM;

        pthread_rwlock_rdlock(&ai.lock);

        fd = ai.ports[fq->fqueue[fq->next++]].fd;

        pthread_rwlock_unlock(&ai.lock);

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
        ssize_t         ret;
        struct timespec abstime;

        if (set == NULL || fq == NULL)
                return -EINVAL;

        if (fq->fqsize > 0)
                return fq->fqsize;

        assert(!fq->next);

        if (timeout != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

        if (set->np1_set)
                ret = frcti_event_wait(set, fq, &abstime);
        else
                ret = shm_flow_set_wait(ai.fqset, set->idx,
                                        fq->fqueue, &abstime);

        if (ret == -ETIMEDOUT) {
                fq->fqsize = 0;
                return -ETIMEDOUT;
        }

        fq->fqsize = ret;

        assert(ret);

        return ret;
}

/* ipcp-dev functions */

int np1_flow_alloc(pid_t     n_api,
                   int       port_id,
                   qoscube_t qc)
{
        return flow_init(port_id, n_api, qc);
}

int np1_flow_dealloc(int port_id)
{
        int fd;

        pthread_rwlock_rdlock(&ai.lock);

        fd = ai.ports[port_id].fd;

        pthread_rwlock_unlock(&ai.lock);

        return fd;
}

int np1_flow_resp(int port_id)
{
        int fd;

        if (port_wait_assign(port_id) != PORT_ID_ASSIGNED)
                return -1;

        pthread_rwlock_rdlock(&ai.lock);

        fd = ai.ports[port_id].fd;

        pthread_rwlock_unlock(&ai.lock);

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
                      qoscube_t       qc)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
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
        msg.qoscube     = qc;

        recv_msg = send_recv_irm_msg(&msg);

        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_port_id || !recv_msg->has_api) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        if (recv_msg->has_result && recv_msg->result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        fd = flow_init(recv_msg->port_id, recv_msg->api, qc);

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

        pthread_rwlock_rdlock(&ai.lock);

        msg.port_id = ai.flows[fd].port_id;

        pthread_rwlock_unlock(&ai.lock);

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

        assert(fd >= 0);
        assert(sdb);

        pthread_rwlock_rdlock(&ai.lock);

        if ((port_id = ai.flows[fd].port_id) < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        pthread_rwlock_unlock(&ai.lock);

        if (!ai.frcti[fd].used)
                idx = shm_rbuff_read(ai.flows[fd].rx_rb);
        else
                idx = frcti_read(fd);

        if (idx < 0)
                return idx;

        *sdb = shm_rdrbuff_get(ai.rdrb, idx);

        return 0;
}

int ipcp_flow_write(int                  fd,
                    struct shm_du_buff * sdb)
{
        if (sdb == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&ai.lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        if ((ai.flows[fd].oflags & FLOW_O_ACCMODE) == FLOW_O_RDONLY) {
                pthread_rwlock_unlock(&ai.lock);
                return -EPERM;
        }

        assert(ai.flows[fd].tx_rb);

        if (!ai.frcti[fd].used) {
                if (finalize_write(fd, shm_du_buff_get_idx(sdb))) {
                        pthread_rwlock_unlock(&ai.lock);
                        return -ENOTALLOC;
                }
        } else {
                if (frcti_write(fd, sdb)) {
                        pthread_rwlock_unlock(&ai.lock);
                        return -1;
                }
        }

        pthread_rwlock_unlock(&ai.lock);

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

        pthread_rwlock_rdlock(&ai.lock);

        rx_rb = ai.flows[fd].rx_rb;

        pthread_rwlock_unlock(&ai.lock);

        shm_rbuff_fini(rx_rb);
}

int ipcp_flow_get_qoscube(int         fd,
                          qoscube_t * cube)
{
        if (fd < 0 || fd >= AP_MAX_FLOWS || cube == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&ai.lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        *cube = ai.flows[fd].cube;

        pthread_rwlock_unlock(&ai.lock);

        return 0;
}

ssize_t local_flow_read(int fd)
{
        ssize_t ret;

        assert(fd >= 0);

        pthread_rwlock_rdlock(&ai.lock);

        ret = shm_rbuff_read(ai.flows[fd].rx_rb);

        pthread_rwlock_unlock(&ai.lock);

        return ret;
}

int local_flow_write(int    fd,
                     size_t idx)
{
        if (fd < 0)
                return -EINVAL;

        pthread_rwlock_rdlock(&ai.lock);

        if (ai.flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        if (finalize_write(fd, idx)) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        pthread_rwlock_unlock(&ai.lock);

        return 0;
}

void ipcp_sdb_release(struct shm_du_buff * sdb)
{
        shm_rdrbuff_remove(ai.rdrb, shm_du_buff_get_idx(sdb));
}
