/*
 * Ouroboros - Copyright (C) 2016 - 2020
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#include <ouroboros/hash.h>
#include <ouroboros/cacep.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/local-dev.h>
#include <ouroboros/sockets.h>
#include <ouroboros/fccntl.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/random.h>
#include <ouroboros/shm_flow_set.h>
#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/shm_rbuff.h>
#include <ouroboros/utils.h>
#include <ouroboros/fqueue.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/types.h>

#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#endif

/* Partial read information. */
#define NO_PART   -1
#define DONE_PART -2

#define CRCLEN    (sizeof(uint32_t))
#define SECMEMSZ  16384
#define SYMMKEYSZ 32
#define MSGBUFSZ  2048

struct flow_set {
        size_t idx;
};

struct fqueue {
        int    fqueue[2 * SHM_BUFFER_SIZE]; /* Safe copy from shm. */
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

#define frcti_to_flow(frcti) \
        ((struct flow *)((uint8_t *) frcti - offsetof(struct flow, frcti)))

struct flow {
        struct shm_rbuff *    rx_rb;
        struct shm_rbuff *    tx_rb;
        struct shm_flow_set * set;
        int                   flow_id;
        int                   oflags;
        qosspec_t             qs;
        ssize_t               part_idx;

        void *                ctx;
        uint8_t               key[SYMMKEYSZ];

        pid_t                 pid;

        bool                  snd_timesout;
        bool                  rcv_timesout;
        struct timespec       snd_timeo;
        struct timespec       rcv_timeo;

        struct frcti *        frcti;
};

struct {
        char *                prog;
        pid_t                 pid;

        struct shm_rdrbuff *  rdrb;
        struct shm_flow_set * fqset;

        struct timerwheel *   tw;

        struct bmp *          fds;
        struct bmp *          fqueues;

        struct flow *         flows;
        struct port *         ports;

        pthread_rwlock_t      lock;
} ai;

#include "frct.c"

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

static enum port_state port_wait_assign(int flow_id)
{
        enum port_state state;
        struct port *   p;

        p = &ai.ports[flow_id];

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

static int proc_announce(char * prog)
{
        irm_msg_t   msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg;
        int         ret = -1;

        msg.code    = IRM_MSG_CODE__IRM_PROC_ANNOUNCE;
        msg.has_pid = true;
        msg.pid     = ai.pid;
        msg.prog    = prog;

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

static void flow_clear(int fd)
{
        memset(&ai.flows[fd], 0, sizeof(ai.flows[fd]));

        ai.flows[fd].flow_id  = -1;
        ai.flows[fd].pid      = -1;
}

#include "crypt.c"

static void flow_fini(int fd)
{
        assert(fd >= 0 && fd < SYS_MAX_FLOWS);

        if (ai.flows[fd].flow_id != -1) {
                port_destroy(&ai.ports[ai.flows[fd].flow_id]);
                bmp_release(ai.fds, fd);
        }

        if (ai.flows[fd].rx_rb != NULL) {
                shm_rbuff_set_acl(ai.flows[fd].rx_rb, ACL_FLOWDOWN);
                shm_rbuff_close(ai.flows[fd].rx_rb);
        }

        if (ai.flows[fd].tx_rb != NULL) {
                shm_rbuff_set_acl(ai.flows[fd].tx_rb, ACL_FLOWDOWN);
                shm_rbuff_close(ai.flows[fd].tx_rb);
        }

        if (ai.flows[fd].set != NULL) {
                shm_flow_set_notify(ai.flows[fd].set,
                                    ai.flows[fd].flow_id,
                                    FLOW_DEALLOC);
                shm_flow_set_close(ai.flows[fd].set);
        }

        if (ai.flows[fd].frcti != NULL)
                frcti_destroy(ai.flows[fd].frcti);

        if (ai.flows[fd].ctx != NULL)
                crypt_fini(ai.flows[fd].ctx);

        flow_clear(fd);
}

static int flow_init(int       flow_id,
                     pid_t     pid,
                     qosspec_t qs,
                     uint8_t * s)
{
        int fd;
        int err = -ENOMEM;

        pthread_rwlock_wrlock(&ai.lock);

        fd = bmp_allocate(ai.fds);
        if (!bmp_is_id_valid(ai.fds, fd)) {
                err = -EBADF;
                goto fail_fds;
        }

        ai.flows[fd].rx_rb = shm_rbuff_open(ai.pid, flow_id);
        if (ai.flows[fd].rx_rb == NULL)
                goto fail_rx_rb;

        ai.flows[fd].tx_rb = shm_rbuff_open(pid, flow_id);
        if (ai.flows[fd].tx_rb == NULL)
                goto fail_tx_rb;

        ai.flows[fd].set = shm_flow_set_open(pid);
        if (ai.flows[fd].set == NULL)
                goto fail_set;

        ai.flows[fd].flow_id  = flow_id;
        ai.flows[fd].oflags   = FLOWFDEFAULT;
        ai.flows[fd].pid      = pid;
        ai.flows[fd].part_idx = NO_PART;
        ai.flows[fd].qs       = qs;

        if (qs.cypher_s > 0) {
                assert(s != NULL);
                if (crypt_init(&ai.flows[fd].ctx) < 0)
                        goto fail_ctx;

                memcpy(ai.flows[fd].key, s, SYMMKEYSZ);
        }

        ai.ports[flow_id].fd = fd;

        port_set_state(&ai.ports[flow_id], PORT_ID_ASSIGNED);

        pthread_rwlock_unlock(&ai.lock);

        return fd;

 fail_ctx:
        shm_flow_set_close(ai.flows[fd].set);
 fail_set:
        shm_rbuff_close(ai.flows[fd].tx_rb);
 fail_tx_rb:
        shm_rbuff_close(ai.flows[fd].rx_rb);
 fail_rx_rb:
        bmp_release(ai.fds, fd);
 fail_fds:
        pthread_rwlock_unlock(&ai.lock);
        return err;
}

static bool check_python(char * str)
{
        if (!strcmp(path_strip(str), "python") ||
            !strcmp(path_strip(str), "python2") ||
            !strcmp(path_strip(str), "python3"))
                return true;

        return false;
}

static void init(int     argc,
                 char ** argv,
                 char ** envp)
{
        const char * prog = argv[0];
        int          i;

        (void) argc;
        (void) envp;

        assert(ai.prog == NULL);

        if (check_python(argv[0]))
                prog = argv[1];

        ai.pid = getpid();
#ifdef HAVE_LIBGCRYPT
        if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
                if (!gcry_check_version(GCRYPT_VERSION))
                        goto fail_fds;
                gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
                gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
        }
#endif
        ai.fds = bmp_create(PROG_MAX_FLOWS - PROG_RES_FDS, PROG_RES_FDS);
        if (ai.fds == NULL)
                goto fail_fds;

        ai.fqueues = bmp_create(PROG_MAX_FQUEUES, 0);
        if (ai.fqueues == NULL)
                goto fail_fqueues;

        ai.rdrb = shm_rdrbuff_open();
        if (ai.rdrb == NULL)
                goto fail_rdrb;

        ai.flows = malloc(sizeof(*ai.flows) * PROG_MAX_FLOWS);
        if (ai.flows == NULL)
                goto fail_flows;

        for (i = 0; i < PROG_MAX_FLOWS; ++i)
                flow_clear(i);

        ai.ports = malloc(sizeof(*ai.ports) * SYS_MAX_FLOWS);
        if (ai.ports == NULL)
                goto fail_ports;

        if (prog != NULL) {
                ai.prog = strdup(path_strip((char *) prog));
                if (ai.prog == NULL)
                        goto fail_prog;

                if (proc_announce((char *) ai.prog))
                        goto fail_announce;
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

        if (rxmwheel_init())
                goto fail_rxmwheel;

        ai.fqset = shm_flow_set_open(getpid());
        if (ai.fqset == NULL)
                goto fail_fqset;

        return;

 fail_fqset:
        rxmwheel_fini();
 fail_rxmwheel:
        pthread_rwlock_destroy(&ai.lock);
 fail_lock:
        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                pthread_cond_destroy(&ai.ports[i].state_cond);
 fail_state_cond:
        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                pthread_mutex_destroy(&ai.ports[i].state_lock);
 fail_announce:
        free(ai.prog);
 fail_prog:
        free(ai.ports);
 fail_ports:
        free(ai.flows);
 fail_flows:
        shm_rdrbuff_close(ai.rdrb);
 fail_rdrb:
        bmp_destroy(ai.fqueues);
 fail_fqueues:
        bmp_destroy(ai.fds);
 fail_fds:
        fprintf(stderr, "FATAL: ouroboros-dev init failed. "
                        "Make sure an IRMd is running.\n\n");
        memset(&ai, 0, sizeof(ai));
        exit(EXIT_FAILURE);
}

static void fini(void)
{
        int i = 0;

        if (ai.fds == NULL)
                return;

        rxmwheel_fini();

        if (ai.prog != NULL)
                free(ai.prog);

        pthread_rwlock_wrlock(&ai.lock);

        for (i = 0; i < PROG_MAX_FLOWS; ++i) {
                if (ai.flows[i].flow_id != -1) {
                        ssize_t idx;
                        shm_rbuff_set_acl(ai.flows[i].rx_rb, ACL_FLOWDOWN);
                        while ((idx = shm_rbuff_read(ai.flows[i].rx_rb)) >= 0)
                                shm_rdrbuff_remove(ai.rdrb, idx);
                        flow_fini(i);
                }
        }

        shm_flow_set_close(ai.fqset);

        for (i = 0; i < SYS_MAX_FLOWS; ++i) {
                pthread_mutex_destroy(&ai.ports[i].state_lock);
                pthread_cond_destroy(&ai.ports[i].state_cond);
        }

        shm_rdrbuff_close(ai.rdrb);

        free(ai.flows);
        free(ai.ports);

        bmp_destroy(ai.fds);
        bmp_destroy(ai.fqueues);

        pthread_rwlock_unlock(&ai.lock);

        pthread_rwlock_destroy(&ai.lock);
}

#if defined(__MACH__) && defined(__APPLE__)
#define INIT_SECTION "__DATA, __mod_init_func"
#define FINI_SECTION "__DATA, __mod_term_func"
#else
#define INIT_SECTION ".init_array"
#define FINI_SECTION ".fini_array"
#endif

__attribute__((section(INIT_SECTION))) __typeof__(init) * __init = init;
__attribute__((section(FINI_SECTION))) __typeof__(fini) * __fini = fini;

int flow_accept(qosspec_t *             qs,
                const struct timespec * timeo)
{
        irm_msg_t   msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg;
        int         fd;
        void *      pkp;          /* public key pair     */
        uint8_t     s[SYMMKEYSZ]; /* secret key for flow */
        uint8_t     buf[MSGBUFSZ];
        int         err = -EIRMD;
        ssize_t     key_len;

        memset(s, 0, SYMMKEYSZ);

        msg.code    = IRM_MSG_CODE__IRM_FLOW_ACCEPT;
        msg.has_pid = true;
        msg.pid     = ai.pid;

        if (timeo != NULL) {
                msg.has_timeo_sec = true;
                msg.has_timeo_nsec = true;
                msg.timeo_sec  = timeo->tv_sec;
                msg.timeo_nsec = timeo->tv_nsec;
        }

        key_len = crypt_dh_pkp_create(&pkp, buf);
        if (key_len < 0) {
                err = -ECRYPT;
                goto fail_crypt_pkp;
        }

        msg.has_pk  = true;
        msg.pk.data = buf;
        msg.pk.len  = (uint32_t) key_len;

        pthread_cleanup_push(crypt_dh_pkp_destroy, pkp);

        recv_msg = send_recv_irm_msg(&msg);

        pthread_cleanup_pop(false);

        if (recv_msg == NULL)
                goto fail_recv;

        if (!recv_msg->has_result)
                goto fail_result;

        if (recv_msg->result !=  0) {
                err = recv_msg->result;
                goto fail_result;
        }

        if (!recv_msg->has_pid || !recv_msg->has_flow_id ||
            recv_msg->qosspec == NULL)
                goto fail_result;

        if (recv_msg->pk.len != 0 &&
            crypt_dh_derive(pkp, recv_msg->pk.data,
                            recv_msg->pk.len, s) < 0) {
                err = -ECRYPT;
                goto fail_result;
        }

        crypt_dh_pkp_destroy(pkp);

        fd = flow_init(recv_msg->flow_id, recv_msg->pid,
                       msg_to_spec(recv_msg->qosspec), s);

        irm_msg__free_unpacked(recv_msg, NULL);

        if (fd < 0)
                return fd;

        pthread_rwlock_wrlock(&ai.lock);

        assert(ai.flows[fd].frcti == NULL);

        if (ai.flows[fd].qs.in_order != 0) {
                ai.flows[fd].frcti = frcti_create(fd);
                if (ai.flows[fd].frcti == NULL) {
                        pthread_rwlock_unlock(&ai.lock);
                        flow_dealloc(fd);
                        return -ENOMEM;
                }
        }

        if (qs != NULL)
                *qs = ai.flows[fd].qs;

        pthread_rwlock_unlock(&ai.lock);

        return fd;

 fail_result:
        irm_msg__free_unpacked(recv_msg, NULL);
 fail_recv:
        crypt_dh_pkp_destroy(pkp);
 fail_crypt_pkp:
        return err;
}

static int __flow_alloc(const char *            dst,
                        qosspec_t *             qs,
                        const struct timespec * timeo,
                        bool join)
{
        irm_msg_t     msg    = IRM_MSG__INIT;
        qosspec_msg_t qs_msg = QOSSPEC_MSG__INIT;
        irm_msg_t *   recv_msg;
        int           fd;
        void *        pkp = NULL;     /* public key pair     */
        uint8_t       s[SYMMKEYSZ];   /* secret key for flow */
        uint8_t       buf[MSGBUFSZ];
        int           err = -EIRMD;

        memset(s, 0, SYMMKEYSZ);

#ifdef QOS_DISABLE_CRC
        if (qs != NULL)
                qs->ber = 1;
#endif
        msg.code    = join ? IRM_MSG_CODE__IRM_FLOW_JOIN
                           : IRM_MSG_CODE__IRM_FLOW_ALLOC;
        msg.dst     = (char *) dst;
        msg.has_pid = true;
        msg.pid     = ai.pid;
        qs_msg      = spec_to_msg(qs);
        msg.qosspec = &qs_msg;

        if (timeo != NULL) {
                msg.has_timeo_sec = true;
                msg.has_timeo_nsec = true;
                msg.timeo_sec  = timeo->tv_sec;
                msg.timeo_nsec = timeo->tv_nsec;
        }

        if (!join && qs != NULL && qs->cypher_s != 0) {
                ssize_t key_len;

                key_len = crypt_dh_pkp_create(&pkp, buf);
                if (key_len < 0) {
                        err = -ECRYPT;
                        goto fail_crypt_pkp;
                }

                msg.has_pk  = true;
                msg.pk.data = buf;
                msg.pk.len  = (uint32_t) key_len;
        }

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                goto fail_send;

        if (!recv_msg->has_result)
                goto fail_result;

        if (recv_msg->result != 0) {
                err = recv_msg->result;
                goto fail_result;
        }

        if (!recv_msg->has_pid || !recv_msg->has_flow_id)
                goto fail_result;

        if (!join && qs != NULL && qs->cypher_s != 0) {
                if (!recv_msg->has_pk || recv_msg->pk.len == 0) {
                        err = -ECRYPT;
                        goto fail_result;
                }

                if (crypt_dh_derive(pkp, recv_msg->pk.data,
                                    recv_msg->pk.len, s) < 0) {
                        err = -ECRYPT;
                        goto fail_result;
                }

                crypt_dh_pkp_destroy(pkp);
        }

        fd = flow_init(recv_msg->flow_id, recv_msg->pid,
                       qs == NULL ? qos_raw : *qs, s);

        irm_msg__free_unpacked(recv_msg, NULL);

        if (fd < 0)
                return fd;

        pthread_rwlock_wrlock(&ai.lock);

        assert(ai.flows[fd].frcti == NULL);

        if (ai.flows[fd].qs.in_order != 0) {
                ai.flows[fd].frcti = frcti_create(fd);
                if (ai.flows[fd].frcti == NULL) {
                        pthread_rwlock_unlock(&ai.lock);
                        flow_dealloc(fd);
                        return -ENOMEM;
                }
        }

        pthread_rwlock_unlock(&ai.lock);

        return fd;

 fail_result:
        irm_msg__free_unpacked(recv_msg, NULL);
 fail_send:
        crypt_dh_pkp_destroy(pkp);
 fail_crypt_pkp:
        return err;
}

int flow_alloc(const char *            dst,
               qosspec_t *             qs,
               const struct timespec * timeo)
{
        return __flow_alloc(dst, qs, timeo, false);
}

int flow_join(const char *            dst,
              qosspec_t *             qs,
              const struct timespec * timeo)
{
        if (qs != NULL && qs->cypher_s != 0)
                return -ECRYPT;

        return __flow_alloc(dst, qs, timeo, true);
}

int flow_dealloc(int fd)
{
        irm_msg_t   msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg;

        if (fd < 0 || fd >= SYS_MAX_FLOWS )
                return -EINVAL;

        msg.code         = IRM_MSG_CODE__IRM_FLOW_DEALLOC;
        msg.has_flow_id  = true;
        msg.has_pid      = true;
        msg.pid          = ai.pid;

        pthread_rwlock_rdlock(&ai.lock);

        if (ai.flows[fd].flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        msg.flow_id = ai.flows[fd].flow_id;

        pthread_rwlock_unlock(&ai.lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EIRMD;
        }

        irm_msg__free_unpacked(recv_msg, NULL);

        pthread_rwlock_wrlock(&ai.lock);

        flow_fini(fd);

        pthread_rwlock_unlock(&ai.lock);

        return 0;
}

int fccntl(int fd,
           int cmd,
           ...)
{
        uint32_t *        fflags;
        uint16_t *        cflags;
        va_list           l;
        struct timespec * timeo;
        qosspec_t *       qs;
        uint32_t          rx_acl;
        uint32_t          tx_acl;
        size_t *          qlen;
        struct flow *     flow;

        if (fd < 0 || fd >= SYS_MAX_FLOWS)
                return -EBADF;

        flow = &ai.flows[fd];

        va_start(l, cmd);

        pthread_rwlock_wrlock(&ai.lock);

        if (flow->flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                va_end(l);
                return -ENOTALLOC;
        }

        switch(cmd) {
        case FLOWSSNDTIMEO:
                timeo = va_arg(l, struct timespec *);
                if (timeo == NULL) {
                        flow->snd_timesout = false;
                } else {
                        flow->snd_timesout = true;
                        flow->snd_timeo    = *timeo;
                }
                break;
        case FLOWGSNDTIMEO:
                timeo = va_arg(l, struct timespec *);
                if (timeo == NULL)
                        goto einval;
                if (!flow->snd_timesout)
                        goto eperm;
                *timeo = flow->snd_timeo;
                break;
        case FLOWSRCVTIMEO:
                timeo = va_arg(l, struct timespec *);
                if (timeo == NULL) {
                        flow->rcv_timesout = false;
                } else {
                        flow->rcv_timesout = true;
                        flow->rcv_timeo    = *timeo;
                }
                break;
        case FLOWGRCVTIMEO:
                timeo = va_arg(l, struct timespec *);
                if (timeo == NULL)
                        goto einval;
                if (!flow->rcv_timesout)
                        goto eperm;
                *timeo = flow->snd_timeo;
                break;
        case FLOWGQOSSPEC:
                qs = va_arg(l, qosspec_t *);
                if (qs == NULL)
                        goto einval;
                *qs = flow->qs;
                break;
        case FLOWGRXQLEN:
                qlen  = va_arg(l, size_t *);
                *qlen = shm_rbuff_queued(flow->rx_rb);
                break;
        case FLOWGTXQLEN:
                qlen  = va_arg(l, size_t *);
                *qlen = shm_rbuff_queued(flow->tx_rb);
                break;
        case FLOWSFLAGS:
                flow->oflags = va_arg(l, uint32_t);
                rx_acl = shm_rbuff_get_acl(flow->rx_rb);
                tx_acl = shm_rbuff_get_acl(flow->rx_rb);
                /*
                 * Making our own flow write only means making the
                 * the other side of the flow read only.
                 */
                if (flow->oflags & FLOWFWRONLY)
                        rx_acl |= ACL_RDONLY;
                if (flow->oflags & FLOWFRDWR)
                        rx_acl |= ACL_RDWR;

                if (flow->oflags & FLOWFDOWN) {
                        rx_acl |= ACL_FLOWDOWN;
                        tx_acl |= ACL_FLOWDOWN;
                        shm_flow_set_notify(flow->set,
                                            flow->flow_id,
                                            FLOW_DOWN);
                } else {
                        rx_acl &= ~ACL_FLOWDOWN;
                        tx_acl &= ~ACL_FLOWDOWN;
                        shm_flow_set_notify(flow->set,
                                            flow->flow_id,
                                            FLOW_UP);
                }

                shm_rbuff_set_acl(flow->rx_rb, rx_acl);
                shm_rbuff_set_acl(flow->tx_rb, tx_acl);

                break;
        case FLOWGFLAGS:
                fflags = va_arg(l, uint32_t *);
                if (fflags == NULL)
                        goto einval;
                *fflags = flow->oflags;
                break;
        case FRCTGFLAGS:
                cflags = (uint16_t *) va_arg(l, int *);
                if (cflags == NULL)
                        goto einval;
                if (flow->frcti == NULL)
                        goto eperm;
                *cflags = frcti_getconf(flow->frcti);
                break;
        default:
                pthread_rwlock_unlock(&ai.lock);
                va_end(l);
                return -ENOTSUP;

        };

        pthread_rwlock_unlock(&ai.lock);

        va_end(l);

        return 0;

 einval:
        pthread_rwlock_unlock(&ai.lock);
        va_end(l);
        return -EINVAL;
 eperm:
        pthread_rwlock_unlock(&ai.lock);
        va_end(l);
        return -EPERM;
}

static int chk_crc(struct shm_du_buff * sdb)
{
        uint32_t crc;
        uint8_t * head = shm_du_buff_head(sdb);
        uint8_t * tail = shm_du_buff_tail_release(sdb, CRCLEN);

        mem_hash(HASH_CRC32, &crc, head, tail - head);

        return !(crc == *((uint32_t *) tail));
}

static int add_crc(struct shm_du_buff * sdb)
{
        uint8_t * head = shm_du_buff_head(sdb);
        uint8_t * tail = shm_du_buff_tail_alloc(sdb, CRCLEN);
        if (tail == NULL)
                return -1;

        mem_hash(HASH_CRC32, tail, head, tail - head);

        return 0;
}

ssize_t flow_write(int          fd,
                   const void * buf,
                   size_t       count)
{
        struct flow *        flow;
        ssize_t              idx;
        int                  ret;
        int                  flags;
        struct timespec      abs;
        struct timespec *    abstime = NULL;
        struct shm_du_buff * sdb;
        uint8_t *            ptr;

        if (buf == NULL)
                return 0;

        if (fd < 0 || fd > PROG_MAX_FLOWS)
                return -EBADF;

        flow = &ai.flows[fd];

        clock_gettime(PTHREAD_COND_CLOCK, &abs);

        pthread_rwlock_rdlock(&ai.lock);

        if (flow->flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        if (ai.flows[fd].snd_timesout) {
                ts_add(&abs, &flow->snd_timeo, &abs);
                abstime = &abs;
        }

        flags = flow->oflags;

        pthread_rwlock_unlock(&ai.lock);

        if ((flags & FLOWFACCMODE) == FLOWFRDONLY)
                return -EPERM;

        if (flags & FLOWFWNOBLOCK)
                idx = shm_rdrbuff_alloc(ai.rdrb,
                                        count,
                                        &ptr,
                                        &sdb);
        else  /* Blocking. */
                idx = shm_rdrbuff_alloc_b(ai.rdrb,
                                          count,
                                          &ptr,
                                          &sdb,
                                          abstime);
        if (idx < 0)
                return idx;

        memcpy(ptr, buf, count);

        if (frcti_snd(flow->frcti, sdb) < 0) {
                shm_rdrbuff_remove(ai.rdrb, idx);
                return -ENOMEM;
        }

        pthread_rwlock_wrlock(&ai.lock);
        if (flow->qs.cypher_s > 0)
                if (crypt_encrypt(flow, sdb) < 0) {
                        pthread_rwlock_unlock(&ai.lock);
                        shm_rdrbuff_remove(ai.rdrb, idx);
                        return -ENOMEM;
                }
        pthread_rwlock_unlock(&ai.lock);

        if (flow->qs.ber == 0 && add_crc(sdb) != 0) {
                shm_rdrbuff_remove(ai.rdrb, idx);
                return -ENOMEM;
        }

        pthread_rwlock_rdlock(&ai.lock);

        if (flags & FLOWFWNOBLOCK)
                ret = shm_rbuff_write(flow->tx_rb, idx);
        else
                ret = shm_rbuff_write_b(flow->tx_rb, idx, abstime);

        if (ret < 0)
                shm_rdrbuff_remove(ai.rdrb, idx);
        else
                shm_flow_set_notify(flow->set, flow->flow_id, FLOW_PKT);

        pthread_rwlock_unlock(&ai.lock);

        assert(ret <= 0);

        return ret;
}

ssize_t flow_read(int    fd,
                  void * buf,
                  size_t count)
{
        ssize_t              idx;
        ssize_t              n;
        uint8_t *            packet;
        struct shm_rbuff *   rb;
        struct shm_du_buff * sdb;
        struct timespec      abs;
        struct timespec *    abstime = NULL;
        struct flow *        flow;
        bool                 noblock;
        bool                 partrd;

        if (fd < 0 || fd > PROG_MAX_FLOWS)
                return -EBADF;

        flow = &ai.flows[fd];

        if (flow->part_idx == DONE_PART) {
                flow->part_idx = NO_PART;
                return 0;
        }

        clock_gettime(PTHREAD_COND_CLOCK, &abs);

        pthread_rwlock_rdlock(&ai.lock);

        if (flow->flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        rb   = flow->rx_rb;
        noblock = flow->oflags & FLOWFRNOBLOCK;
        partrd = !(flow->oflags & FLOWFRNOPART);

        if (ai.flows[fd].rcv_timesout) {
                ts_add(&abs, &flow->rcv_timeo, &abs);
                abstime = &abs;
        }

        pthread_rwlock_unlock(&ai.lock);

        idx = flow->part_idx;
        if (idx < 0) {
                idx = frcti_queued_pdu(flow->frcti);
                if (idx < 0) {
                        do {
                                idx = noblock ? shm_rbuff_read(rb) :
                                        shm_rbuff_read_b(rb, abstime);
                                if (idx < 0)
                                        return idx;

                                sdb = shm_rdrbuff_get(ai.rdrb, idx);
                                if (flow->qs.ber == 0 && chk_crc(sdb) != 0) {
                                        shm_rdrbuff_remove(ai.rdrb, idx);
                                        continue;
                                }

                                pthread_rwlock_wrlock(&ai.lock);
                                if (flow->qs.cypher_s > 0)
                                        if (crypt_decrypt(flow, sdb) < 0) {
                                                pthread_rwlock_unlock(&ai.lock);
                                                shm_rdrbuff_remove(ai.rdrb,
                                                                   idx);
                                                return -ENOMEM;
                                        }
                                pthread_rwlock_unlock(&ai.lock);
                        } while (frcti_rcv(flow->frcti, sdb) != 0);
                }
        }

        n = shm_rdrbuff_read(&packet, ai.rdrb, idx);

        assert(n >= 0);

        if (n <= (ssize_t) count) {
                memcpy(buf, packet, n);
                shm_rdrbuff_remove(ai.rdrb, idx);
                flow->part_idx = (partrd && n == (ssize_t) count) ?
                        DONE_PART : NO_PART;
                return n;
        } else {
                if (partrd) {
                        memcpy(buf, packet, count);
                        sdb = shm_rdrbuff_get(ai.rdrb, idx);
                        shm_du_buff_head_release(sdb, n);
                        flow->part_idx = idx;
                        return count;
                } else {
                        shm_rdrbuff_remove(ai.rdrb, idx);
                        return -EMSGSIZE;
                }
        }
}

/* fqueue functions. */

struct flow_set * fset_create()
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

        pthread_rwlock_unlock(&ai.lock);

        return set;
}

void fset_destroy(struct flow_set * set)
{
        if (set == NULL)
                return;

        fset_zero(set);

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
        free(fq);
}

void fset_zero(struct flow_set * set)
{
        if (set == NULL)
                return;

        shm_flow_set_zero(ai.fqset, set->idx);
}

int fset_add(struct flow_set * set,
             int               fd)
{
        int    ret;
        size_t packets;
        size_t i;

        if (set == NULL || fd < 0 || fd > SYS_MAX_FLOWS)
                return -EINVAL;

        pthread_rwlock_wrlock(&ai.lock);

        if (ai.flows[fd].flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -EINVAL;
        }

        ret = shm_flow_set_add(ai.fqset, set->idx, ai.flows[fd].flow_id);

        packets = shm_rbuff_queued(ai.flows[fd].rx_rb);
        for (i = 0; i < packets; i++)
                shm_flow_set_notify(ai.fqset, ai.flows[fd].flow_id, FLOW_PKT);

        pthread_rwlock_unlock(&ai.lock);

        return ret;
}

void fset_del(struct flow_set * set,
              int               fd)
{
        if (set == NULL || fd < 0 || fd > SYS_MAX_FLOWS)
                return;

        pthread_rwlock_wrlock(&ai.lock);

        if (ai.flows[fd].flow_id >= 0)
                shm_flow_set_del(ai.fqset, set->idx, ai.flows[fd].flow_id);

        pthread_rwlock_unlock(&ai.lock);
}

bool fset_has(const struct flow_set * set,
              int                     fd)
{
        bool ret = false;

        if (set == NULL || fd < 0 || fd > SYS_MAX_FLOWS)
                return false;

        pthread_rwlock_rdlock(&ai.lock);

        if (ai.flows[fd].flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return false;
        }

        ret = (shm_flow_set_has(ai.fqset, set->idx, ai.flows[fd].flow_id) == 1);

        pthread_rwlock_unlock(&ai.lock);

        return ret;
}

int fqueue_next(struct fqueue * fq)
{
        int fd;

        if (fq == NULL)
                return -EINVAL;

        if (fq->fqsize == 0 || fq->next == fq->fqsize)
                return -EPERM;

        pthread_rwlock_rdlock(&ai.lock);

        fd = ai.ports[fq->fqueue[fq->next]].fd;

        fq->next += 2;

        pthread_rwlock_unlock(&ai.lock);

        return fd;
}

enum fqtype fqueue_type(struct fqueue * fq)
{
        if (fq == NULL)
                return -EINVAL;

        if (fq->fqsize == 0 || fq->next == 0)
                return -EPERM;

        return fq->fqueue[fq->next - 1];
}

int fevent(struct flow_set *       set,
           struct fqueue *         fq,
           const struct timespec * timeo)
{
        ssize_t           ret;
        struct timespec   abstime;
        struct timespec * t = NULL;

        if (set == NULL || fq == NULL)
                return -EINVAL;

        if (fq->fqsize > 0 && fq->next != fq->fqsize)
                return fq->fqsize;

        if (timeo != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeo, &abstime);
                t = &abstime;
        }

        ret = shm_flow_set_wait(ai.fqset, set->idx, fq->fqueue, t);
        if (ret == -ETIMEDOUT) {
                fq->fqsize = 0;
                return -ETIMEDOUT;
        }

        fq->fqsize = ret << 1;
        fq->next   = 0;

        assert(ret);

        return ret;
}

/* ipcp-dev functions. */

int np1_flow_alloc(pid_t     n_pid,
                   int       flow_id,
                   qosspec_t qs)
{
        qs.cypher_s = 0; /* No encryption ctx for np1 */
        return flow_init(flow_id, n_pid, qs, NULL);
}

int np1_flow_dealloc(int flow_id)
{
        int fd;

        pthread_rwlock_rdlock(&ai.lock);

        fd = ai.ports[flow_id].fd;

        pthread_rwlock_unlock(&ai.lock);

        return fd;
}

int np1_flow_resp(int flow_id)
{
        int fd;

        if (port_wait_assign(flow_id) != PORT_ID_ASSIGNED)
                return -1;

        pthread_rwlock_rdlock(&ai.lock);

        fd = ai.ports[flow_id].fd;

        pthread_rwlock_unlock(&ai.lock);

        return fd;
}

int ipcp_create_r(int result)
{
        irm_msg_t   msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg;
        int         ret;

        msg.code       = IRM_MSG_CODE__IPCP_CREATE_R;
        msg.has_pid    = true;
        msg.pid        = getpid();
        msg.has_result = true;
        msg.result     = result;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ipcp_flow_req_arr(const uint8_t * dst,
                      size_t          len,
                      qosspec_t       qs,
                      const void *    data,
                      size_t          dlen)
{
        irm_msg_t     msg = IRM_MSG__INIT;
        irm_msg_t *   recv_msg;
        qosspec_msg_t qs_msg;
        int           fd;

        assert(dst != NULL);

        msg.code      = IRM_MSG_CODE__IPCP_FLOW_REQ_ARR;
        msg.has_pid   = true;
        msg.pid       = getpid();
        msg.has_hash  = true;
        msg.hash.len  = len;
        msg.hash.data = (uint8_t *) dst;
        qs_msg        = spec_to_msg(&qs);
        msg.qosspec   = &qs_msg;
        msg.has_pk    = true;
        msg.pk.data   = (uint8_t *) data;
        msg.pk.len    = dlen;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_flow_id || !recv_msg->has_pid) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        if (recv_msg->has_result && recv_msg->result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        qs.cypher_s = 0; /* No encryption ctx for np1 */
        fd = flow_init(recv_msg->flow_id, recv_msg->pid, qs, NULL);

        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;
}

int ipcp_flow_alloc_reply(int          fd,
                          int          response,
                          const void * data,
                          size_t       len)
{
        irm_msg_t   msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg;
        int         ret;

        assert(fd >= 0 && fd < SYS_MAX_FLOWS);

        msg.code         = IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY;
        msg.has_flow_id  = true;
        msg.has_pk       = true;
        msg.pk.data      = (uint8_t *) data;
        msg.pk.len       = (uint32_t) len;

        pthread_rwlock_rdlock(&ai.lock);

        msg.flow_id = ai.flows[fd].flow_id;

        pthread_rwlock_unlock(&ai.lock);

        msg.has_response = true;
        msg.response     = response;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
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
        struct flow *      flow;
        struct shm_rbuff * rb;
        ssize_t            idx;

        assert(fd >= 0 && fd < SYS_MAX_FLOWS);
        assert(sdb);

        flow = &ai.flows[fd];

        pthread_rwlock_rdlock(&ai.lock);

        assert(flow->flow_id >= 0);

        rb = flow->rx_rb;

        pthread_rwlock_unlock(&ai.lock);

        if (flow->frcti != NULL) {
                idx = frcti_queued_pdu(flow->frcti);
                if (idx >= 0) {
                        *sdb = shm_rdrbuff_get(ai.rdrb, idx);
                        return 0;
                }
        }

        do {
                idx = shm_rbuff_read(rb);
                if (idx < 0)
                        return idx;
                *sdb = shm_rdrbuff_get(ai.rdrb, idx);
                if (flow->qs.ber == 0 && chk_crc(*sdb) != 0)
                        continue;
        } while (frcti_rcv(flow->frcti, *sdb) != 0);

        return 0;
}

int ipcp_flow_write(int                  fd,
                    struct shm_du_buff * sdb)
{
        struct flow * flow;
        int           ret;
        ssize_t       idx;

        assert(fd >= 0 && fd < SYS_MAX_FLOWS);
        assert(sdb);

        flow = &ai.flows[fd];

        pthread_rwlock_rdlock(&ai.lock);

        if (flow->flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        if ((flow->oflags & FLOWFACCMODE) == FLOWFRDONLY) {
                pthread_rwlock_unlock(&ai.lock);
                return -EPERM;
        }

        assert(flow->tx_rb);

        idx = shm_du_buff_get_idx(sdb);

        if (frcti_snd(flow->frcti, sdb) < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOMEM;
        }

        if (flow->qs.ber == 0 && add_crc(sdb) != 0) {
                pthread_rwlock_unlock(&ai.lock);
                shm_rdrbuff_remove(ai.rdrb, idx);
                return -ENOMEM;
        }

        ret = shm_rbuff_write_b(flow->tx_rb, idx, NULL);
        if (ret == 0)
                shm_flow_set_notify(flow->set, flow->flow_id, FLOW_PKT);
        else
                shm_rdrbuff_remove(ai.rdrb, idx);

        pthread_rwlock_unlock(&ai.lock);

        assert(ret <= 0);

        return ret;
}

int ipcp_sdb_reserve(struct shm_du_buff ** sdb,
                     size_t                len)
{
        return shm_rdrbuff_alloc_b(ai.rdrb, len, NULL, sdb, NULL) < 0 ? -1 : 0;
}

void ipcp_sdb_release(struct shm_du_buff * sdb)
{
        shm_rdrbuff_remove(ai.rdrb, shm_du_buff_get_idx(sdb));
}

int ipcp_flow_fini(int fd)
{
        struct shm_rbuff * rx_rb;

        assert(fd >= 0 && fd < SYS_MAX_FLOWS);

        pthread_rwlock_rdlock(&ai.lock);

        if (ai.flows[fd].flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -1;
        }

        shm_rbuff_set_acl(ai.flows[fd].rx_rb, ACL_FLOWDOWN);
        shm_rbuff_set_acl(ai.flows[fd].tx_rb, ACL_FLOWDOWN);

        shm_flow_set_notify(ai.flows[fd].set,
                            ai.flows[fd].flow_id,
                            FLOW_DEALLOC);

        rx_rb = ai.flows[fd].rx_rb;

        pthread_rwlock_unlock(&ai.lock);

        if (rx_rb != NULL)
                shm_rbuff_fini(rx_rb);

        return 0;
}

int ipcp_flow_get_qoscube(int         fd,
                          qoscube_t * cube)
{
        assert(fd >= 0 && fd < SYS_MAX_FLOWS);
        assert(cube);

        pthread_rwlock_rdlock(&ai.lock);

        assert(ai.flows[fd].flow_id >= 0);

        *cube = qos_spec_to_cube(ai.flows[fd].qs);

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
        struct flow * flow;
        int           ret;

        assert(fd >= 0);

        flow = &ai.flows[fd];

        pthread_rwlock_rdlock(&ai.lock);

        if (flow->flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }
        ret = shm_rbuff_write_b(flow->tx_rb, idx, NULL);
        if (ret == 0)
                shm_flow_set_notify(flow->set, flow->flow_id, FLOW_PKT);
        else
                shm_rdrbuff_remove(ai.rdrb, idx);

        pthread_rwlock_unlock(&ai.lock);

        return ret;
}
