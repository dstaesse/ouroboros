/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * API for applications
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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
#include <ouroboros/list.h>
#include <ouroboros/local-dev.h>
#include <ouroboros/sockets.h>
#include <ouroboros/fccntl.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/np1_flow.h>
#include <ouroboros/protobuf.h>
#include <ouroboros/pthread.h>
#include <ouroboros/random.h>
#include <ouroboros/shm_flow_set.h>
#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/shm_rbuff.h>
#include <ouroboros/utils.h>
#include <ouroboros/fqueue.h>
#ifdef PROC_FLOW_STATS
#include <ouroboros/rib.h>
#endif

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif
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
        struct list_head      next;

        struct shm_rbuff *    rx_rb;
        struct shm_rbuff *    tx_rb;
        struct shm_flow_set * set;
        int                   flow_id;
        uint16_t              oflags;
        qosspec_t             qs;
        ssize_t               part_idx;

        void *                ctx;
        uint8_t               key[SYMMKEYSZ];

        pid_t                 pid;

        struct timespec       snd_act;
        struct timespec       rcv_act;

        bool                  snd_timesout;
        bool                  rcv_timesout;
        struct timespec       snd_timeo;
        struct timespec       rcv_timeo;

        struct frcti *        frcti;
};

struct flow_set {
        size_t           idx;
        pthread_rwlock_t lock;
};

struct fqueue {
        struct flowevent fqueue[SHM_BUFFER_SIZE]; /* Safe copy from shm. */
        size_t           fqsize;
        size_t           next;
};

struct {
        struct shm_rdrbuff *  rdrb;
        struct shm_flow_set * fqset;

        struct bmp *          fds;
        struct bmp *          fqueues;

        struct flow *         flows;
        struct port *         ports;
        struct list_head      flow_list;

        pthread_t             tx;
        pthread_t             rx;
        size_t                n_frcti;
        fset_t *              frct_set;

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

        p->fd    = -1;
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
        msg.pid     = getpid();
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

#include "crypt.c"
#include "frct.c"

void * flow_tx(void * o)
{
        struct timespec tic = {0, TICTIME};

        (void) o;

        while (true) {
                timerwheel_move();

                nanosleep(&tic, NULL);
        }

        return (void *) 0;
}

static void flow_send_keepalive(struct flow * flow,
                                struct timespec now)
{
        struct shm_du_buff * sdb;
        ssize_t              idx;
        uint8_t *            ptr;

        idx = shm_rdrbuff_alloc(ai.rdrb, 0, &ptr, &sdb);
        if (idx < 0)
                return;

        pthread_rwlock_wrlock(&ai.lock);

        flow->snd_act = now;

        if (shm_rbuff_write(flow->tx_rb, idx))
                shm_rdrbuff_remove(ai.rdrb, idx);
        else
                shm_flow_set_notify(flow->set, flow->flow_id, FLOW_PKT);

        pthread_rwlock_unlock(&ai.lock);
}

/* Needs rdlock on ai. */
static void _flow_keepalive(struct flow * flow)
{
        struct timespec    now;
        struct timespec    s_act;
        struct timespec    r_act;
        int                flow_id;
        time_t             timeo;
        uint32_t           acl;

        s_act = flow->snd_act;
        r_act = flow->rcv_act;

        flow_id = flow->flow_id;
        timeo   = flow->qs.timeout;

        acl = shm_rbuff_get_acl(flow->rx_rb);
        if (timeo == 0 ||  acl & (ACL_FLOWPEER | ACL_FLOWDOWN))
                return;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        if (ts_diff_ns(&r_act, &now) > timeo * MILLION) {
                shm_rbuff_set_acl(flow->rx_rb, ACL_FLOWPEER);
                shm_flow_set_notify(ai.fqset, flow_id, FLOW_PEER);
                return;
        }

        if (ts_diff_ns(&s_act, &now) > (timeo * MILLION) >> 2) {
                pthread_rwlock_unlock(&ai.lock);

                flow_send_keepalive(flow, now);

                pthread_rwlock_rdlock(&ai.lock);
        }
}

static void handle_keepalives(void)
{
        struct list_head * p;
        struct list_head * h;

        pthread_rwlock_rdlock(&ai.lock);

        list_for_each_safe(p, h, &ai.flow_list) {
                struct flow * flow;
                flow = list_entry(p, struct flow, next);
                _flow_keepalive(flow);
        }

        pthread_rwlock_unlock(&ai.lock);
}

static void __cleanup_fqueue_destroy(void * fq)
{
        fqueue_destroy((fqueue_t *) fq);
}

void * flow_rx(void * o)
{
        struct timespec tic = {0, TICTIME};
        int             ret;
        struct fqueue * fq;

        (void) o;

        fq = fqueue_create();

        pthread_cleanup_push(__cleanup_fqueue_destroy, fq);

        /* fevent will filter all FRCT packets for us */
        while ((ret = fevent(ai.frct_set, fq, &tic)) != 0) {
                if (ret == -ETIMEDOUT) {
                        handle_keepalives();
                        continue;
                }

                while (fqueue_next(fq) >= 0)
                        ; /* no need to act */
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

static void flow_clear(int fd)
{
        memset(&ai.flows[fd], 0, sizeof(ai.flows[fd]));

        ai.flows[fd].flow_id  = -1;
        ai.flows[fd].pid      = -1;
}

static void flow_fini(int fd)
{
        assert(fd >= 0 && fd < SYS_MAX_FLOWS);

        if (ai.flows[fd].frcti != NULL) {
                ai.n_frcti--;
                if (ai.n_frcti == 0) {
                        pthread_cancel(ai.tx);
                        pthread_join(ai.tx, NULL);
                }

                shm_flow_set_del(ai.fqset, 0, ai.flows[fd].flow_id);

                frcti_destroy(ai.flows[fd].frcti);
        }

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

        if (ai.flows[fd].ctx != NULL)
                crypt_fini(ai.flows[fd].ctx);

        list_del(&ai.flows[fd].next);

        flow_clear(fd);
}

static int flow_init(int       flow_id,
                     pid_t     pid,
                     qosspec_t qs,
                     uint8_t * s,
                     time_t    mpl)
{
        struct timespec now;
        struct flow *   flow;
        int             fd;
        int             err = -ENOMEM;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_rwlock_wrlock(&ai.lock);

        fd = bmp_allocate(ai.fds);
        if (!bmp_is_id_valid(ai.fds, fd)) {
                err = -EBADF;
                goto fail_fds;
        }

        flow = &ai.flows[fd];

        flow->rx_rb = shm_rbuff_open(getpid(), flow_id);
        if (flow->rx_rb == NULL)
                goto fail_rx_rb;

        flow->tx_rb = shm_rbuff_open(pid, flow_id);
        if (flow->tx_rb == NULL)
                goto fail_tx_rb;

        flow->set = shm_flow_set_open(pid);
        if (flow->set == NULL)
                goto fail_set;

        flow->flow_id  = flow_id;
        flow->oflags   = FLOWFDEFAULT;
        flow->pid      = pid;
        flow->part_idx = NO_PART;
        flow->qs       = qs;
        flow->snd_act  = now;
        flow->rcv_act  = now;

        if (qs.cypher_s > 0) {
                if (crypt_init(&flow->ctx) < 0)
                        goto fail_ctx;

                memcpy(flow->key, s, SYMMKEYSZ);
        }

        assert(flow->frcti == NULL);

        if (flow->qs.in_order != 0) {
                flow->frcti = frcti_create(fd, DELT_A, DELT_R, mpl);
                if (flow->frcti == NULL)
                        goto fail_frcti;

                if (shm_flow_set_add(ai.fqset, 0, flow_id))
                        goto fail_flow_set_add;

                ++ai.n_frcti;
                if (ai.n_frcti == 1 &&
                    pthread_create(&ai.tx, NULL, flow_tx, NULL) < 0)
                        goto fail_tx_thread;
        }

        list_add_tail(&flow->next, &ai.flow_list);

        ai.ports[flow_id].fd = fd;

        port_set_state(&ai.ports[flow_id], PORT_ID_ASSIGNED);

        pthread_rwlock_unlock(&ai.lock);

        return fd;

 fail_tx_thread:
        shm_flow_set_del(ai.fqset, 0, flow_id);
 fail_flow_set_add:
        frcti_destroy(flow->frcti);
 fail_frcti:
        crypt_fini(flow->ctx);
 fail_ctx:
        shm_flow_set_close(flow->set);
 fail_set:
        shm_rbuff_close(flow->tx_rb);
 fail_tx_rb:
        shm_rbuff_close(flow->rx_rb);
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
        char * prog = argv[0];
        int    i;
#ifdef PROC_FLOW_STATS
        char   procstr[32];
#endif
        (void) argc;
        (void) envp;

        if (check_python(argv[0]))
                prog = argv[1];

        prog = path_strip(prog);
        if (prog == NULL) {
                fprintf(stderr, "FATAL: Could not find program name.");
                goto fail_prog;
        }

        if (proc_announce(prog)) {
                fprintf(stderr, "FATAL: Could not announce to IRMd.");
                goto fail_prog;
        }

#ifdef HAVE_LIBGCRYPT
        if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
                if (!gcry_check_version(GCRYPT_VERSION)) {
                        fprintf(stderr, "FATAL: Could not get gcry version.");
                        goto fail_prog;
                }
                gcry_control(GCRYCTL_DISABLE_SECMEM, 0);
                gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
        }
#endif
        ai.fds = bmp_create(PROG_MAX_FLOWS - PROG_RES_FDS, PROG_RES_FDS);
        if (ai.fds == NULL) {
                fprintf(stderr, "FATAL: Could not create fd bitmap.");
                goto fail_fds;
        }

        ai.fqueues = bmp_create(PROG_MAX_FQUEUES, 0);
        if (ai.fqueues == NULL) {
                fprintf(stderr, "FATAL: Could not create fqueue bitmap.");
                goto fail_fqueues;
        }

        ai.rdrb = shm_rdrbuff_open();
        if (ai.rdrb == NULL) {
                fprintf(stderr, "FATAL: Could not open packet buffer.");
                goto fail_rdrb;
        }

        ai.flows = malloc(sizeof(*ai.flows) * PROG_MAX_FLOWS);
        if (ai.flows == NULL)
                goto fail_flows;

        for (i = 0; i < PROG_MAX_FLOWS; ++i)
                flow_clear(i);

        ai.ports = malloc(sizeof(*ai.ports) * SYS_MAX_FLOWS);
        if (ai.ports == NULL)
                goto fail_ports;

        for (i = 0; i < SYS_MAX_FLOWS; ++i) {
                ai.ports[i].state = PORT_INIT;
                if (pthread_mutex_init(&ai.ports[i].state_lock, NULL)) {
                        fprintf(stderr, "FATAL: Could not init lock %d.", i);
                        goto fail_flow_lock;
                }
                if (pthread_cond_init(&ai.ports[i].state_cond, NULL)) {
                        pthread_mutex_destroy(&ai.ports[i].state_lock);
                        fprintf(stderr, "FATAL: Could not init cond %d.", i);
                        goto fail_flow_lock;
                }
        } /* Do not reuse i after this ! */

        if (pthread_rwlock_init(&ai.lock, NULL)) {
                fprintf(stderr, "FATAL: Could not initialize flow lock");
                goto fail_flow_lock;
        }

        ai.fqset = shm_flow_set_open(getpid());
        if (ai.fqset == NULL) {
                fprintf(stderr, "FATAL: Could not open flow set.");
                goto fail_fqset;
        }

        ai.frct_set = fset_create();
        if (ai.frct_set == NULL || ai.frct_set->idx != 0) {
                fprintf(stderr, "FATAL: Could not create FRCT set.");
                goto fail_frct_set;
        }

        if (timerwheel_init() < 0) {
                fprintf(stderr, "FATAL: Could not initialize timerwheel.");
                goto fail_timerwheel;
        }

#if defined PROC_FLOW_STATS
        if (strstr(argv[0], "ipcpd") == NULL) {
                sprintf(procstr, "proc.%d", getpid());
                if (rib_init(procstr) < 0) {
                        fprintf(stderr, "FATAL: Could not initialize RIB.");
                        goto fail_rib_init;
                }
        }
#endif
        if (pthread_create(&ai.rx, NULL, flow_rx, NULL) < 0) {
                fprintf(stderr, "FATAL: Could not start monitor thread.");
                goto fail_monitor;
        }

        list_head_init(&ai.flow_list);

        return;

 fail_monitor:
#if defined PROC_FLOW_STATS
        rib_fini();
 fail_rib_init:
#endif
        timerwheel_fini();
 fail_timerwheel:
        fset_destroy(ai.frct_set);
 fail_frct_set:
        shm_flow_set_close(ai.fqset);
 fail_fqset:
        pthread_rwlock_destroy(&ai.lock);
 fail_flow_lock:
        while (i-- > 0) {
                pthread_mutex_destroy(&ai.ports[i].state_lock);
                pthread_cond_destroy(&ai.ports[i].state_cond);
        }
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
        memset(&ai, 0, sizeof(ai));
 fail_prog:
        exit(EXIT_FAILURE);
}

static void fini(void)
{
        int  i;

        if (ai.fds == NULL)
                return;

        pthread_cancel(ai.rx);
        pthread_join(ai.rx, NULL);

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

        for (i = 0; i < SYS_MAX_FLOWS; ++i) {
                pthread_mutex_destroy(&ai.ports[i].state_lock);
                pthread_cond_destroy(&ai.ports[i].state_cond);
        }

        pthread_rwlock_unlock(&ai.lock);

#ifdef PROC_FLOW_STATS
        rib_fini();
#endif

        timerwheel_fini();

        fset_destroy(ai.frct_set);

        shm_flow_set_close(ai.fqset);

        pthread_rwlock_destroy(&ai.lock);

        free(ai.flows);
        free(ai.ports);

        shm_rdrbuff_close(ai.rdrb);

        bmp_destroy(ai.fds);
        bmp_destroy(ai.fqueues);

        memset(&ai, 0, sizeof(ai));
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
        msg.pid     = getpid();

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
        if (key_len > 0) {
                msg.has_pk  = true;
                msg.pk.data = buf;
                msg.pk.len  = (uint32_t) key_len;
        }

        pthread_cleanup_push(crypt_dh_pkp_destroy, pkp);

        recv_msg = send_recv_irm_msg(&msg);

        pthread_cleanup_pop(false);

        if (recv_msg == NULL)
                goto fail_recv;

        if (!recv_msg->has_result)
                goto fail_msg;

        if (recv_msg->result !=  0) {
                err = recv_msg->result;
                goto fail_msg;
        }

        if (!recv_msg->has_pid || !recv_msg->has_flow_id ||
            !recv_msg->has_mpl || recv_msg->qosspec == NULL)
                goto fail_msg;

        if (recv_msg->pk.len != 0 &&
            crypt_dh_derive(pkp, recv_msg->pk.data,
                            recv_msg->pk.len, s) < 0) {
                err = -ECRYPT;
                goto fail_msg;
        }

        crypt_dh_pkp_destroy(pkp);

        fd = flow_init(recv_msg->flow_id, recv_msg->pid,
                       qos_spec_msg_to_s(recv_msg->qosspec), s,
                       recv_msg->mpl);

        irm_msg__free_unpacked(recv_msg, NULL);

        if (fd < 0)
                return fd;


        pthread_rwlock_rdlock(&ai.lock);

        if (qs != NULL)
                *qs = ai.flows[fd].qs;

        pthread_rwlock_unlock(&ai.lock);

        return fd;

 fail_msg:
        irm_msg__free_unpacked(recv_msg, NULL);
 fail_recv:
        crypt_dh_pkp_destroy(pkp);
 fail_crypt_pkp:
        return err;
}

int flow_alloc(const char *            dst,
               qosspec_t *             qs,
               const struct timespec * timeo)
{
        irm_msg_t     msg    = IRM_MSG__INIT;
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
        msg.code    = IRM_MSG_CODE__IRM_FLOW_ALLOC;
        msg.dst     = (char *) dst;
        msg.has_pid = true;
        msg.pid     = getpid();
        msg.qosspec = qos_spec_s_to_msg(qs == NULL ? &qos_raw : qs);

        if (timeo != NULL) {
                msg.has_timeo_sec = true;
                msg.has_timeo_nsec = true;
                msg.timeo_sec  = timeo->tv_sec;
                msg.timeo_nsec = timeo->tv_nsec;
        }

        if (qs != NULL && qs->cypher_s != 0) {
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
        qosspec_msg__free_unpacked(msg.qosspec, NULL);

        if (recv_msg == NULL)
                goto fail_send;

        if (!recv_msg->has_result)
                goto fail_result;

        if (recv_msg->result != 0) {
                err = recv_msg->result;
                goto fail_result;
        }

        if (!recv_msg->has_pid || !recv_msg->has_flow_id ||
            !recv_msg->has_mpl)
                goto fail_result;

        if (qs != NULL && qs->cypher_s != 0) {
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

        /* TODO: Make sure qosspec is set in msg */
        if (qs != NULL && recv_msg->qosspec != NULL)
                *qs = qos_spec_msg_to_s(recv_msg->qosspec);

        fd = flow_init(recv_msg->flow_id, recv_msg->pid,
                       qs == NULL ? qos_raw : *qs, s,
                       recv_msg->mpl);

        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;

 fail_result:
        irm_msg__free_unpacked(recv_msg, NULL);
 fail_send:
        crypt_dh_pkp_destroy(pkp);
 fail_crypt_pkp:
        return err;
}

int flow_join(const char *            dst,
              qosspec_t *             qs,
              const struct timespec * timeo)
{
        irm_msg_t     msg    = IRM_MSG__INIT;
        irm_msg_t *   recv_msg;
        uint8_t       s[SYMMKEYSZ];
        int           fd;
        int           err = -EIRMD;

#ifdef QOS_DISABLE_CRC
        if (qs != NULL)
                qs->ber = 1;
#endif
        if (qs != NULL && qs->cypher_s > 0)
                return -ENOTSUP; /* TODO: Encrypted broadcast */

        memset(s, 0, SYMMKEYSZ);

        msg.code    = IRM_MSG_CODE__IRM_FLOW_JOIN;
        msg.dst     = (char *) dst;
        msg.has_pid = true;
        msg.pid     = getpid();
        msg.qosspec = qos_spec_s_to_msg(qs == NULL ? &qos_raw : qs);

        if (timeo != NULL) {
                msg.has_timeo_sec = true;
                msg.has_timeo_nsec = true;
                msg.timeo_sec  = timeo->tv_sec;
                msg.timeo_nsec = timeo->tv_nsec;
        }

        recv_msg = send_recv_irm_msg(&msg);
        qosspec_msg__free_unpacked(msg.qosspec, NULL);

        if (recv_msg == NULL)
                goto fail_send;

        if (!recv_msg->has_result)
                goto fail_result;

        if (recv_msg->result != 0) {
                err = recv_msg->result;
                goto fail_result;
        }

        if (!recv_msg->has_pid || !recv_msg->has_flow_id ||
            !recv_msg->has_mpl)
                goto fail_result;

        fd = flow_init(recv_msg->flow_id, recv_msg->pid,
                       qs == NULL ? qos_raw : *qs, s,
                       recv_msg->mpl);

        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;

 fail_result:
        irm_msg__free_unpacked(recv_msg, NULL);
 fail_send:
        return err;
}

int flow_dealloc(int fd)
{
        irm_msg_t       msg = IRM_MSG__INIT;
        irm_msg_t *     recv_msg;
        uint8_t         buf[128];
        struct timespec tic = {0, TICTIME};
        struct flow *   f;
        time_t          timeo;

        if (fd < 0 || fd >= SYS_MAX_FLOWS )
                return -EINVAL;

        msg.code           = IRM_MSG_CODE__IRM_FLOW_DEALLOC;
        msg.has_flow_id    = true;
        msg.has_pid        = true;
        msg.pid            = getpid();
        msg.has_timeo_sec  = true;
        msg.has_timeo_nsec = true;
        msg.timeo_nsec     = 0;

        f = &ai.flows[fd];

        pthread_rwlock_rdlock(&ai.lock);

        if (f->flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        msg.flow_id = f->flow_id;

        f->oflags = FLOWFDEFAULT | FLOWFRNOPART;

        f->rcv_timesout = true;
        f->rcv_timeo = tic;

        pthread_rwlock_unlock(&ai.lock);

        flow_read(fd, buf, 128);

        pthread_rwlock_rdlock(&ai.lock);

        timeo = frcti_dealloc(f->frcti);
        while (timeo < 0) { /* keep the flow active for rtx */
                ssize_t         ret;

                pthread_rwlock_unlock(&ai.lock);

                ret = flow_read(fd, buf, 128);

                pthread_rwlock_rdlock(&ai.lock);

                timeo = frcti_dealloc(f->frcti);

                if (ret == -EFLOWDOWN && timeo < 0)
                        timeo = -timeo;
        }

        msg.timeo_sec = timeo;

        pthread_cleanup_push(__cleanup_rwlock_unlock, &ai.lock);

        shm_rbuff_fini(ai.flows[fd].tx_rb);

        pthread_cleanup_pop(true);

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
        uint16_t          csflags;
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
        case FRCTSFLAGS:
                csflags = (uint16_t) va_arg(l, uint32_t);
                if (flow->frcti == NULL)
                        goto eperm;
                frcti_setflags(flow->frcti, csflags);
                break;
        case FRCTGFLAGS:
                cflags = (uint16_t *) va_arg(l, uint32_t *);
                if (cflags == NULL)
                        goto einval;
                if (flow->frcti == NULL)
                        goto eperm;
                *cflags = frcti_getflags(flow->frcti);
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

static int flow_tx_sdb(struct flow *        flow,
                       struct shm_du_buff * sdb,
                       bool                 block,
                       struct timespec *    abstime)
{
        struct timespec now;
        ssize_t         idx;
        int             ret;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_rwlock_wrlock(&ai.lock);

        flow->snd_act = now;

        pthread_rwlock_unlock(&ai.lock);

        idx = shm_du_buff_get_idx(sdb);

        pthread_rwlock_rdlock(&ai.lock);

        if (shm_du_buff_len(sdb) > 0) {
                if (frcti_snd(flow->frcti, sdb) < 0)
                        goto enomem;

                if (flow->qs.cypher_s > 0 && crypt_encrypt(flow, sdb) < 0)
                        goto enomem;

                if (flow->qs.ber == 0 && add_crc(sdb) != 0)
                        goto enomem;
        }

        pthread_cleanup_push(__cleanup_rwlock_unlock, &ai.lock);

        if (!block)
                ret = shm_rbuff_write(flow->tx_rb, idx);
        else
                ret = shm_rbuff_write_b(flow->tx_rb, idx, abstime);

        if (ret < 0)
                shm_rdrbuff_remove(ai.rdrb, idx);
        else
                shm_flow_set_notify(flow->set, flow->flow_id, FLOW_PKT);

        pthread_cleanup_pop(true);

        return 0;

enomem:
        pthread_rwlock_unlock(&ai.lock);
        shm_rdrbuff_remove(ai.rdrb, idx);
        return -ENOMEM;
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

        if (buf == NULL && count != 0)
                return -EINVAL;

        if (fd < 0 || fd >= PROG_MAX_FLOWS)
                return -EBADF;

        flow = &ai.flows[fd];

        clock_gettime(PTHREAD_COND_CLOCK, &abs);

        pthread_rwlock_wrlock(&ai.lock);

        if (flow->flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        if (flow->snd_timesout) {
                ts_add(&abs, &flow->snd_timeo, &abs);
                abstime = &abs;
        }

        flags = flow->oflags;

        pthread_rwlock_unlock(&ai.lock);

        if ((flags & FLOWFACCMODE) == FLOWFRDONLY)
                return -EPERM;

        if (flags & FLOWFWNOBLOCK) {
                if (!frcti_is_window_open(flow->frcti))
                        return -EAGAIN;
                idx = shm_rdrbuff_alloc(ai.rdrb, count, &ptr, &sdb);
        } else {
                ret = frcti_window_wait(flow->frcti, abstime);
                if (ret < 0)
                        return ret;
                idx = shm_rdrbuff_alloc_b(ai.rdrb, count, &ptr, &sdb, abstime);
        }

        if (idx < 0)
                return idx;

        if (count > 0)
                memcpy(ptr, buf, count);

        ret = flow_tx_sdb(flow, sdb, !(flags & FLOWFWNOBLOCK), abstime);

        return ret < 0 ? (ssize_t) ret : (ssize_t) count;
}

static bool invalid_pkt(struct flow *        flow,
                        struct shm_du_buff * sdb)
{
        if (shm_du_buff_len(sdb) == 0)
                return true;

        if (flow->qs.ber == 0 && chk_crc(sdb) != 0)
                return true;

        if (flow->qs.cypher_s > 0 && crypt_decrypt(flow, sdb) < 0)
                return true;

        return false;
}

static ssize_t flow_rx_sdb(struct flow *         flow,
                           struct shm_du_buff ** sdb,
                           bool                  block,
                           struct timespec *     abstime)
{
        ssize_t         idx;
        struct timespec now;

        idx = block ? shm_rbuff_read_b(flow->rx_rb, abstime) :
                shm_rbuff_read(flow->rx_rb);
        if (idx < 0)
                return idx;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_rwlock_wrlock(&ai.lock);

        flow->rcv_act = now;

        pthread_rwlock_unlock(&ai.lock);

        *sdb = shm_rdrbuff_get(ai.rdrb, idx);
        if (invalid_pkt(flow, *sdb)) {
                shm_rdrbuff_remove(ai.rdrb, idx);
                return -EAGAIN;
        }

        return idx;
}

ssize_t flow_read(int    fd,
                  void * buf,
                  size_t count)
{
        ssize_t              idx;
        ssize_t              n;
        uint8_t *            packet;
        struct shm_du_buff * sdb;
        struct timespec      abs;
        struct timespec      now;
        struct timespec *    abstime = NULL;
        struct flow *        flow;
        bool                 block;
        bool                 partrd;

        if (fd < 0 || fd >= PROG_MAX_FLOWS)
                return -EBADF;

        flow = &ai.flows[fd];

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_rwlock_rdlock(&ai.lock);

        if (flow->flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        if (flow->part_idx == DONE_PART) {
                pthread_rwlock_unlock(&ai.lock);
                flow->part_idx = NO_PART;
                return 0;
        }

        block  = !(flow->oflags & FLOWFRNOBLOCK);
        partrd = !(flow->oflags & FLOWFRNOPART);

        if (flow->rcv_timesout) {
                ts_add(&now, &flow->rcv_timeo, &abs);
                abstime = &abs;
        }

        idx = flow->part_idx;
        if (idx < 0) {
                while ((idx = frcti_queued_pdu(flow->frcti)) < 0) {
                        pthread_rwlock_unlock(&ai.lock);

                        idx = flow_rx_sdb(flow, &sdb, block, abstime);
                        if (idx < 0) {
                                if (block && idx != -EAGAIN)
                                        return idx;
                                if (!block)
                                        return idx;

                                pthread_rwlock_rdlock(&ai.lock);
                                continue;
                        }

                        pthread_rwlock_rdlock(&ai.lock);

                        frcti_rcv(flow->frcti, sdb);
                }
        }

        sdb = shm_rdrbuff_get(ai.rdrb, idx);

        pthread_rwlock_unlock(&ai.lock);

        packet = shm_du_buff_head(sdb);

        n = shm_du_buff_len(sdb);

        assert(n >= 0);

        if (n <= (ssize_t) count) {
                memcpy(buf, packet, n);
                ipcp_sdb_release(sdb);

                pthread_rwlock_wrlock(&ai.lock);

                flow->part_idx = (partrd && n == (ssize_t) count) ?
                        DONE_PART : NO_PART;

                flow->rcv_act = now;

                pthread_rwlock_unlock(&ai.lock);
                return n;
        } else {
                if (partrd) {
                        memcpy(buf, packet, count);
                        shm_du_buff_head_release(sdb, n);
                        pthread_rwlock_wrlock(&ai.lock);
                        flow->part_idx = idx;

                        flow->rcv_act = now;

                        pthread_rwlock_unlock(&ai.lock);
                        return count;
                } else {
                        ipcp_sdb_release(sdb);
                        return -EMSGSIZE;
                }
        }
}

/* fqueue functions. */

struct flow_set * fset_create(void)
{
        struct flow_set * set;

        set = malloc(sizeof(*set));
        if (set == NULL)
                goto fail_malloc;

        assert(ai.fqueues);

        pthread_rwlock_wrlock(&ai.lock);

        set->idx = bmp_allocate(ai.fqueues);
        if (!bmp_is_id_valid(ai.fqueues, set->idx))
                goto fail_bmp_alloc;

        pthread_rwlock_unlock(&ai.lock);

        return set;

 fail_bmp_alloc:
        pthread_rwlock_unlock(&ai.lock);
        free(set);
 fail_malloc:
        return NULL;
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

struct fqueue * fqueue_create(void)
{
        struct fqueue * fq = malloc(sizeof(*fq));
        if (fq == NULL)
                return NULL;

        memset(fq->fqueue, -1, SHM_BUFFER_SIZE * sizeof(*fq->fqueue));
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
        struct flow *           flow;
        int                     ret;

        if (set == NULL || fd < 0 || fd >= SYS_MAX_FLOWS)
                return -EINVAL;

        flow = &ai.flows[fd];

        pthread_rwlock_rdlock(&ai.lock);

        if (flow->flow_id < 0) {
                ret = -EINVAL;
                goto fail;
        }

        if (flow->frcti != NULL)
                shm_flow_set_del(ai.fqset, 0, ai.flows[fd].flow_id);

        ret = shm_flow_set_add(ai.fqset, set->idx, ai.flows[fd].flow_id);
        if (ret < 0)
                goto fail;

        if (shm_rbuff_queued(ai.flows[fd].rx_rb))
                shm_flow_set_notify(ai.fqset, ai.flows[fd].flow_id, FLOW_PKT);

        pthread_rwlock_unlock(&ai.lock);

        return ret;

 fail:
        pthread_rwlock_unlock(&ai.lock);
        return ret;
}

void fset_del(struct flow_set * set,
              int               fd)
{
        struct flow * flow;

        if (set == NULL || fd < 0 || fd >= SYS_MAX_FLOWS)
                return;

        flow = &ai.flows[fd];

        pthread_rwlock_rdlock(&ai.lock);

        if (flow->flow_id >= 0)
                shm_flow_set_del(ai.fqset, set->idx, flow->flow_id);

        if (flow->frcti != NULL)
                shm_flow_set_add(ai.fqset, 0, ai.flows[fd].flow_id);

        pthread_rwlock_unlock(&ai.lock);
}

bool fset_has(const struct flow_set * set,
              int                     fd)
{
        bool ret;

        if (set == NULL || fd < 0 || fd >= SYS_MAX_FLOWS)
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

/* Filter fqueue events for non-data packets */
static int fqueue_filter(struct fqueue * fq)
{
        struct shm_du_buff * sdb;
        int                  fd;
        ssize_t              idx;
        struct frcti *       frcti;

        while (fq->next < fq->fqsize) {
                if (fq->fqueue[fq->next].event != FLOW_PKT)
                        return 1;

                pthread_rwlock_rdlock(&ai.lock);

                fd = ai.ports[fq->fqueue[fq->next].flow_id].fd;
                if (fd < 0) {
                        ++fq->next;
                        pthread_rwlock_unlock(&ai.lock);
                        continue;
                }

                frcti = ai.flows[fd].frcti;
                if (frcti == NULL) {
                        pthread_rwlock_unlock(&ai.lock);
                        return 1;
                }

                if (__frcti_pdu_ready(frcti) >= 0) {
                        pthread_rwlock_unlock(&ai.lock);
                        return 1;
                }

                pthread_rwlock_unlock(&ai.lock);

                idx = flow_rx_sdb(&ai.flows[fd], &sdb, false, NULL);
                if (idx < 0)
                        return 0;

                pthread_rwlock_rdlock(&ai.lock);

                sdb = shm_rdrbuff_get(ai.rdrb, idx);

                __frcti_rcv(frcti, sdb);

                if (__frcti_pdu_ready(frcti) >= 0) {
                        pthread_rwlock_unlock(&ai.lock);
                        return 1;
                }

                pthread_rwlock_unlock(&ai.lock);

                ++fq->next;
        }

        return 0;
}

int fqueue_next(struct fqueue * fq)
{
        int                fd;
        struct flowevent * e;

        if (fq == NULL)
                return -EINVAL;

        if (fq->fqsize == 0 || fq->next == fq->fqsize)
                return -EPERM;

        if (fq->next != 0 && fqueue_filter(fq) == 0)
                return -EPERM;

        pthread_rwlock_rdlock(&ai.lock);

        e = fq->fqueue + fq->next;

        fd = ai.ports[e->flow_id].fd;

        ++fq->next;

        pthread_rwlock_unlock(&ai.lock);

        return fd;
}

enum fqtype fqueue_type(struct fqueue * fq)
{
        if (fq == NULL)
                return -EINVAL;

        if (fq->fqsize == 0 || fq->next == 0)
                return -EPERM;

        return fq->fqueue[(fq->next - 1)].event;
}

ssize_t fevent(struct flow_set *       set,
               struct fqueue *         fq,
               const struct timespec * timeo)
{
        ssize_t           ret = 0;
        struct timespec   abs;
        struct timespec * t = NULL;

        if (set == NULL || fq == NULL)
                return -EINVAL;

        if (fq->fqsize > 0 && fq->next != fq->fqsize)
                return 1;

        clock_gettime(PTHREAD_COND_CLOCK, &abs);

        if (timeo != NULL) {
                ts_add(&abs, timeo, &abs);
                t = &abs;
        }

        while (ret == 0) {
                ret = shm_flow_set_wait(ai.fqset, set->idx, fq->fqueue, t);
                if (ret == -ETIMEDOUT)
                        return -ETIMEDOUT;

                fq->fqsize = ret;
                fq->next   = 0;

                ret = fqueue_filter(fq);
        }

        assert(ret != 0);

        return 1;
}

/* ipcp-dev functions. */

int np1_flow_alloc(pid_t     n_pid,
                   int       flow_id)
{
        return flow_init(flow_id, n_pid, qos_np1, NULL, 0);
}

int np1_flow_dealloc(int    flow_id,
                     time_t timeo)
{
        int fd;

        /*
         * TODO: Don't pass timeo to the IPCP but wait in IRMd.
         * This will need async ops, waiting until we bootstrap
         * the IRMd over ouroboros.
         */

        sleep(timeo);

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
                      time_t          mpl,
                      const void *    data,
                      size_t          dlen)
{
        irm_msg_t     msg = IRM_MSG__INIT;
        irm_msg_t *   recv_msg;
        int           fd;

        assert(dst != NULL);

        msg.code      = IRM_MSG_CODE__IPCP_FLOW_REQ_ARR;
        msg.has_pid   = true;
        msg.pid       = getpid();
        msg.has_hash  = true;
        msg.hash.len  = len;
        msg.hash.data = (uint8_t *) dst;
        msg.qosspec   = qos_spec_s_to_msg(&qs);
        msg.has_mpl   = true;
        msg.mpl       = mpl;
        msg.has_pk    = true;
        msg.pk.data   = (uint8_t *) data;
        msg.pk.len    = dlen;

        recv_msg = send_recv_irm_msg(&msg);
        qosspec_msg__free_unpacked(msg.qosspec, NULL);

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

        fd = flow_init(recv_msg->flow_id, recv_msg->pid, qos_np1, NULL, 0);

        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;
}

int ipcp_flow_alloc_reply(int          fd,
                          int          response,
                          time_t       mpl,
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
        msg.has_mpl      = true;
        msg.mpl          = mpl;

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
        struct flow * flow;
        ssize_t       idx = -1;

        assert(fd >= 0 && fd < SYS_MAX_FLOWS);
        assert(sdb);

        flow = &ai.flows[fd];

        pthread_rwlock_rdlock(&ai.lock);

        assert(flow->flow_id >= 0);

        while (frcti_queued_pdu(flow->frcti) < 0) {
                pthread_rwlock_unlock(&ai.lock);

                idx = flow_rx_sdb(flow, sdb, false, NULL);
                if (idx < 0)
                        return idx;

                pthread_rwlock_rdlock(&ai.lock);

                frcti_rcv(flow->frcti, *sdb);
        }

        pthread_rwlock_unlock(&ai.lock);

        return 0;
}

int ipcp_flow_write(int                  fd,
                    struct shm_du_buff * sdb)
{
        struct flow *   flow;
        int             ret;

        assert(fd >= 0 && fd < SYS_MAX_FLOWS);
        assert(sdb);

        flow = &ai.flows[fd];

        pthread_rwlock_wrlock(&ai.lock);

        if (flow->flow_id < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return -ENOTALLOC;
        }

        if ((flow->oflags & FLOWFACCMODE) == FLOWFRDONLY) {
                pthread_rwlock_unlock(&ai.lock);
                return -EPERM;
        }

        pthread_rwlock_unlock(&ai.lock);

        ret = flow_tx_sdb(flow, sdb, true, NULL);

        return ret;
}

int np1_flow_read(int                   fd,
                  struct shm_du_buff ** sdb)
{
        struct flow *    flow;
        ssize_t          idx = -1;

        assert(fd >= 0 && fd < SYS_MAX_FLOWS);
        assert(sdb);

        flow = &ai.flows[fd];

        assert(flow->flow_id >= 0);

        pthread_rwlock_rdlock(&ai.lock);

        idx = shm_rbuff_read(flow->rx_rb);;
        if (idx < 0) {
                pthread_rwlock_unlock(&ai.lock);
                return idx;
        }

        pthread_rwlock_unlock(&ai.lock);

        *sdb = shm_rdrbuff_get(ai.rdrb, idx);

        return 0;
}

int np1_flow_write(int                  fd,
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

        pthread_rwlock_unlock(&ai.lock);

        idx = shm_du_buff_get_idx(sdb);

        ret = shm_rbuff_write_b(flow->tx_rb, idx, NULL);
        if (ret < 0)
                shm_rdrbuff_remove(ai.rdrb, idx);
        else
                shm_flow_set_notify(flow->set, flow->flow_id, FLOW_PKT);

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

size_t ipcp_flow_queued(int fd)
{
        size_t q;

        pthread_rwlock_rdlock(&ai.lock);

        assert(ai.flows[fd].flow_id >= 0);

        q = shm_rbuff_queued(ai.flows[fd].tx_rb);

        pthread_rwlock_unlock(&ai.lock);

        return q;
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
