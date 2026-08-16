/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Packet scheduler component
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200112L
#endif

#include "config.h"

#include <ouroboros/errno.h>
#include <ouroboros/notifier.h>
#include <ouroboros/time.h>

#include "common/connmgr.h"
#include "ipcp.h"
#include "psched.h"

#include <assert.h>
#include <sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#ifndef BUILD_CONTAINER
static int qos_prio [] = {
        QOS_PRIO_BE,
        QOS_PRIO_VIDEO,
        QOS_PRIO_VOICE,
};
#endif

struct psched {
        fset_t *         set[QOS_CUBE_MAX * IPCP_SCHED_THR_MUL];
        next_packet_fn_t callback;
        read_fn_t        read;
        pthread_t        readers[QOS_CUBE_MAX * IPCP_SCHED_THR_MUL];
};

struct sched_info {
        struct psched * sch;
        qoscube_t       qc;
        size_t          idx;
};

/* Map an FD to one reader's set: one FD, one thread (no shared FDs). */
static size_t fd_set_idx(int fd, qoscube_t qc)
{
        return qc + ((size_t) fd % IPCP_SCHED_THR_MUL) * QOS_CUBE_MAX;
}

static void cleanup_reader(void * o)
{
        fqueue_destroy((fqueue_t *) o);
}

/*
 * Per-reader deadline scheduler: a paced flow is served, then deferred
 * to its next-send deadline instead of blocking the thread, so it never
 * stalls its thread-mates.
 */
struct dsched {
        uint64_t deadline[PROC_MAX_FLOWS]; /* absolute ns, per tracked fd   */
        int      active[PROC_MAX_FLOWS];   /* compact list of tracked fds   */
        int      posn[PROC_MAX_FLOWS];     /* fd -> active index, -1 = none  */
        size_t   n;
};

static void cleanup_dsched(void * o)
{
        free(o);
}

static void dsched_track(struct dsched * d,
                         int             fd,
                         uint64_t        deadline)
{
        if (d->posn[fd] >= 0)
                return;

        d->deadline[fd]   = deadline;
        d->posn[fd]       = (int) d->n;
        d->active[d->n++] = fd;
}

static void dsched_untrack(struct dsched * d,
                           int             fd)
{
        int i = d->posn[fd];

        if (i < 0)
                return;

        d->active[i]          = d->active[--d->n];
        d->posn[d->active[i]] = i;
        d->posn[fd]           = -1;
}

/* Fold a deadline into the earliest pending one (0 = none yet). */
static uint64_t dmin_fold(uint64_t dmin,
                          uint64_t deadline)
{
        if (dmin == 0 || deadline < dmin)
                return deadline;

        return dmin;
}

static uint64_t dsched_serve(struct dsched * d,
                             struct psched * sched,
                             qoscube_t       qc,
                             uint64_t        now)
{
        struct ssm_pk_buff * spb;
        uint64_t             dmin = 0;
        size_t               i;
        int                  fd;
        int                  ret;
        time_t               wait;
        bool                 served;

        /* Round-robin one packet per flow so none monopolises egress. */
        do {
                served = false;

                for (i = 0; i < d->n; ) {
                        fd = d->active[i];

                        if (d->deadline[fd] > now) {
                                dmin = dmin_fold(dmin, d->deadline[fd]);
                                ++i;
                                continue;
                        }

                        ret = sched->read(fd, &spb);
                        if (ret == -EAGAIN) { /* empty now, keep it */
                                ++i;
                                continue;
                        }

                        if (ret < 0) {
                                dsched_untrack(d, fd);
                                continue;
                        }

                        wait   = sched->callback(fd, qc, spb);
                        served = true;

                        if (wait > 0) {
                                d->deadline[fd] = now + (uint64_t) wait;
                                dmin = dmin_fold(dmin, d->deadline[fd]);
                        }

                        ++i;
                }
        } while (served);

        return dmin;
}

static void dsched_events(struct dsched * d,
                          fqueue_t *      fq,
                          uint64_t        now)
{
        int fd;

        while ((fd = fqueue_next(fq)) >= 0) {
                switch (fqueue_type(fq)) {
                case FLOW_DEALLOC:
                        dsched_untrack(d, fd);
                        notifier_event(NOTIFY_DT_FLOW_DEALLOC, &fd);
                        break;
                case FLOW_DOWN:
                        notifier_event(NOTIFY_DT_FLOW_DOWN, &fd);
                        break;
                case FLOW_UP:
                        notifier_event(NOTIFY_DT_FLOW_UP, &fd);
                        break;
                case FLOW_PKT:
                        dsched_track(d, fd, now);
                        break;
                default:
                        break;
                }
        }
}

static void * packet_reader(void * o)
{
        struct psched * sched;
        struct dsched * d;
        fqueue_t *      fq;
        qoscube_t       qc;
        size_t          idx;

        sched = ((struct sched_info *) o)->sch;
        qc    = ((struct sched_info *) o)->qc;
        idx   = ((struct sched_info *) o)->idx;

        ipcp_lock_to_core();

        free(o);

        fq = fqueue_create();
        if (fq == NULL)
                return (void *) -1;

        d = malloc(sizeof(*d));
        if (d == NULL) {
                fqueue_destroy(fq);
                return (void *) -1;
        }

        memset(d, 0, sizeof(*d));
        memset(d->posn, 0xFF, sizeof(d->posn)); /* -1: nothing tracked yet */

        pthread_cleanup_push(cleanup_dsched, d);
        pthread_cleanup_push(cleanup_reader, fq);

        while (true) {
                struct timespec   now_ts;
                struct timespec   to;
                struct timespec * timeo;
                uint64_t          now;
                uint64_t          dmin;
                uint64_t          delta;
                int               ret;

                clock_gettime(PTHREAD_COND_CLOCK, &now_ts);

                now = TS_TO_UINT64(now_ts);

                dmin = dsched_serve(d, sched, qc, now);

                if (dmin == 0) {
                        timeo = NULL;
                } else {
                        delta = dmin > now ? dmin - now : 1;
                        to.tv_sec  = (time_t) (delta / BILLION);
                        to.tv_nsec = (long) (delta % BILLION);
                        timeo = &to;
                }

                ret = fevent(sched->set[idx], fq, timeo);
                if (ret < 0)
                        continue;

                dsched_events(d, fq, now);
        }

        pthread_cleanup_pop(true);
        pthread_cleanup_pop(true);

        return (void *) 0;
}

struct psched * psched_create(next_packet_fn_t callback,
                              read_fn_t        read)
{
        struct psched *       psched;
        struct sched_info *   infos[QOS_CUBE_MAX * IPCP_SCHED_THR_MUL];
        int                   i;
        int                   j;

        assert(callback);

        psched = malloc(sizeof(*psched));
        if (psched == NULL)
                goto fail_malloc;

        psched->callback = callback;
        psched->read     = read;

        for (i = 0; i < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++i) {
                psched->set[i] = fset_create();
                if (psched->set[i] == NULL) {
                        for (j = 0; j < i; ++j)
                                fset_destroy(psched->set[j]);
                        goto fail_flow_set;
                }
        }

        for (i = 0; i < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++i) {
                infos[i] = malloc(sizeof(*infos[i]));
                if (infos[i] == NULL) {
                        for (j = 0; j < i; ++j)
                                free(infos[j]);
                        goto fail_infos;
                }
                infos[i]->sch = psched;
                infos[i]->qc  = i % QOS_CUBE_MAX;
                infos[i]->idx = i;
        }

        for (i = 0; i < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++i) {
                if (pthread_create(&psched->readers[i], NULL,
                                   packet_reader, infos[i])) {
                        for (j = 0; j < i; ++j)
                                pthread_cancel(psched->readers[j]);
                        for (j = 0; j < i; ++j)
                                pthread_join(psched->readers[j], NULL);
                        for (j = i; j < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++j)
                                free(infos[j]);
                        goto fail_infos;
                }
        }

#ifndef BUILD_CONTAINER
        for (i = 0; i < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++i) {
                struct sched_param  par;
                int                 pol = SCHED_RR;
                int                 min;
                int                 max;

                min = sched_get_priority_min(pol);
                max = sched_get_priority_max(pol);

                min = (max - min) / 2;

                par.sched_priority = min +
                        (qos_prio[i % QOS_CUBE_MAX] * (max - min) / 99);

                if (pthread_setschedparam(psched->readers[i], pol, &par))
                        goto fail_sched;
        }
#endif

        return psched;

#ifndef BUILD_CONTAINER
 fail_sched:
        for (j = 0; j < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++j)
                pthread_cancel(psched->readers[j]);

        for (j = 0; j < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++j)
                pthread_join(psched->readers[j], NULL);
#endif
 fail_infos:
        for (j = 0; j < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++j)
                fset_destroy(psched->set[j]);
 fail_flow_set:
        free(psched);
 fail_malloc:
        return NULL;
}

void psched_destroy(struct psched * psched)
{
        int i;

        assert(psched);

        for (i = 0; i < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++i) {
                pthread_cancel(psched->readers[i]);
                pthread_join(psched->readers[i], NULL);
        }

        for (i = 0; i < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++i)
                fset_destroy(psched->set[i]);

        free(psched);
}

void psched_add(struct psched * psched,
                int             fd)
{
        qoscube_t qc;

        assert(psched);

        ipcp_flow_get_qoscube(fd, &qc);
        fset_add(psched->set[fd_set_idx(fd, qc)], fd);
}

void psched_del(struct psched * psched,
                int             fd)
{
        qoscube_t qc;

        assert(psched);

        ipcp_flow_get_qoscube(fd, &qc);
        fset_del(psched->set[fd_set_idx(fd, qc)], fd);
}
