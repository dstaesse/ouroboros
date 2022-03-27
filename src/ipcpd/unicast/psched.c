/*
 * Ouroboros - Copyright (C) 2016 - 2021
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

#include "common/connmgr.h"
#include "ipcp.h"
#include "psched.h"

#include <assert.h>
#include <sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static int qos_prio [] = {
        QOS_PRIO_BE,
        QOS_PRIO_VIDEO,
        QOS_PRIO_VOICE,
};

struct psched {
        fset_t *         set[QOS_CUBE_MAX];
        next_packet_fn_t callback;
        read_fn_t        read;
        pthread_t        readers[QOS_CUBE_MAX * IPCP_SCHED_THR_MUL];
};

struct sched_info {
        struct psched * sch;
        qoscube_t       qc;
};

static void cleanup_reader(void * o)
{
        fqueue_destroy((fqueue_t *) o);
}

static void * packet_reader(void * o)
{
        struct psched *       sched;
        struct shm_du_buff *  sdb;
        int                   fd;
        fqueue_t *            fq;
        qoscube_t             qc;

        sched = ((struct sched_info *) o)->sch;
        qc    = ((struct sched_info *) o)->qc;

        ipcp_lock_to_core();

        free(o);

        fq = fqueue_create();
        if (fq == NULL)
                return (void *) -1;

        pthread_cleanup_push(cleanup_reader, fq);

        while (true) {
                int ret = fevent(sched->set[qc], fq, NULL);
                if (ret < 0)
                        continue;

                while ((fd = fqueue_next(fq)) >= 0) {
                        switch (fqueue_type(fq)) {
                        case FLOW_DEALLOC:
                                notifier_event(NOTIFY_DT_FLOW_DEALLOC, &fd);
                                break;
                        case FLOW_DOWN:
                                notifier_event(NOTIFY_DT_FLOW_DOWN, &fd);
                                break;
                        case FLOW_UP:
                                notifier_event(NOTIFY_DT_FLOW_UP, &fd);
                                break;
                        case FLOW_PKT:
                                if (sched->read(fd, &sdb) < 0)
                                        continue;

                                sched->callback(fd, qc, sdb);
                                break;
                        default:
                                break;
                        }
                }
        }

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

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
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

        return psched;

 fail_sched:
        for (j = 0; j < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++j)
                pthread_cancel(psched->readers[j]);
        for (j = 0; j < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++j)
                pthread_join(psched->readers[j], NULL);
 fail_infos:
        for (j = 0; j < QOS_CUBE_MAX; ++j)
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

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                fset_destroy(psched->set[i]);

        free(psched);
}

void psched_add(struct psched * psched,
                int             fd)
{
        qoscube_t qc;

        assert(psched);

        ipcp_flow_get_qoscube(fd, &qc);
        fset_add(psched->set[qc], fd);
}

void psched_del(struct psched * psched,
                int             fd)
{
        qoscube_t qc;

        assert(psched);

        ipcp_flow_get_qoscube(fd, &qc);
        fset_del(psched->set[qc], fd);
}
