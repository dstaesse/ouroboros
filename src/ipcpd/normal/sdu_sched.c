/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * SDU scheduler component
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#define _POSIX_C_SOURCE 199309L

#include "config.h"

#include <ouroboros/errno.h>

#include "sdu_sched.h"

#include <assert.h>
#include <sched.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

static int qos_prio [] = {
        QOS_PRIO_BE,
        QOS_PRIO_VIDEO,
        QOS_PRIO_VOICE
};

struct sdu_sched {
        fset_t *      set[QOS_CUBE_MAX];
        next_sdu_fn_t callback;
        pthread_t     readers[QOS_CUBE_MAX * IPCP_SCHED_THR_MUL];
};

struct sched_info {
        struct sdu_sched * sch;
        qoscube_t          qc;
};

static void cleanup_reader(void * o)
{
        fqueue_destroy((fqueue_t *) o);
}

static void * sdu_reader(void * o)
{
        struct sdu_sched *   sched;
        struct shm_du_buff * sdb;
        int                  fd;
        fqueue_t *           fq;
        qoscube_t            qc;

        sched = ((struct sched_info *) o)->sch;
        qc    = ((struct sched_info *) o)->qc;

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
                        if (ipcp_flow_read(fd, &sdb))
                                continue;

                        sched->callback(fd, qc, sdb);
                }
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

struct sdu_sched * sdu_sched_create(next_sdu_fn_t callback)
{
        struct sdu_sched *  sdu_sched;
        struct sched_info * infos[QOS_CUBE_MAX * IPCP_SCHED_THR_MUL];
        int                 i;
        int                 j;

        sdu_sched = malloc(sizeof(*sdu_sched));
        if (sdu_sched == NULL)
                goto fail_malloc;

        assert(callback);

        sdu_sched->callback = callback;

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                sdu_sched->set[i] = fset_create();
                if (sdu_sched->set[i] == NULL) {
                        for (j = 0; j < i; ++j)
                                fset_destroy(sdu_sched->set[j]);
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
                infos[i]->sch = sdu_sched;
                infos[i]->qc  = i % QOS_CUBE_MAX;
        }

        for (i = 0; i < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++i) {
                if (pthread_create(&sdu_sched->readers[i], NULL,
                                   sdu_reader, infos[i])) {
                        for (j = 0; j < i; ++j)
                                pthread_cancel(sdu_sched->readers[j]);
                        for (j = 0; j < i; ++j)
                                pthread_join(sdu_sched->readers[j], NULL);
                        goto fail_pthr;
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
                if (pthread_setschedparam(sdu_sched->readers[i], pol, &par))
                        goto fail_sched;
        }

        return sdu_sched;

 fail_sched:
        for (j = 0; j < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++j)
                pthread_cancel(sdu_sched->readers[j]);
        for (j = 0; j < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++j)
                pthread_join(sdu_sched->readers[j], NULL);
 fail_pthr:
        for (j = 0; j < QOS_CUBE_MAX * IPCP_SCHED_THR_MUL; ++j)
                free(infos[j]);
 fail_infos:
        for (j = 0; j < QOS_CUBE_MAX; ++j)
                fset_destroy(sdu_sched->set[j]);
 fail_flow_set:
        free(sdu_sched);
 fail_malloc:
        return NULL;
}

void sdu_sched_destroy(struct sdu_sched * sdu_sched)
{
        int i;

        assert(sdu_sched);

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                pthread_cancel(sdu_sched->readers[i]);
                pthread_join(sdu_sched->readers[i], NULL);
        }

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                fset_destroy(sdu_sched->set[i]);

        free(sdu_sched);
}

void sdu_sched_add(struct sdu_sched * sdu_sched,
                   int                fd)
{
        qoscube_t qc;

        assert(sdu_sched);

        ipcp_flow_get_qoscube(fd, &qc);
        fset_add(sdu_sched->set[qc], fd);
}

void sdu_sched_del(struct sdu_sched * sdu_sched,
                   int                fd)
{
        qoscube_t qc;

        assert(sdu_sched);

        ipcp_flow_get_qoscube(fd, &qc);
        fset_del(sdu_sched->set[qc], fd);
}
