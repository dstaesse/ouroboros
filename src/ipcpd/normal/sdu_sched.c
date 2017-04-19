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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "sdu-scheduler"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/errno.h>

#include "sdu_sched.h"

#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>

#define FD_UPDATE_TIMEOUT 10000 /* nanoseconds */

struct sdu_sched {
        flow_set_t * set[QOS_CUBE_MAX];
        fqueue_t *   fqs[QOS_CUBE_MAX];
        next_sdu_t   callback;
        pthread_t    sdu_reader;
};

static void * sdu_reader(void * o)
{
        struct sdu_sched *   sched;
        struct shm_du_buff * sdb;
        struct timespec      timeout = {0, FD_UPDATE_TIMEOUT};
        int                  fd;
        int                  i = 0;
        int                  ret;

        sched = (struct sdu_sched *) o;

        while (true) {
                /* FIXME: replace with scheduling policy call */
                i = (i + 1) % QOS_CUBE_MAX;

                ret = flow_event_wait(sched->set[i], sched->fqs[i], &timeout);
                if (ret == -ETIMEDOUT)
                        continue;

                if (ret < 0) {
                        log_warn("Event error: %d.", ret);
                        continue;
                }

                while ((fd = fqueue_next(sched->fqs[i])) >= 0) {
                        if (ipcp_flow_read(fd, &sdb)) {
                                log_warn("Failed to read SDU from fd %d.", fd);
                                continue;
                        }

                        if (sched->callback(fd, i, sdb)) {
                                log_warn("Callback reported an error.");
                                continue;
                        }
                }
        }

        return (void *) 0;
}

struct sdu_sched * sdu_sched_create(flow_set_t * set[QOS_CUBE_MAX],
                                    next_sdu_t   callback)
{
        struct sdu_sched * sdu_sched;
        int                i;
        int                j;

        sdu_sched = malloc(sizeof(*sdu_sched));
        if (sdu_sched == NULL)
                return NULL;

        sdu_sched->callback = callback;

        for (i = 0; i < QOS_CUBE_MAX; ++i) {
                sdu_sched->set[i] = set[i];

                sdu_sched->fqs[i] = fqueue_create();
                if (sdu_sched->fqs[i] == NULL) {
                        for (j = i; j >= 0; --j)
                                fqueue_destroy(sdu_sched->fqs[j]);
                        free(sdu_sched);
                        return NULL;
                }
        }

        pthread_create(&sdu_sched->sdu_reader,
                       NULL,
                       sdu_reader,
                       (void *) sdu_sched);

        return sdu_sched;
}

void sdu_sched_destroy(struct sdu_sched * sdu_sched)
{
        int i;

        assert(sdu_sched);

        pthread_cancel(sdu_sched->sdu_reader);

        pthread_join(sdu_sched->sdu_reader, NULL);

        for (i = 0; i < QOS_CUBE_MAX; ++i)
                fqueue_destroy(sdu_sched->fqs[i]);

        free(sdu_sched);
}
