/*
 * Ouroboros - Copyright (C) 2016 - 2018
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

#ifndef OUROBOROS_IPCPD_NORMAL_SDU_SCHED_H
#define OUROBOROS_IPCPD_NORMAL_SDU_SCHED_H

#include <ouroboros/ipcp-dev.h>
#include <ouroboros/fqueue.h>

typedef void (* next_sdu_fn_t)(int                  fd,
                               qoscube_t            qc,
                               struct shm_du_buff * sdb);

struct sdu_sched * sdu_sched_create(next_sdu_fn_t callback);

void               sdu_sched_destroy(struct sdu_sched * sdu_sched);

void               sdu_sched_add(struct sdu_sched * sdu_sched,
                                 int                fd);

void               sdu_sched_del(struct sdu_sched * sdu_sched,
                                 int                fd);

#endif /* OUROBOROS_IPCPD_NORMAL_SDU_SCHED_H */
