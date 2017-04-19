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

#ifndef OUROBOROS_IPCPD_NORMAL_SDU_SCHED_H
#define OUROBOROS_IPCPD_NORMAL_SDU_SCHED_H

#include <ouroboros/ipcp-dev.h>
#include <ouroboros/fqueue.h>

typedef int (* next_sdu_t)(int                  fd,
                           qoscube_t            qc,
                           struct shm_du_buff * sdb);

struct sdu_sched * sdu_sched_create(flow_set_t * set[QOS_CUBE_MAX],
                                    next_sdu_t   callback);

void               sdu_sched_destroy(struct sdu_sched * sdu_sched);

#endif /* OUROBOROS_IPCPD_NORMAL_SDU_SCHED_H */
