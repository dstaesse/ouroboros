/*
 * Ouroboros - Copyright (C) 2016 - 2022
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

#ifndef OUROBOROS_IPCPD_UNICAST_PSCHED_H
#define OUROBOROS_IPCPD_UNICAST_PSCHED_H

#include <ouroboros/ipcp-dev.h>
#include <ouroboros/fqueue.h>

typedef void (* next_packet_fn_t)(int                  fd,
                                  qoscube_t            qc,
                                  struct shm_du_buff * sdb);

typedef int (* read_fn_t)(int                   fd,
                          struct shm_du_buff ** sdb);

struct psched * psched_create(next_packet_fn_t callback,
                              read_fn_t        read);

void            psched_destroy(struct psched * psched);

void            psched_add(struct psched * psched,
                           int             fd);

void            psched_del(struct psched * psched,
                           int             fd);

#endif /* OUROBOROS_IPCPD_UNICAST_PSCHED_H */
