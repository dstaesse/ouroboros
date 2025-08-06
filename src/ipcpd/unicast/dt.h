/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Data Transfer component
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

#ifndef OUROBOROS_IPCPD_UNICAST_DT_H
#define OUROBOROS_IPCPD_UNICAST_DT_H

#include <ouroboros/ipcp.h>
#include <ouroboros/qoscube.h>
#include <ouroboros/shm_rdrbuff.h>

#define DT_COMP      "Data Transfer"
#define DT_PROTO     "dtp"
#define INVALID_ADDR 0

int  dt_init(struct dt_config cfg);

void dt_fini(void);

int  dt_start(void);

void dt_stop(void);

int  dt_reg_comp(void *  comp,
                 void (* func)(void * comp, struct shm_du_buff * sdb),
                 char *  name);

void dt_unreg_comp(int eid);

int  dt_write_packet(uint64_t             dst_addr,
                     qoscube_t            qc,
                     uint64_t             eid,
                     struct shm_du_buff * sdb);

#endif /* OUROBOROS_IPCPD_UNICAST_DT_H */
