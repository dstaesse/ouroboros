/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Data Transfer component
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

#ifndef OUROBOROS_IPCPD_NORMAL_DT_H
#define OUROBOROS_IPCPD_NORMAL_DT_H

#include <ouroboros/ipcp.h>
#include <ouroboros/shm_rdrbuff.h>

#include "dt_pci.h"

#define DT_COMP      "Data Transfer"
#define DT_PROTO     "dtp"
#define INVALID_ADDR 0

int  dt_init(enum pol_routing pr,
             enum pol_pff     pp,
             uint8_t          addr_size,
             uint8_t          eid_size,
             uint8_t          max_ttl
);

void dt_fini(void);

int  dt_start(void);

void dt_stop(void);

int  dt_reg_comp(void * comp,
                 void (* func)(void * comp, struct shm_du_buff * sdb),
                 char * name);

int  dt_write_sdu(uint64_t             dst_addr,
                  qoscube_t            qc,
                  int                  res_fd,
                  struct shm_du_buff * sdb);

#endif /* OUROBOROS_IPCPD_NORMAL_DT_H */
