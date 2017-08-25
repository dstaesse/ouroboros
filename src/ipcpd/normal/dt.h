/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Data Transfer AE
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

#define DT_AE        "Data Transfer"
#define DT_PROTO     "dtp"
#define INVALID_ADDR 0

int  dt_init(enum pol_routing pr,
             uint8_t          addr_size,
             uint8_t          fd_size,
             bool             has_ttl
);

void dt_fini(void);

int  dt_start(void);

void dt_stop(void);

int  dt_reg_ae(void * ae,
               void (* func)(void * ae, struct shm_du_buff * sdb));

int  dt_write_sdu(uint64_t             dst_addr,
                  qoscube_t            qc,
                  int                  res_fd,
                  struct shm_du_buff * sdb);

#endif /* OUROBOROS_IPCPD_NORMAL_DT_H */
