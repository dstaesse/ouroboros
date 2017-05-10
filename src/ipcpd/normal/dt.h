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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef OUROBOROS_IPCPD_NORMAL_DT_H
#define OUROBOROS_IPCPD_NORMAL_DT_H

#include <ouroboros/shm_rdrbuff.h>

#include "dt_pci.h"

#define INVALID_ADDR 0

#define DT_PROTO "dt"
#define FD_FA    1
#define FD_DHT   2

typedef uint32_t dt_cep_id_t;

int  dt_init(void);

void dt_fini(void);

int  dt_start(void);

void dt_stop(void);

int  dt_write_sdu(uint64_t             dst_addr,
                  qoscube_t            qc,
                  int                  np1_fd,
                  struct shm_du_buff * sdb);

#endif /* OUROBOROS_IPCPD_NORMAL_DT_H */
