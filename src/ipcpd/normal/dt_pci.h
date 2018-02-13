/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Protocol Control Information of Data Transfer Component
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

#ifndef OUROBOROS_IPCPD_NORMAL_DT_PCI_H
#define OUROBOROS_IPCPD_NORMAL_DT_PCI_H

#include <ouroboros/shm_du_buff.h>
#include <ouroboros/proto.h>
#include <ouroboros/qoscube.h>

#include <stdint.h>
#include <stdbool.h>

/* Abstract syntax */
enum dtp_fields {
        DTP_DST = 0,   /* DST ADDRESS      */
        DTP_QOS,       /* QOS ID           */
        DTP_DEID,      /* DST Endpoint ID  */
        DTP_TTL,       /* TTL FIELD        */
        DTP_NUM_FIELDS /* Number of fields */
};

/* Fixed field lengths */
#define TTL_LEN 1
#define QOS_LEN 1

struct dt_pci {
        uint64_t  dst_addr;
        qoscube_t qc;
        uint8_t   ttl;
        uint32_t  eid;
};

int   dt_pci_init(uint8_t addr_size,
                  uint8_t eid_size,
                  uint8_t max_ttl);

void  dt_pci_fini(void);

int   dt_pci_ser(struct shm_du_buff * sdb,
                 struct dt_pci *      dt_pci);

void  dt_pci_des(struct shm_du_buff * sdb,
                 struct dt_pci *      dt_pci);

void  dt_pci_shrink(struct shm_du_buff * sdb);

#endif /* OUROBOROS_IPCPD_NORMAL_DT_PCI_H */
