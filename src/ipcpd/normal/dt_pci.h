/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Protocol Control Information of Data Transfer AE
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

#ifndef OUROBOROS_IPCPD_NORMAL_DT_PCI_H
#define OUROBOROS_IPCPD_NORMAL_DT_PCI_H

#include <ouroboros/shm_du_buff.h>
#include <ouroboros/shared.h>

#define PDU_TYPE_FA   0x40
#define PDU_TYPE_FRCT 0x80

#define INVALID_ADDR 0

struct dt_pci {
        uint64_t  dst_addr;
        qoscube_t qc;
        uint8_t   ttl;
        uint8_t   pdu_type;
};

int   dt_pci_init(void);

void  dt_pci_fini(void);

int   dt_pci_ser(struct shm_du_buff * sdb,
                 struct dt_pci *      dt_pci);

void  dt_pci_des(struct shm_du_buff * sdb,
                 struct dt_pci *      dt_pci);

void  dt_pci_shrink(struct shm_du_buff * sdb);

#endif /* OUROBOROS_IPCPD_NORMAL_DT_PCI_H */
