/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Protocol Control Information for FRCT
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

#ifndef OUROBOROS_IPCPD_NORMAL_FRCT_PCI_H
#define OUROBOROS_IPCPD_NORMAL_FRCT_PCI_H

#include <ouroboros/shm_du_buff.h>

typedef uint32_t cep_id_t;

#define INVALID_CEP_ID 0

struct frct_pci {
        cep_id_t dst_cep_id;
        uint64_t seqno;
};

int  frct_pci_init(void);

void frct_pci_fini(void);

int  frct_pci_ser(struct shm_du_buff * sdb,
                  struct frct_pci *    frct_pci);

void frct_pci_des(struct shm_du_buff * sdb,
                  struct frct_pci *    frct_pci);

#endif /* OUROBOROS_IPCPD_NORMAL_FRCT_PCI_H */
