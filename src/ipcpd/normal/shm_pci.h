/*
 * Ouroboros - Copyright (C) 2016
 *
 * Protocol Control Information in Shared Memory Map
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#ifndef OUROBOROS_IPCP_SHM_PCI_H
#define OUROBOROS_IPCP_SHM_PCI_H

#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/utils.h>

#include "dt_const.h"

#define PDU_TYPE_MGMT 0x40
#define PDU_TYPE_DTP  0x80

typedef uint32_t cep_id_t;
#define INVALID_CEP_ID 0
#define INVALID_ADDR 0

struct pci {
        uint8_t  pdu_type;
        uint64_t dst_addr;
        uint64_t src_addr;
        cep_id_t dst_cep_id;
        cep_id_t src_cep_id;
        uint8_t  qos_id;
        uint32_t pdu_length;
        uint64_t seqno;
        uint8_t  ttl;
        uint8_t  flags;
};

int          shm_pci_ser(struct shm_du_buff * sdb,
                         struct pci *         pci);

buffer_t *   shm_pci_ser_buf(buffer_t *   buf,
                             struct pci * pci);

struct pci * shm_pci_des(struct shm_du_buff * sdb);

int          shm_pci_shrink(struct shm_du_buff * sdb);

int          shm_pci_dec_ttl(struct shm_du_buff * sdb);

#endif /* OUROBOROS_IPCP_SHM_PCI_H */
