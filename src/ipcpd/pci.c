/*
 * Ouroboros - Copyright (C) 2016
 *
 * Protocol Control Information
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

#include "pci.h"
#include <malloc.h>
#include <errno.h>

#define OUROBOROS_PREFIX "ipcp/pci"

#include <ouroboros/logs.h>

#define PCI_HEAD_SIZE(a, b) a.addr_size * 2 +  \
        a.cep_id_size * 2 +                    \
        a.pdu_length_size +                    \
        b.ttl_size +                           \
        a.seqno_size +                         \
        a.qos_id_size
#define PCI_TAIL_SIZE(b) b.chk_size


struct pci {
        /* head */
        uint8_t * dst_addr;
        uint8_t * src_addr;
        uint8_t * dst_cep_id;
        uint8_t * src_cep_id;
        uint8_t * pdu_length;
        uint8_t * ttl;
        uint8_t * seqno;
        uint8_t * qos_id;

        uint8_t * chk;

        du_buff_t * dub;

        struct ipcp_dtp_const dtpc;
        struct ipcp_dup_const dupc;

};

pci_t * pci_create(du_buff_t                   * dub,
                   const struct ipcp_dtp_const * dtpc,
                   const struct ipcp_dup_const * dupc)
{
        struct pci * p;

        if (dub == NULL) {
                LOG_DBGF("Bogus input. Bugging out.");
                return NULL;
        }

        p = malloc(sizeof *p);

        if (p == NULL)
                return NULL;

        p->dub = dub;

        p->dtpc = *dtpc;
        p->dupc = *dupc;

        p->dst_addr   = NULL;
        p->src_addr   = NULL;
        p->dst_cep_id = NULL;
        p->src_cep_id = NULL;
        p->pdu_length = NULL;
        p->ttl        = NULL;
        p->seqno      = NULL;
        p->qos_id     = NULL;
        p->chk        = NULL;

        return p;
}

void pci_destroy(pci_t * pci)
{
        free(pci);
}

int pci_init(pci_t                 * pci)
{
        if (pci == NULL) {
                LOG_DBGF("Bogus input. Bugging out.");
                return -EINVAL;
        }

        uint8_t * pci_head = du_buff_head_alloc(pci->dub, PCI_HEAD_SIZE(
                                                        pci->dtpc,pci->dupc));
        uint8_t * pci_tail = du_buff_tail_alloc(pci->dub, PCI_TAIL_SIZE(
                                                        pci->dupc));

        if (pci_head == NULL) {
                LOG_DBG("Failed to allocate space for PCI at head.");
                return -ENOBUFS;
        }

        if (pci_tail == NULL) {
                LOG_DBG("Failed to allocate space for PCI at tail.");
                return -ENOBUFS;
        }

        pci->dst_addr   = pci_head;
        pci->src_addr   = (pci_head += pci->dtpc.addr_size);
        pci->dst_cep_id = (pci_head += pci->dtpc.addr_size);
        pci->src_cep_id = (pci_head += pci->dtpc.cep_id_size);
        pci->pdu_length = (pci_head += pci->dtpc.cep_id_size);
        pci->ttl        = (pci_head += pci->dtpc.pdu_length_size);
        pci->seqno      = (pci_head += pci->dupc.ttl_size);
        pci->qos_id     = (pci_head += pci->dtpc.seqno_size);

        pci->chk        = (pci_tail);

        return 0;
}

void pci_release(pci_t * pci)
{
        if (pci == NULL)
                return;

        if (pci->dub == NULL)
                return;

        du_buff_head_release(pci->dub, PCI_HEAD_SIZE(pci->dtpc, pci->dupc));
        du_buff_tail_release(pci->dub, PCI_TAIL_SIZE(pci->dupc));
}
