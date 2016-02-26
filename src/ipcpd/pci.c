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

struct pci {
        uint8_t * src_addr;
        uint8_t * dst_addr;
        uint8_t * pdu_length;
        uint8_t * qos_id;
        uint8_t * seqnr;
        uint8_t * pad_h;
        uint8_t * pad_t;

        uint8_t   head_sz;
        uint8_t   tail_sz;

};

pci_t * pci_create(struct dtp_const * dtc)
{
        int i          = 0;

        if (dtc == NULL)
                return NULL;

        struct pci * p = malloc(sizeof pci);

        if (p == NULL)
                return NULL:

        p->src_addr =NULL;
        p->dst_addr = NULL;
        p->pdu_length = NULL;
        p->qos_id = NULL;
        p->seqnr = NULL;
        p->pad_h = NULL;
        p->pad_t = NULL;

        head_sz = 0;
        tail_sz = 0;

        return p;
}

/* policy... one could reorder the data fields
   exercise left to the idiot that cares */
int * pci_init(pci_t            * pci,
               d_buff_t         * dub,
               struct dtp_const * dtc,
               struct dup_const * dupc)
{
        uint8_t * pci_head;
        uint8_t * pci_tail;

        /* nastiness ahead, all members are uint8_t's */
        uint8_t * n = (uint8_t *) dtc;
        for (i=0; i < sizeof *dtc; ++i)
                n[i] & 0x80 ? tail_sz += n[i] & 0x80:
                        head_sz += n[i];
        head_sz += n[0] & 0x80 ? n[0] : 0; /* dst_addr */

        n = (uint8_t *) dupc;
        for (i=0; i < sizeof *dupc; ++i)
                n[i] & 0x80 ? tail_sz += n[i] & 0x80 :
                        head_sz += n[i];
        tail_sz += n[0] & 0x80 ? n[0] : 0; /* dst_addr */

        /* end of nastiness */

        pci_head = du_buff_head_alloc(dub, head_sz);
        pci_tail = du_buff_tail_alloc(dub, tail_sz);

        LOG_MISSING();
}

void pci_destroy(pci_t * pci)
{
        free (pci);
}
