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

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/rib.h>

#include "dt_const.h"
#include "frct_pci.h"
#include "ribconfig.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct {
        struct dt_const dtc;
        size_t          head_size;

        /* offsets */
        size_t          seqno_o;
} frct_pci_info;

int frct_pci_init(void)
{
        /* read dt constants from the RIB */
        if (rib_read(BOOT_PATH "/dt/const/cep_id_size",
                     &frct_pci_info.dtc.cep_id_size,
                     sizeof(frct_pci_info.dtc.cep_id_size)) < 0 ||
            rib_read(BOOT_PATH "/dt/const/seqno_size",
                     &frct_pci_info.dtc.seqno_size,
                     sizeof(frct_pci_info.dtc.seqno_size)) < 0)
                return -1;

        frct_pci_info.seqno_o = frct_pci_info.dtc.cep_id_size;

        frct_pci_info.head_size = frct_pci_info.seqno_o +
                frct_pci_info.dtc.seqno_size;

        return 0;
}

void frct_pci_fini(void) {
        return;
}

int frct_pci_ser(struct shm_du_buff * sdb,
                 struct frct_pci *    frct_pci)
{
        uint8_t * head;

        assert(sdb);
        assert(frct_pci);

        head = shm_du_buff_head_alloc(sdb, frct_pci_info.head_size);
        if (head == NULL)
                return -EPERM;

        /* FIXME: Add check and operations for Big Endian machines */
        memcpy(head, &frct_pci->dst_cep_id, frct_pci_info.dtc.cep_id_size);
        memcpy(head + frct_pci_info.seqno_o, &frct_pci->seqno,
               frct_pci_info.dtc.seqno_size);

        return 0;
}

void frct_pci_des(struct shm_du_buff * sdb,
                  struct frct_pci *    frct_pci)
{
        uint8_t * head;

        assert(sdb);
        assert(frct_pci);

        head = shm_du_buff_head(sdb);

        /* FIXME: Add check and operations for Big Endian machines */
        memcpy(&frct_pci->dst_cep_id, head, frct_pci_info.dtc.cep_id_size);
        memcpy(&frct_pci->seqno, head + frct_pci_info.seqno_o,
               frct_pci_info.dtc.seqno_size);

        shm_du_buff_head_release(sdb, frct_pci_info.head_size);
}
