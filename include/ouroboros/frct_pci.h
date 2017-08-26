/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Protocol Control Information of FRCT
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_LIB_FRCT_PCI_H
#define OUROBOROS_LIB_FRCT_PCI_H

#include <ouroboros/shm_du_buff.h>

#include <stdint.h>
#include <stdbool.h>

struct frct_pci {
        /* Present in every PDU. */
        uint8_t  type;
        uint8_t  flags;
        uint64_t seqno;

        /* Present in config PDU. */
        uint8_t  conf_flags;

        /* Present in flow control PDU. */
        uint64_t lwe;
        uint64_t rwe;
};

enum pdu_types {
        PDU_TYPE_DATA        = 0x01,
        PDU_TYPE_ACK         = 0x02,
        PDU_TYPE_FC          = 0x04,
        PDU_TYPE_ACK_AND_FC  = (PDU_TYPE_ACK | PDU_TYPE_FC),
        PDU_TYPE_CONFIG      = 0x08,
        PDU_TYPE_RENDEZ_VOUS = 0x10
};

enum config_flags {
        CONF_RESOURCE_CONTROL = 0x01,
        CONF_RELIABLE         = 0x02,
        CONF_ERROR_CHECK      = 0x04,
        CONF_ORDERED          = 0x08,
        CONF_PARTIAL          = 0x10
};

enum data_flags {
        FLAG_DATA_RUN       = 0x01,
        FLAG_MORE_FRAGMENTS = 0x02
};

int frct_pci_ser(struct shm_du_buff * sdb,
                 struct frct_pci *    pci,
                 bool                 error_check);

int frct_pci_des(struct shm_du_buff * sdb,
                 struct frct_pci *    pci,
                 bool                 error_check);

#endif /* OUROBOROS_LIB_FRCT_PCI_H */
