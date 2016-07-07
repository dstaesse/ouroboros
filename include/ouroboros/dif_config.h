/*
 * Ouroboros - Copyright (C) 2016
 *
 * DIF configurations for each IPCP type
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#include <stdint.h>
#include <unistd.h>

#ifndef OUROBOROS_DIF_CONFIG_H
#define OUROBOROS_DIF_CONFIG_H

enum ipcp_type {
        IPCP_LOCAL = 0,
        IPCP_NORMAL,
        IPCP_SHIM_UDP,
        IPCP_SHIM_ETH_LLC
};

struct dif_config {
        char * dif_name;
        enum ipcp_type type;

        union {
                /* Normal DIF */
                struct {
                        uint8_t addr_size;
                        uint8_t cep_id_size;
                        uint8_t pdu_length_size;
                        uint8_t qos_id_size;
                        uint8_t seqno_size;

                        /* DUP constants */
                        uint8_t ttl_size;
                        uint8_t chk_size;

                        uint32_t min_pdu_size;
                        uint32_t max_pdu_size;
                };
                /* Shim UDP */
                struct {
                        uint32_t ip_addr;
                        uint32_t dns_addr;
                };
                /* Shim Ethernet LLC */
                struct {
                        char * if_name;
                };
        };
};


#endif /* OUROBOROS_DIF_CONFIG_H */
