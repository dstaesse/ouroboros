/*
 * Ouroboros - Copyright (C) 2016
 *
 * Data Transfer Constants for the IPCP
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

#ifndef OUROBOROS_IPCPD_NORMAL_DT_CONST_H
#define OUROBOROS_IPCPD_NORMAL_DT_CONST_H

#include <stdint.h>
#include <stdbool.h>

struct dt_const {
        uint8_t  addr_size;
        uint8_t  cep_id_size;
        uint8_t  pdu_length_size;
        uint8_t  seqno_size;
        bool     has_ttl;
        bool     has_chk;
        uint32_t min_pdu_size;
        uint32_t max_pdu_size;
};

#endif /* OUROBOROS_IPCPD_NORMAL_DT_CONST_H */
