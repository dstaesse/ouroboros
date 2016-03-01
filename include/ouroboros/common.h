/*
 * Ouroboros - Copyright (C) 2016
 *
 * Common definitions
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

#ifndef OUROBOROS_COMMON_H
#define OUROBOROS_COMMON_H

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>

typedef uint32_t port_id_t;

typedef struct {
        uint8_t * data;
        size_t    size;
} buffer_t;

typedef struct {
        char * ap_name;
        int    api_id;
        char * ae_name;
        int    aei_id;
} rina_name_t;

/* FIXME: may need revision */
struct qos_spec {
        char * qos_name;
        char * dif_name;

        uint32_t delay;
        uint32_t jitter;
};

/* FIXME: What should be configurable in the DIF? */
struct dif_config {
        /* general data */
        qos_spec * qosspecs;

        /* TODO: efficient policies */

        /* dt field sizes in octets */
        uint8_t addr_size;
        uint8_t cep_id_size;
        uint8_t pdu_length_size;
        uint8_t qos_id_size;
        uint8_t seqno_size;

        /* constants for dup */
        uint8_t ttl_size;
        uint8_t chk_size;

        /* values, octets */
        uint32_t min_pdu_size;
        uint32_t max_pdu_size;

};

#endif /* OUROBOROS_COMMON_H */
