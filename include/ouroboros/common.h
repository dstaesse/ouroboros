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

typedef uint32_t port_id_t;

/* FIXME: To be moved into a separate file */
typedef struct {
        char * data;
        size_t size;
} buffer_t;

typedef struct {
        char * ap_name;
        int api_id;
        char * ae_name;
        int aei_id;
} rina_name_t;

/* FIXME: To be extended to have all QoS params */
struct qos_spec {
        char * name;
        char * dif_name;
        double delay;
        double jitter;
};

/* FIXME: What should be configurable in the DIF? */
struct dif_info {
        int cep_id_size;
};

#endif
