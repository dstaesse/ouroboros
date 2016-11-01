/*
 * Ouroboros - Copyright (C) 2016
 *
 * The Common Distributed Application Protocol
 *
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#ifndef OUROBOROS_CDAP_H
#define OUROBOROS_CDAP_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define F_SYNC 0x0001

enum cdap_opcode {
        CDAP_READ = 0,
        CDAP_WRITE,
        CDAP_START,
        CDAP_STOP,
        CDAP_CREATE,
        CDAP_DELETE
};

struct cdap;

/* Callback functions that work on the application's RIB */
struct cdap_ops {
        int (* cdap_request)(struct cdap *    instance,
                             int              invoke_id,
                             enum cdap_opcode opcode,
                             char *           name,
                             uint8_t *        data,
                             size_t           len,
                             uint32_t         flags);

        int (* cdap_reply)(struct cdap * instance,
                           int           invoke_id,
                           int           result,
                           uint8_t *     data,
                           size_t        len);
};

/* Assumes flow is blocking */
struct cdap * cdap_create(struct cdap_ops * ops,
                          int               fd);
int           cdap_destroy(struct cdap * instance);

/* Returns a positive invoke-id on success to be used in the callback */
int           cdap_send_request(struct cdap *    instance,
                                enum cdap_opcode code,
                                char *           name,
                                uint8_t *        data,
                                size_t           len,
                                uint32_t         flags);

/* Can only be called following a callback function */
int           cdap_send_reply(struct cdap * instance,
                              int           invoke_id,
                              int           result,
                              uint8_t *     data,
                              size_t        len);
#endif
