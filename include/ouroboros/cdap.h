/*
 * Ouroboros - Copyright (C) 2016
 *
 * The Common Distributed Application Protocol
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#include <ouroboros/common.h>

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define F_SYNC 0x0001

struct cdap;

/* Callback functions that work on the application's RIB */
struct cdap_ops {
        int (* cdap_reply)(struct cdap * instance,
                           int           invoke_id,
                           int           result,
                           buffer_t *    val,
                           size_t        len);

        int (* cdap_read)(struct cdap * instance,
                          char *        name);
        int (* cdap_write)(struct cdap * instance,
                           char *        name,
                           buffer_t *    val,
                           size_t        len,
                           uint32_t      flags);

        int (* cdap_create)(struct cdap * instance,
                            char *        name,
                            buffer_t      val);
        int (* cdap_delete)(struct cdap * instance,
                            char *        name,
                            buffer_t      val);

        int (* cdap_start)(struct cdap * instance,
                           char *        name);
        int (* cdap_stop)(struct cdap * instance,
                          char *        name);
};

/* Assumes flow is blocking */
struct cdap * cdap_create(struct cdap_ops * ops,
                          int               fd);
int           cdap_destroy(struct cdap * instance);

/* Returns a positive invoke-id on success to be used in the callback */
int           cdap_send_read(struct cdap * instance,
                             char *        name);
int           cdap_send_write(struct cdap * instance,
                              char *        name,
                              buffer_t *    val,
                              size_t        len,
                              uint32_t      flags);

int           cdap_send_create(struct cdap * instance,
                               char *        name,
                               buffer_t      val);
int           cdap_send_delete(struct cdap * instance,
                               char *        name,
                               buffer_t      val);

int           cdap_send_start(struct cdap * instance,
                              char *        name);
int           cdap_send_stop(struct cdap * instance,
                             char *        name);

/* Can only be called following a callback function */
int           cdap_send_reply(struct cdap * instance,
                              int           invoke_id,
                              int           result,
                              buffer_t *    val,
                              size_t        len);
#endif
