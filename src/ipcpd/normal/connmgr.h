/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Handles the different AP connections
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_IPCPD_NORMAL_CONNMGR_H
#define OUROBOROS_IPCPD_NORMAL_CONNMGR_H

#include <ouroboros/cacep.h>
#include <ouroboros/qos.h>

#include "ae.h"
#include "neighbors.h"

int         connmgr_init(void);

void        connmgr_fini(void);

int         connmgr_start(void);

void        connmgr_stop(void);

int         connmgr_ae_init(enum ae_id               id,
                            const struct conn_info * info,
                            struct nbs *             nbs);

void        connmgr_ae_fini(enum ae_id id);

int         connmgr_ipcp_connect(const char * dst,
                                 const char * component);

int         connmgr_ipcp_disconnect(const char * dst,
                                    const char * component);

int         connmgr_alloc(enum ae_id    id,
                          const char *  dst,
                          qosspec_t *   qs,
                          struct conn * conn);

int         connmgr_dealloc(enum ae_id    id,
                            struct conn * conn);

int         connmgr_wait(enum ae_id    id,
                         struct conn * conn);

#endif /* OUROBOROS_IPCPD_NORMAL_CONNMGR_H */
