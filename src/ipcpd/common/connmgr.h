/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Handles the different AP connections
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#ifndef OUROBOROS_IPCPD_COMMON_CONNMGR_H
#define OUROBOROS_IPCPD_COMMON_CONNMGR_H

#include <ouroboros/cacep.h>
#include <ouroboros/qos.h>

#include "comp.h"

#define NOTIFY_DT_CONN_ADD     0x00D0
#define NOTIFY_DT_CONN_DEL     0x00D1
#define NOTIFY_DT_CONN_QOS     0x00D2
#define NOTIFY_DT_CONN_UP      0x00D3
#define NOTIFY_DT_CONN_DOWN    0x00D4
#define NOTIFY_DT_FLOW_UP      0x00D5
#define NOTIFY_DT_FLOW_DOWN    0x00D6
#define NOTIFY_DT_FLOW_DEALLOC 0x00D7

#define NOTIFY_MGMT_CONN_ADD   0x00F0
#define NOTIFY_MGMT_CONN_DEL   0x00F1

int         connmgr_init(void);

void        connmgr_fini(void);

int         connmgr_start(void);

void        connmgr_stop(void);

int         connmgr_comp_init(enum comp_id             id,
                              const struct conn_info * info);

void        connmgr_comp_fini(enum comp_id id);

int         connmgr_ipcp_connect(const char * dst,
                                 const char * component,
                                 qosspec_t    qs);

int         connmgr_ipcp_disconnect(const char * dst,
                                    const char * component);

int         connmgr_alloc(enum comp_id  id,
                          const char *  dst,
                          qosspec_t *   qs,
                          struct conn * conn);

int         connmgr_dealloc(enum comp_id  id,
                            struct conn * conn);

int         connmgr_wait(enum comp_id  id,
                         struct conn * conn);

#endif /* OUROBOROS_IPCPD_COMMON_CONNMGR_H */
