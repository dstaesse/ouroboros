/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Handles the different AP connections
 *
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
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

#ifndef OUROBOROS_IPCPD_NORMAL_CONNMGR_H
#define OUROBOROS_IPCPD_NORMAL_CONNMGR_H

#include <ouroboros/cacep.h>
#include <ouroboros/qos.h>

struct conn {
        struct conn_info conn_info;
        struct flow_info {
                int              fd;
                qosspec_t        qs;
        } flow_info;
};

int         connmgr_init(void);

void        connmgr_fini(void);

int         connmgr_start(void);

void        connmgr_stop(void);

struct ae * connmgr_ae_create(struct conn_info info);

void        connmgr_ae_destroy(struct ae * ae);

int         connmgr_alloc(struct ae *   ae,
                          char *        dst_name,
                          qosspec_t     qs,
                          struct conn * conn);

int         connmgr_wait(struct ae *   ae,
                         struct conn * conn);

#endif /* OUROBOROS_IPCPD_NORMAL_CONNMGR_H */
