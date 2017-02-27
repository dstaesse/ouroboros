/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Normal IPC Process - Authenticated CDAP Flow Allocator
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

#ifndef OUROBOROS_IPCPD_NORMAL_CDAP_FLOW_H
#define OUROBOROS_IPCPD_NORMAL_CDAP_FLOW_H

#include <ouroboros/cacep.h>
#include <ouroboros/cdap.h>
#include <ouroboros/qos.h>

struct cdap_flow {
        int              fd;
        struct cdap *    ci;
        struct conn_info info;
};

struct cdap_flow * cdap_flow_arr(int                      fd,
                                 int                      resp,
                                 const struct conn_info * info);

struct cdap_flow * cdap_flow_alloc(const char *             dst_name,
                                   qosspec_t *              qs,
                                   const struct conn_info * info);

void               cdap_flow_dealloc(struct cdap_flow * flow);

#endif /* OUROBOROS_IPCPD_NORMAL_CDAP_FLOW_H */
