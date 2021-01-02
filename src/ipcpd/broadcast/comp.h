/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Components for the broadcast IPC process
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

#ifndef OUROBOROS_IPCPD_BROADCAST_COMP_H
#define OUROBOROS_IPCPD_BROADCAST_COMP_H

#include <ouroboros/cacep.h>

#define DST_MAX_STRLEN 64

enum comp_id {
        COMPID_DT = 0,
        COMPID_ENROLL,
        COMPID_MAX
};

struct conn {
        struct conn_info conn_info;
        struct {
                char      dst[DST_MAX_STRLEN + 1];
                int       fd;
                qosspec_t qs;
        } flow_info;
};

#endif /* OUROBOROS_IPCPD_BROADCAST_COMP_H */
