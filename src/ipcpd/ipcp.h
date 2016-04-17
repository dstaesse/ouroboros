/*
 * Ouroboros - Copyright (C) 2016
 *
 * IPC process structure
 *
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

#ifndef IPCPD_IPCP_H
#define IPCPD_IPCP_H

#include "ipcp-ops.h"
#include "ipcp-data.h"

enum ipcp_state {
        IPCP_INIT = 0,
        IPCP_ENROLLING,
        IPCP_BOOTSTRAPPING,
        IPCP_ENROLLED,
        IPCP_DISCONNECTED,
        IPCP_SHUTDOWN
};

struct ipcp {
        struct ipcp_data * data;
        struct ipcp_ops *  ops;

        enum ipcp_state    state;
        int                irmd_fd;
};

int ipcp_main_loop();

#endif
