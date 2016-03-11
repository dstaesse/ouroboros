/*
 * Ouroboros - Copyright (C) 2016
 *
 * The sockets layer to communicate between daemons
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

#ifndef OUROBOROS_SOCKETS_H
#define OUROBOROS_SOCKETS_H

#include "common.h"
#include "rina_name.h"

#define IRM_SOCK_PATH "/tmp/irm_sock"
#define IRM_MSG_BUF_SIZE 256

enum irm_msg_code {
        IRM_CREATE_IPCP,
        IRM_DESTROY_IPCP,
        IRM_BOOTSTRAP_IPCP,
        IRM_ENROLL_IPCP,
        IRM_REG_IPCP,
        IRM_UNREG_IPCP
};

struct irm_msg {
        enum irm_msg_code code;
        rina_name_t * name;
        char * ipcp_type;
        struct dif_config * conf;
        char * dif_name;
        char ** difs;
        size_t difs_size;
};

int              client_socket_open(char * file_name);
int              server_socket_open(char * file_name);

buffer_t *       serialize_irm_msg(struct irm_msg * msg);
struct irm_msg * deserialize_irm_msg(buffer_t * data);

#endif
