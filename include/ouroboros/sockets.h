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

#include <ouroboros/common.h>
#include <ouroboros/rina_name.h>

#include <sys/types.h>

#define IRM_SOCK_PATH "/tmp/irm_sock"
#define IRM_MSG_BUF_SIZE 256

#define IPCP_SOCK_PATH_PREFIX "/tmp/ipcp_sock"
#define IPCP_MSG_BUFS_SIZE IRM_MSG_BUF_SIZE

enum irm_msg_code {
        IRM_CREATE_IPCP,
        IRM_DESTROY_IPCP,
        IRM_BOOTSTRAP_IPCP,
        IRM_ENROLL_IPCP,
        IRM_REG_IPCP,
        IRM_UNREG_IPCP
};

struct irm_msg {
        enum irm_msg_code   code;
        rina_name_t *       name;
        char *              ipcp_type;
        struct dif_config * conf;
        char *              dif_name;
        char **             difs;
        size_t              difs_size;
};

enum ipcp_msg_code {
        IPCP_BOOTSTRAP,
        IPCP_ENROLL,
        IPCP_REG,
        IPCP_UNREG
};

struct ipcp_msg {
        enum ipcp_msg_code  code;
        struct dif_config * conf;
        char *              dif_name;
        rina_name_t *       member;
        char **             difs;
        size_t              difs_size;
};

/* Returns the full socket path of an IPCP */
char *            ipcp_sock_path(pid_t pid);

int               client_socket_open(char * file_name);
int               server_socket_open(char * file_name);

/* Caller has to free the buffer */
buffer_t *        serialize_irm_msg(struct irm_msg * msg);
buffer_t *        serialize_ipcp_msg(struct ipcp_msg * msg);
/* Caller has to free all the allocated fields in the message */
struct irm_msg *  deserialize_irm_msg(buffer_t * data);
struct ipcp_msg * deserialize_ipcp_msg(buffer_t * data);

#endif
