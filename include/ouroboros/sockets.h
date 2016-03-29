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

#include <sys/types.h>

#include "irmd_messages.pb-c.h"
typedef IrmMsg irm_msg_t;

#include "ipcpd_messages.pb-c.h"
typedef IpcpMsg ipcp_msg_t;

#define IRM_SOCK_PATH "/tmp/irm_sock"
#define IRM_MSG_BUF_SIZE 256

#define IPCP_SOCK_PATH_PREFIX "/tmp/ipcp_sock"
#define IPCP_MSG_BUFS_SIZE IRM_MSG_BUF_SIZE

/* Returns the full socket path of an IPCP */
char *      ipcp_sock_path(pid_t pid);

int         server_socket_open(char * file_name);
int         client_socket_open(char * file_name);

int         send_irm_msg(irm_msg_t * msg);
irm_msg_t * send_recv_irm_msg(irm_msg_t * msg);

#endif
