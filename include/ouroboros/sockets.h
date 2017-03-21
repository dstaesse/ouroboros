/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The sockets layer to communicate between daemons
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OUROBOROS_SOCKETS_H
#define OUROBOROS_SOCKETS_H

#include <sys/types.h>

#include "dif_config.pb-c.h"
typedef DifConfigMsg dif_config_msg_t;

#include "irmd_messages.pb-c.h"
typedef IrmMsg irm_msg_t;

#include "ipcpd_messages.pb-c.h"
typedef IpcpMsg ipcp_msg_t;

#define SOCK_PATH "/var/run/ouroboros/"
#define SOCK_PATH_SUFFIX ".sock"

#define IRM_SOCK_PATH SOCK_PATH "irm" SOCK_PATH_SUFFIX
#define IRM_MSG_BUF_SIZE 256

#define IPCP_SOCK_PATH_PREFIX SOCK_PATH "ipcp"
#define IPCP_MSG_BUF_SIZE IRM_MSG_BUF_SIZE

/* Returns the full socket path of an IPCP */
char *      ipcp_sock_path(pid_t api);

int         server_socket_open(char * file_name);

int         client_socket_open(char * file_name);

irm_msg_t * send_recv_irm_msg(irm_msg_t * msg);

irm_msg_t * send_recv_irm_msg_b(irm_msg_t * msg);

#endif
