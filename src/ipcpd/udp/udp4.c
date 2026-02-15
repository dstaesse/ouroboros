/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * IPC process over UDP/IPv4
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200112L
#endif

#include <ouroboros/ipcp-dev.h>

#define BUILD_IPCP_UDP4
#define THIS_TYPE                IPCP_UDP4
#define TYPE_STR                 "IPCP over UDP/IPv4"
#define OUROBOROS_PREFIX         "ipcpd/udp4"
#define IPCP_UDP_MAX_PACKET_SIZE 8980
#define __AF                     AF_INET
#define __ADDRSTRLEN             INET_ADDRSTRLEN
#define __SOCKADDR               sockaddr_in
#define __ADDR                   in_addr
#define __ADDR_ANY_INIT          { .s_addr = INADDR_ANY }

#include "udp.c"
