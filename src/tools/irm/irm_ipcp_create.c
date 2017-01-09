/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Create IPC Processes
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#include <ouroboros/irm.h>

#include <stdio.h>
#include <string.h>

#include "irm_ops.h"
#include "irm_utils.h"

#define NORMAL "normal"
#define SHIM_UDP "shim-udp"
#define SHIM_ETH_LLC "shim-eth-llc"
#define LOCAL "local"

static void usage(void)
{
        printf("Usage: irm ipcp create\n"
               "                name <ipcp name>\n"
               "                type [TYPE]\n\n"
               "where TYPE = {" NORMAL " " LOCAL " "
               SHIM_UDP " " SHIM_ETH_LLC "}\n");
}

int do_create_ipcp(int argc, char ** argv)
{
        char * ipcp_type = NULL;
        char * ipcp_name = NULL;
        enum ipcp_type type = 0;
        pid_t api;

        while (argc > 0) {
                if (matches(*argv, "type") == 0) {
                        ipcp_type = *(argv + 1);
                } else if (matches(*argv, "name") == 0) {
                        ipcp_name = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "ipcp create\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (ipcp_type == NULL || ipcp_name == NULL) {
                usage();
                return -1;
        }

        if (strcmp(ipcp_type, NORMAL) == 0)
                type = IPCP_NORMAL;
        else if (strcmp(ipcp_type, SHIM_UDP) == 0)
                type = IPCP_SHIM_UDP;
        else if (strcmp(ipcp_type, LOCAL) == 0)
                type = IPCP_LOCAL;
        else if (strcmp(ipcp_type, SHIM_ETH_LLC) == 0)
                type = IPCP_SHIM_ETH_LLC;
        else {
                usage();
                return -1;
        }

        api = irm_create_ipcp(ipcp_name, type);
        if (api == 0)
                return -1;

        if (type == IPCP_NORMAL)
                irm_bind_api(api, ipcp_name);

        return 0;
}
