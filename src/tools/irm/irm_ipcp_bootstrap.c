/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Bootstrap IPC Processes
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#ifdef __FreeBSD__
#include <sys/socket.h>
#endif
#include <ouroboros/irm.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/hash.h>

#include "irm_ops.h"
#include "irm_utils.h"

#define NORMAL            "normal"
#define SHIM_UDP          "shim-udp"
#define SHIM_ETH_LLC      "shim-eth-llc"
#define LOCAL             "local"

#define CRC32             "CRC32"
#define MD5               "MD5"
#define SHA3_224          "SHA3_224"
#define SHA3_256          "SHA3_256"
#define SHA3_384          "SHA3_384"
#define SHA3_512          "SHA3_512"

#define DEFAULT_HASH_ALGO HASH_SHA3_256
#define DEFAULT_HASH_STR  SHA3_256
#define DEFAULT_ADDR_SIZE 4
#define DEFAULT_FD_SIZE   2
#define DEFAULT_DDNS      0
#define DEFAULT_ADDR_AUTH FLAT_RANDOM
#define DEFAULT_DT_GAM    COMPLETE
#define DEFAULT_RM_GAM    COMPLETE
#define ADDR_AUTH_FLAT    "flat"

#define DT_GAM_COMPLETE   "complete"
#define RM_GAM_COMPLETE   "complete"

static void usage(void)
{
        /* FIXME: Add ipcp_config stuff */
        printf("Usage: irm ipcp bootstrap\n"
               "                name <ipcp name>\n"
               "                dif <DIF name>\n"
               "                type [TYPE]\n"
               "                [hash [ALGORITHM] (default: %s)]\n"
               "where TYPE = {" NORMAL " " LOCAL " "
               SHIM_UDP " " SHIM_ETH_LLC"},\n"
               "      ALGORITHM = { " CRC32 " " MD5 " "
               SHA3_224 " " SHA3_256 " " SHA3_384 " " SHA3_512 "}.\n\n"
               "if TYPE == " NORMAL "\n"
               "                [addr <address size> (default: %d)]\n"
               "                [fd <fd size> (default: %d)]\n"
               "                [ttl <add time to live value in the PCI>]\n"
               "                [addr_auth <address policy> (default: %s)]\n"
               "                [dt_gam <data transfer graph adjacency manager>"
               " (default: %s)]\n"
               "                [rm_gam <rib manager graph adjacency manager>"
               " (default: %s)]\n"
               "if TYPE == " SHIM_UDP "\n"
               "                ip <IP address in dotted notation>\n"
               "                [dns <DDNS IP address in dotted notation>"
               " (default = none: %d)]\n"
               "if TYPE == " SHIM_ETH_LLC "\n"
               "                if_name <interface name>\n",
               DEFAULT_HASH_STR, DEFAULT_ADDR_SIZE, DEFAULT_FD_SIZE,
               ADDR_AUTH_FLAT, DT_GAM_COMPLETE, RM_GAM_COMPLETE, DEFAULT_DDNS);
}

int do_bootstrap_ipcp(int argc, char ** argv)
{
        char *             name           = NULL;
        char *             hash           = DEFAULT_HASH_STR;
        pid_t              api;
        struct ipcp_config conf;
        uint8_t            addr_size      = DEFAULT_ADDR_SIZE;
        uint8_t            fd_size        = DEFAULT_FD_SIZE;
        bool               has_ttl        = false;
        enum pol_addr_auth addr_auth_type = DEFAULT_ADDR_AUTH;
        enum pol_gam       dt_gam_type    = DEFAULT_DT_GAM;
        enum pol_gam       rm_gam_type    = DEFAULT_RM_GAM;
        uint32_t           ip_addr        = 0;
        uint32_t           dns_addr       = DEFAULT_DDNS;
        char *             ipcp_type      = NULL;
        char *             dif_name       = NULL;
        char *             if_name        = NULL;
        pid_t *            apis           = NULL;
        ssize_t            len            = 0;
        int                i              = 0;

        while (argc > 0) {
                if (matches(*argv, "type") == 0) {
                        ipcp_type = *(argv + 1);
                } else if (matches(*argv, "dif") == 0) {
                        dif_name = *(argv + 1);
                } else if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
                } else if (matches(*argv, "hash") == 0) {
                        hash = *(argv + 1);
                } else if (matches(*argv, "ip") == 0) {
                        if (inet_pton (AF_INET, *(argv + 1), &ip_addr) != 1) {
                                usage();
                                return -1;
                        }
                } else if (matches(*argv, "dns") == 0) {
                        if (inet_pton(AF_INET, *(argv + 1), &dns_addr) != 1) {
                                usage();
                                return -1;
                        }
                } else if (matches(*argv, "if_name") == 0) {
                        if_name = *(argv + 1);
                } else if (matches(*argv, "addr") == 0) {
                        addr_size = atoi(*(argv + 1));
                } else if (matches(*argv, "fd") == 0) {
                        fd_size = atoi(*(argv + 1));
                } else if (matches(*argv, "ttl") == 0) {
                        has_ttl = true;
                        argc++;
                        argv--;
                } else if (matches(*argv, "addr_auth") == 0) {
                        if (strcmp(ADDR_AUTH_FLAT, *(argv + 1)) == 0)
                                addr_auth_type = FLAT_RANDOM;
                } else if (matches(*argv, "dt_gam") == 0) {
                        if (strcmp(DT_GAM_COMPLETE, *(argv + 1)) == 0)
                                dt_gam_type = COMPLETE;
                } else if (matches(*argv, "rm_gam") == 0) {
                        if (strcmp(RM_GAM_COMPLETE, *(argv + 1)) == 0)
                                rm_gam_type = COMPLETE;
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "ipcp bootstrap\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (name == NULL || dif_name == NULL || ipcp_type == NULL) {
                usage();
                return -1;
        }

        strcpy(conf.dif_info.dif_name, dif_name);

        if (strcmp(hash, CRC32) == 0) {
                conf.dif_info.dir_hash_algo = HASH_CRC32;
        } else if (strcmp(hash, MD5) == 0) {
                conf.dif_info.dir_hash_algo = HASH_MD5;
        } else if (strcmp(hash, SHA3_224) == 0) {
                conf.dif_info.dir_hash_algo = HASH_SHA3_224;
        } else if (strcmp(hash, SHA3_256) == 0) {
                conf.dif_info.dir_hash_algo = HASH_SHA3_256;
        } else if (strcmp(hash, SHA3_384) == 0) {
                conf.dif_info.dir_hash_algo = HASH_SHA3_384;
        } else if (strcmp(hash, SHA3_512) == 0) {
                conf.dif_info.dir_hash_algo = HASH_SHA3_512;
        } else {
                usage();
                return -1;
        }

        if (strcmp(ipcp_type, NORMAL) == 0) {
                conf.type = IPCP_NORMAL;
                conf.addr_size = addr_size;
                conf.fd_size = fd_size;
                conf.has_ttl = has_ttl;
                conf.addr_auth_type = addr_auth_type;
                conf.dt_gam_type = dt_gam_type;
                conf.rm_gam_type = rm_gam_type;
        } else if (strcmp(ipcp_type, SHIM_UDP) == 0) {
                conf.type = IPCP_SHIM_UDP;
                if (ip_addr == 0) {
                        usage();
                        return -1;
                }
                conf.ip_addr = ip_addr;
                conf.dns_addr = dns_addr;
        } else if (strcmp(ipcp_type, LOCAL) == 0) {
                conf.type = IPCP_LOCAL;
        } else if (strcmp(ipcp_type, SHIM_ETH_LLC) == 0) {
                conf.type = IPCP_SHIM_ETH_LLC;
                if (if_name == NULL) {
                        usage();
                        return -1;
                }
                conf.if_name = if_name;
        } else {
                usage();
                return -1;
        }

        len = irm_list_ipcps(name, &apis);
        if (len <= 0) {
                api = irm_create_ipcp(name, conf.type);
                if (api == 0)
                        return -1;
                len = irm_list_ipcps(name, &apis);
        }

        for (i = 0; i < len; i++)
                if (irm_bootstrap_ipcp(apis[i], &conf)) {
                        free(apis);
                        return -1;
                }

        if (apis != NULL)
                free(apis);

        return 0;
}
