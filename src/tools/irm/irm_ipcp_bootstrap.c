/*
 * Ouroboros - Copyright (C) 2016
 *
 * Bootstrap IPC Processes
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#ifdef __FreeBSD__
#include <sys/socket.h>
#endif
#include <ouroboros/irm.h>
#include <ouroboros/irm_config.h>

#include "irm_ops.h"
#include "irm_utils.h"

#define NORMAL "normal"
#define SHIM_UDP "shim-udp"
#define SHIM_ETH_LLC "shim-eth-llc"
#define LOCAL "local"

#define DEFAULT_ADDR_SIZE 4
#define DEFAULT_CEP_ID_SIZE 2
#define DEFAULT_PDU_LEN_SIZE 2
#define DEFAULT_SEQ_NO_SIZE 4
#define DEFAULT_MIN_PDU_SIZE 0
#define DEFAULT_MAX_PDU_SIZE 9000
#define DEFAULT_DDNS 0

static void usage(void)
{
        /* FIXME: Add dif_config stuff */
        printf("Usage: irm ipcp bootstrap\n"
               "                name <ipcp name>\n"
               "                dif <DIF name>\n"
               "                type [TYPE]\n\n"
               "where TYPE = {" NORMAL " " LOCAL " "
               SHIM_UDP " " SHIM_ETH_LLC"}\n\n"
               "if TYPE == " NORMAL "\n"
               "                [addr <address size> (default: %d)]\n"
               "                [cep_id <CEP-id size> (default: %d)]\n"
               "                [pdu_len <PDU length size> (default: %d)]\n"
               "                [seqno <sequence number size> (default: %d)]\n"
               "                [ttl <add time to live value in the PCI>]\n"
               "                [chk <add 32-bit checksum in the PCI>]\n"
               "                [min_pdu <minimum PDU size> (default: %d)]\n"
               "                [max_pdu <maximum PDU size> (default: %d)]\n"
               "if TYPE == " SHIM_UDP "\n"
               "                ip <IP address in dotted notation>\n"
               "                [dns <DDNS IP address in dotted notation>"
               " (default = none: %d)]\n"
               "if TYPE == " SHIM_ETH_LLC "\n"
               "                if_name <interface name>\n",
               DEFAULT_ADDR_SIZE, DEFAULT_CEP_ID_SIZE,
               DEFAULT_PDU_LEN_SIZE, DEFAULT_SEQ_NO_SIZE,
               DEFAULT_MIN_PDU_SIZE, DEFAULT_MAX_PDU_SIZE, DEFAULT_DDNS);
}

int do_bootstrap_ipcp(int argc, char ** argv)
{
        char * name = NULL;
        pid_t api;
        struct dif_config conf;
        uint8_t addr_size = DEFAULT_ADDR_SIZE;
        uint8_t cep_id_size = DEFAULT_CEP_ID_SIZE;
        uint8_t pdu_length_size = DEFAULT_PDU_LEN_SIZE;
        uint8_t seqno_size = DEFAULT_SEQ_NO_SIZE;
        bool has_ttl = false;
        bool has_chk = false;
        uint32_t min_pdu_size = DEFAULT_MIN_PDU_SIZE;
        uint32_t max_pdu_size = DEFAULT_MAX_PDU_SIZE;
        uint32_t ip_addr = 0;
        uint32_t dns_addr = DEFAULT_DDNS;
        char * ipcp_type = NULL;
        char * dif_name = NULL;
        char * if_name = NULL;
        pid_t * apis = NULL;
        ssize_t len = 0;
        int i = 0;

        while (argc > 0) {
                if (matches(*argv, "type") == 0) {
                        ipcp_type = *(argv + 1);
                } else if (matches(*argv, "dif") == 0) {
                        dif_name = *(argv + 1);
                } else if (matches(*argv, "name") == 0) {
                        name = *(argv + 1);
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
                } else if (matches(*argv, "cep_id") == 0) {
                        cep_id_size = atoi(*(argv + 1));
                } else if (matches(*argv, "pdu_len") == 0) {
                        pdu_length_size = atoi(*(argv + 1));
                } else if (matches(*argv, "seqno") == 0) {
                        seqno_size = atoi(*(argv + 1));
                } else if (matches(*argv, "ttl") == 0) {
                        has_ttl = true;
                        argc++;
                        argv--;
                } else if (matches(*argv, "chk") == 0) {
                        has_chk = true;
                        argc++;
                        argv--;
                } else if (matches(*argv, "min_pdu") == 0) {
                        min_pdu_size = atoi(*(argv + 1));
                } else if (matches(*argv, "max_pdu") == 0) {
                        max_pdu_size = atoi(*(argv + 1));
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

        conf.dif_name = dif_name;

        if (strcmp(ipcp_type, NORMAL) == 0) {
                conf.type = IPCP_NORMAL;
                conf.addr_size = addr_size;
                conf.cep_id_size = cep_id_size;
                conf.pdu_length_size = pdu_length_size;
                conf.seqno_size = seqno_size;
                conf.has_ttl = has_ttl;
                conf.has_chk = has_chk;
                conf.min_pdu_size = min_pdu_size;
                conf.max_pdu_size = max_pdu_size;
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
                if (conf.type == IPCP_NORMAL)
                        irm_bind_api(api, name);
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
