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

#include <ouroboros/irm.h>
#include <ouroboros/dif_config.h>

#include "irm_ops.h"
#include "irm_utils.h"

#define NORMAL "normal"
#define SHIM_UDP "shim-udp"

#define DEFAULT_ADDR_SIZE 4
#define DEFAULT_CEP_ID_SIZE 2
#define DEFAULT_PDU_LEN_SIZE 2
#define DEFAULT_QOS_ID_SIZE 1
#define DEFAULT_SEQ_NO_SIZE 4
#define DEFAULT_TTL_SIZE 1
#define DEFAULT_CHK_SIZE 2
#define DEFAULT_MIN_PDU_SIZE 0
#define DEFAULT_MAX_PDU_SIZE 9000

static void usage()
{
        /* FIXME: Add dif_config stuff */
        printf("Usage: irm bootstrap_ipcp\n"
               "           ap <application process name>\n"
               "           [api <application process instance>]\n"
               "           dif <DIF name>\n"
               "           type [TYPE]\n\n"
               "where TYPE = {" NORMAL " " SHIM_UDP "}\n\n"
               "if TYPE == " NORMAL "\n"
               "           [addr <address size> (default: %d)]\n"
               "           [cep_id <CEP-id size> (default: %d)]\n"
               "           [pdu_len <PDU length size> (default: %d)]\n"
               "           [qos_id <QoS-id size> (default: %d)]\n"
               "           [seqno <sequence number size> (default: %d)]\n"
               "           [ttl <time to live size>  (default: %d)]\n"
               "           [chk <checksum size>  (default: %d)]\n"
               "           [min_pdu <minimum PDU size> (default: %d)]\n"
               "           [max_pdu <maximum PDU size> (default: %d)]\n"
               "if TYPE == " SHIM_UDP "\n"
               "           ip <IP address in dotted notation>\n",
               DEFAULT_ADDR_SIZE, DEFAULT_CEP_ID_SIZE,
               DEFAULT_PDU_LEN_SIZE, DEFAULT_QOS_ID_SIZE,
               DEFAULT_SEQ_NO_SIZE, DEFAULT_TTL_SIZE,
               DEFAULT_CHK_SIZE, DEFAULT_MIN_PDU_SIZE,
               DEFAULT_MAX_PDU_SIZE);
}

int do_bootstrap_ipcp(int argc, char ** argv)
{
        instance_name_t   api = {NULL, 0};
        struct dif_config conf;
        uint8_t addr_size = DEFAULT_ADDR_SIZE;
        uint8_t cep_id_size = DEFAULT_CEP_ID_SIZE;
        uint8_t pdu_length_size = DEFAULT_PDU_LEN_SIZE;
        uint8_t qos_id_size = DEFAULT_QOS_ID_SIZE;
        uint8_t seqno_size = DEFAULT_SEQ_NO_SIZE;
        uint8_t ttl_size = DEFAULT_TTL_SIZE;
        uint8_t chk_size = DEFAULT_CHK_SIZE;
        uint32_t min_pdu_size = DEFAULT_MIN_PDU_SIZE;
        uint32_t max_pdu_size = DEFAULT_MAX_PDU_SIZE;
        uint32_t ip_addr = 0;
        char * ipcp_type = NULL;
        char * dif_name = NULL;

        while (argc > 0) {
                if (matches(*argv, "type") == 0) {
                        ipcp_type = *(argv + 1);
                } else if (matches(*argv, "dif") == 0) {
                        dif_name = *(argv + 1);
                } else if (matches(*argv, "ap") == 0) {
                        api.name = *(argv + 1);
                } else if (matches(*argv, "api") == 0) {
                        api.id = atoi(*(argv + 1));
                } else if (matches(*argv, "ip") == 0) {
                        if (inet_pton (AF_INET, *(argv + 1), &ip_addr) != 1) {
                                usage();
                                return -1;
                        }
                } else if (matches(*argv, "addr") == 0) {
                        addr_size = atoi(*(argv + 1));
                } else if (matches(*argv, "cep_id") == 0) {
                        cep_id_size = atoi(*(argv + 1));
                } else if (matches(*argv, "pdu_len") == 0) {
                        pdu_length_size = atoi(*(argv + 1));
                } else if (matches(*argv, "qos_id") == 0) {
                        qos_id_size = atoi(*(argv + 1));
                } else if (matches(*argv, "seqno") == 0) {
                        seqno_size = atoi(*(argv + 1));
                } else if (matches(*argv, "ttl") == 0) {
                        ttl_size = atoi(*(argv + 1));
                } else if (matches(*argv, "chk") == 0) {
                        chk_size = atoi(*(argv + 1));
                } else if (matches(*argv, "min_pdu") == 0) {
                        min_pdu_size = atoi(*(argv + 1));
                } else if (matches(*argv, "max_pdu") == 0) {
                        max_pdu_size = atoi(*(argv + 1));
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "destroy_ipcp\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (api.name == NULL || dif_name == NULL || ipcp_type == NULL) {
                usage();
                return -1;
        }

        conf.dif_name = dif_name;

        if (strcmp(ipcp_type, NORMAL) == 0) {
                conf.type = IPCP_NORMAL;
                conf.addr_size = addr_size;
                conf.cep_id_size = cep_id_size;
                conf.pdu_length_size = pdu_length_size;
                conf.qos_id_size = qos_id_size;
                conf.seqno_size = seqno_size;
                conf.ttl_size = ttl_size;
                conf.chk_size = chk_size;
                conf.min_pdu_size = min_pdu_size;
                conf.max_pdu_size = max_pdu_size;
        } else if (strcmp(ipcp_type, SHIM_UDP) == 0) {
                conf.type = IPCP_SHIM_UDP;
                if (ip_addr == 0) {
                        usage();
                        return -1;
                }
                conf.ip_addr = ip_addr;
        } else {
                usage();
                return -1;
        }

        return irm_bootstrap_ipcp(&api, &conf);
}
