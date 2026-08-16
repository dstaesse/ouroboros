/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Connect components of unicast or broadcast IPC processes
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <ouroboros/irm.h>
#include <ouroboros/qos.h>

#include "irm_ops.h"
#include "irm_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>

#define DT   "dt"
#define MGMT "mgmt"

static void usage(void)
{
        printf("Usage: irm ipcp connect\n"
               "                name      <ipcp name>\n"
               "                dst       <name of destination IPCP>\n"
               "                [component [COMPONENT]]\n"
               "                [udp       [UDP_PEER]]\n"
               "                [eth       [dev <device>]"
               " [ethertype <ethertype>]]\n"
               "where COMPONENT in {" DT " " MGMT "}\n"
               "and UDP_PEER is <IP address or host>[:<port>]\n\n"
               "if COMPONENT == " DT "\n"
               "                [qos       [QOS]]\n"
               "where QOS in {raw, safe, rt, rt-safe, msg}\n");
}

int do_connect_ipcp(int     argc,
                    char ** argv)
{
        char *                  ipcp      = NULL;
        char *                  dst       = NULL;
        char *                  comp      = "*";
        char *                  component = NULL;
        char *                  qos       = NULL;
        char *                  udpstr    = NULL;
        char *                  devstr    = NULL;
        uint16_t                ethertype = POA_ETHERTYPE;
        bool                    eth       = false;
        struct poa_addr         addr;
        struct poa_addr *       pa        = NULL;
        struct ipcp_list_info * ipcps;
        ssize_t                 len       = 0;
        pid_t                   pid       = -1;
        ssize_t                 i;
        int                     cargs;
        qosspec_t               qs        = qos_raw;

        while (argc > 0) {
                cargs = 2;
                if (strcmp(*argv, "eth") == 0)
                        cargs = 1;

                if (argc < cargs) {
                        usage();
                        return -1;
                }

                if (matches(*argv, "name") == 0) {
                        ipcp = *(argv + 1);
                } else if (matches(*argv, "dst") == 0) {
                        dst = *(argv + 1);
                } else if (matches(*argv, "component") == 0) {
                        comp = *(argv + 1);
                } else if (matches(*argv, "qos") == 0) {
                        qos = *(argv + 1);
                } else if (strcmp(*argv, "udp") == 0) {
                        udpstr = *(argv + 1);
                } else if (strcmp(*argv, "dev") == 0) {
                        devstr = *(argv + 1);
                } else if (strcmp(*argv, "ethertype") == 0) {
                        if (parse_ethertype(*(argv + 1), &ethertype) < 0) {
                                printf("Invalid ethertype: \"%s\".\n",
                                       *(argv + 1));
                                return -1;
                        }
                } else if (strcmp(*argv, "eth") == 0) {
                        eth = true;
                        cargs = 1;
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "ipcp connect\".\n", *argv);
                        return -1;
                }

                argc -= cargs;
                argv += cargs;
        }

        if (ipcp == NULL || comp == NULL) {
                usage();
                return -1;
        }

        memset(&addr, 0, sizeof(addr));

        if (udpstr != NULL) {
                if (poa_addr_set_udp(&addr, udpstr) < 0)
                        return -1;
                pa = &addr;
        }

        if (eth) {
                if (udpstr != NULL) {
                        printf("Connect via udp or eth, not both.\n");
                        return -1;
                }

                if (dst == NULL) {
                        usage();
                        return -1;
                }

                if (poa_addr_set_eth(&addr, devstr, ethertype) < 0)
                        return -1;
                pa = &addr;
        }

        if (dst == NULL && pa == NULL) {
                usage();
                return -1;
        }

        if (dst == NULL)
                dst = "";

        if (qos != NULL) {
                if (strcmp(qos, "raw") == 0)
                        qs = qos_raw;
                else if (strcmp(qos, "safe") == 0)
                        qs = qos_raw_safe;
                else if (strcmp(qos, "rt") == 0)
                        qs = qos_rt;
                else if (strcmp(qos, "rt-safe") == 0)
                        qs = qos_rt_safe;
                else if (strcmp(qos, "msg") == 0)
                        qs = qos_msg;
                else if (strcmp(qos, "stream") == 0) {
                        printf("Stream QoS is not allowed on "
                               "IPCP component flows.\n");
                        return -1;
                } else
                        printf("Unknown QoS cube, defaulting to raw.\n");
        }

        len = irm_list_ipcps(&ipcps);
        for (i = 0; i < len; i++)
                if (strcmp(ipcps[i].name, ipcp) == 0)
                        pid = ipcps[i].pid;

        free(ipcps);

        if (pid == -1)
                return -1;

        if (wildcard_match(comp, MGMT) == 0) {
                component = MGMT_COMP;
                /* FIXME: move to qos_msg when stable */
                if (irm_connect_ipcp(pid, dst, component, qos_raw, pa))
                        return -1;
        }

        if (wildcard_match(comp, DT) == 0) {
                component = DT_COMP;
                if (irm_connect_ipcp(pid, dst, component, qs, pa))
                        return -1;
        }

        return 0;
}
