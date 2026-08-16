/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Handy helper functions for the IRM tool
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

/*
 * Copyright (c) 1989, 1993, 1994
 *      The Regents of the University of California.  All rights reserved.
 *
 * Wildcard Match code below is derived from software contributed to Berkeley by
 * Guido van Rossum.
 *
 * Copyright (c) 2011 The FreeBSD Foundation
 * All rights reserved.
 * Portions of this software were developed by David Chisnall
 * under sponsorship from the FreeBSD Foundation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * wildcard_match is based on the fnmatch function from POSIX.2.
 * Implementation based on that one from FreeBSD.
 */


#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <ouroboros/ipcp.h>

#include "irm_utils.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int matches(const char * cmd,
            const char * pattern)
{
        size_t len = strlen(cmd);

        if (len > strlen(pattern))
                return -1;

        return memcmp(pattern, cmd, len);
}

int wildcard_match(const char * pattern,
                   const char * string)
{
        char c;

        /* For loop? Why not Zoidberg? */
        for (;;) {
                switch (c = *pattern++) {
                case '\0':
                        return (*string == '\0' ? 0 : -1);
                case '*':
                        c = *pattern;

                        if (c == '\0')
                                return 0;

                        /* General case, use recursion. */
                        while (*string != '\0') {
                                if (!wildcard_match(pattern, string))
                                        return 0;
                                ++string;
                        }
                        return -1;
                default:
                        if (c != *string)
                                return -1;
                        string++;
                        break;
                }
        }
}

/* Splits "<addr>[:<port>]"; bare IPv6 needs no brackets. */
static int parse_udp_str(const char * str,
                         char *       host,
                         int *        port)
{
        struct in6_addr v6;
        char            buf[POA_HOST_STRLEN + 1];
        char *          p;
        char *          end;
        long            n;

        *port = POA_UDP_PORT;

        if (strlen(str) > POA_HOST_STRLEN)
                goto fail;

        strcpy(buf, str);

        if (buf[0] == '[') {
                p = strchr(buf, ']');
                if (p == NULL)
                        goto fail;

                *p++ = '\0';

                strcpy(host, buf + 1);

                if (*p == '\0')
                        return 0;

                if (*p != ':')
                        goto fail;

                ++p;
        } else if (inet_pton(AF_INET6, buf, &v6) == 1) {
                strcpy(host, buf);
                return 0;
        } else {
                p = strrchr(buf, ':');
                if (p == NULL) {
                        strcpy(host, buf);
                        return 0;
                }

                *p++ = '\0';

                strcpy(host, buf);
        }

        n = strtol(p, &end, 10);
        if (*p == '\0' || *end != '\0' || n < 1 || n > 65535)
                goto fail;

        *port = (int) n;

        return 0;
 fail:
        printf("Invalid UDP address: \"%s\".\n", str);
        return -1;
}

/* An unresolved name is left for the IRMd, which picks the family. */
int poa_addr_set_udp(struct poa_addr * addr,
                     const char *      str)
{
        char host[POA_HOST_STRLEN + 1];
        int  port;

        if (parse_udp_str(str, host, &port) < 0)
                return -1;

        if (inet_pton(AF_INET, host, &addr->udp4.ip_addr) == 1) {
                addr->type      = POA_UDP4;
                addr->udp4.port = port;
                return 0;
        }

        if (inet_pton(AF_INET6, host, &addr->udp6.ip_addr) == 1) {
                addr->type      = POA_UDP6;
                addr->udp6.port = port;
                return 0;
        }

        addr->type      = POA_UDP;
        addr->udp4.port = port;

        strcpy(addr->hostname, host);

        return 0;
}

/*
 * Parses a hex ethertype; rejects garbage and out-of-range values.
 * Overflow clamps to LONG_MAX and lands in the range check.
 */
int parse_ethertype(const char * str,
                    uint16_t *   ethertype)
{
        char * end;
        long   val;

        val = strtol(str, &end, 16);

        if (end == str || *end != '\0')
                return -1;

        if (val < 0 || val > 0xFFFF)
                return -1;

        *ethertype = (uint16_t) val;

        return 0;
}

int poa_addr_set_eth(struct poa_addr * addr,
                     const char *      devstr,
                     uint16_t          ethertype)
{
        addr->type = POA_ETH;

        addr->eth.src.ethertype = ethertype;
        addr->eth.dst.ethertype = ethertype;

        if (devstr != NULL) {
                if (strlen(devstr) > DEV_NAME_SIZE) {
                        printf("Invalid device name: \"%s\".\n", devstr);
                        return -1;
                }

                strcpy(addr->eth.src.dev, devstr);
        }

        return 0;
}

/* Matches src/ipcpd/ipcp.c; keep in sync. */
void poa_spec_str(const struct poa_spec * poa,
                  char *                  buf,
                  size_t                  len)
{
        char addr[INET6_ADDRSTRLEN];

        switch (poa->type) {
        case POA_UDP4:
                if (inet_ntop(AF_INET, &poa->udp4.ip_addr,
                              addr, sizeof(addr)) == NULL)
                        break;

                snprintf(buf, len, "udp4 %s:%u", addr, poa->udp4.port);
                return;
        case POA_UDP6:
                if (inet_ntop(AF_INET6, &poa->udp6.ip_addr,
                              addr, sizeof(addr)) == NULL)
                        break;

                snprintf(buf, len, "udp6 [%s]:%u", addr, poa->udp6.port);
                return;
        case POA_ETH:
                snprintf(buf, len, "eth %s 0x%04X", poa->eth.dev,
                         poa->eth.ethertype);
                return;
        default:
                break;
        }

        snprintf(buf, len, "(unknown)");
}

int poa_spec_set(struct poa_spec * poa,
                 const char *      udpstr,
                 const char *      devstr,
                 uint16_t          ethertype)
{
        char host[POA_HOST_STRLEN + 1];
        int  port;

        memset(poa, 0, sizeof(*poa));

        if ((udpstr != NULL) + (devstr != NULL) > 1) {
                printf("A PoA is an address or a device.\n");
                return -1;
        }

        if (udpstr != NULL) {
                if (parse_udp_str(udpstr, host, &port) < 0)
                        return -1;

                if (inet_pton(AF_INET, host, &poa->udp4.ip_addr) == 1) {
                        poa->type      = POA_UDP4;
                        poa->udp4.port = port;
                        return 0;
                }

                if (inet_pton(AF_INET6, host, &poa->udp6.ip_addr) == 1) {
                        poa->type      = POA_UDP6;
                        poa->udp6.port = port;
                        return 0;
                }

                printf("Invalid IP address: \"%s\".\n", udpstr);
                return -1;
        }

        if (devstr != NULL) {
                if (strlen(devstr) > DEV_NAME_SIZE) {
                        printf("Invalid device name: \"%s\".\n", devstr);
                        return -1;
                }

                poa->type          = POA_ETH;
                poa->eth.ethertype = ethertype;

                strcpy(poa->eth.dev, devstr);

                return 0;
        }

        return -1;
}
