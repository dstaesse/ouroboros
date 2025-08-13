/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Create IPC Processes
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

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE 500

#include <ouroboros/errno.h>
#include <ouroboros/irm.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "irm_ops.h"
#include "irm_utils.h"

#define RR    "round-robin"
#define SPILL "spillover"
#define SCRT  "<security_dir>/server/<name>/crt.pem"
#define SKEY  "<security_dir>/server/<name>/key.pem"
#define CCRT  "<security_dir>/client/<name>/crt.pem"
#define CKEY  "<security_dir>/client/<name>/key.pem"

static void usage(void)
{
        printf("Usage: irm name create\n"
               "                <name>. max %d chars.\n"
               "                [lb LB_POLICY], default: %s\n"
               "                [scrtpath <path>, default: " SCRT "]\n"
               "                [skeypath <path>, default: " SKEY "]\n"
               "                [ccrtpath <path>, default: " CCRT "]\n"
               "                [ckeypath <path>, default: " CKEY "]\n"
               "\n"
               "where LB_POLICY in {" RR " " SPILL "}\n",
                NAME_SIZE, RR);
}

int do_create_name(int     argc,
                   char ** argv)
{
        struct name_info info = {};
        char * name = NULL;
        char * scrtpath = NULL;
        char * skeypath = NULL;
        char * ccrtpath = NULL;
        char * ckeypath = NULL;
        char * lb_pol = RR;

        name = *(argv++);
        --argc;

        while (argc > 0) {
                if (matches(*argv, "lb") == 0) {
                        lb_pol = *(argv + 1);
                } else if (matches(*argv, "scrtpath") == 0) {
                        scrtpath = *(argv + 1);
                } else if (matches(*argv, "skeypath") == 0) {
                        skeypath = *(argv + 1);
                } else if (matches(*argv, "ccrtpath") == 0) {
                        ccrtpath = *(argv + 1);
                } else if (matches(*argv, "ckeypath") == 0) {
                        ckeypath = *(argv + 1);
                } else {
                        printf("\"%s\" is unknown, try \"irm "
                               "name create\".\n", *argv);
                        return -1;
                }

                argc -= 2;
                argv += 2;
        }

        if (name == NULL)
                goto fail;

        if (strlen(name) > NAME_SIZE) {
                printf("Name too long.\n");
                goto fail;
        }

        strcpy(info.name, name);

        if (scrtpath != NULL) {
                scrtpath = realpath(scrtpath, NULL);
                if (scrtpath == NULL) {
                        printf("Failed to resolve server crt path: %s.\n",
                                strerror(errno));
                        goto fail;
                }
                if (strlen(scrtpath) > NAME_PATH_SIZE) {
                        printf("Server crt path > %d chars.", NAME_PATH_SIZE);
                        free(scrtpath);
                        goto fail;
                }
                strcpy(info.s.crt, scrtpath);
                free(scrtpath);
        }

        if (skeypath != NULL) {
                skeypath = realpath(skeypath, NULL);
                if (skeypath == NULL) {
                        printf("Failed to resolve server key path: %s.\n",
                                strerror(errno));
                        goto fail;
                }
                if (strlen(skeypath) > NAME_PATH_SIZE) {
                        printf("Server key path > %d chars.", NAME_PATH_SIZE);
                        free(skeypath);
                        goto fail;
                }
                strcpy(info.s.key, skeypath);
                free(skeypath);
        }

        if (ccrtpath != NULL) {
                ccrtpath = realpath(ccrtpath, NULL);
                if (ccrtpath == NULL) {
                        printf("Failed to resolve client crt path: %s.\n",
                                strerror(errno));
                        goto fail;
                }
                if (strlen(ccrtpath) > NAME_PATH_SIZE) {
                        printf("Client crt path > %d chars.", NAME_PATH_SIZE);
                        free(ccrtpath);
                        goto fail;
                }
                strcpy(info.c.crt, ccrtpath);
                free(ccrtpath);
        }

        if (ckeypath != NULL) {
                ckeypath = realpath(ckeypath, NULL);
                if (ckeypath == NULL) {
                        printf("Failed to resolve client key path: %s.\n",
                                strerror(errno));
                        goto fail;
                }

                if (strlen(ckeypath) > NAME_PATH_SIZE) {
                        printf("Client key path > %d chars.", NAME_PATH_SIZE);
                        free(ckeypath);
                        goto fail;
                }
                strcpy(info.c.key, ckeypath);
                free(ckeypath);
        }

        if (strcmp(lb_pol, RR) == 0)
                info.pol_lb = LB_RR;
        else if (strcmp(lb_pol, SPILL) == 0)
                info.pol_lb = LB_SPILL;
        else {
                usage();
                return -1;
        }

        return irm_create_name(&info);
 fail:
        usage();
        return -1;
}
