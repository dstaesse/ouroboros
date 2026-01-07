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
#define SENC  "<security_dir>/server/<name>/enc.conf"
#define SCRT  "<security_dir>/server/<name>/crt.pem"
#define SKEY  "<security_dir>/server/<name>/key.pem"
#define CENC  "<security_dir>/client/<name>/enc.conf"
#define CCRT  "<security_dir>/client/<name>/crt.pem"
#define CKEY  "<security_dir>/client/<name>/key.pem"

static void usage(void)
{
        printf("Usage: irm name create\n"
               "                <name>. max %d chars.\n"
               "                [lb LB_POLICY], default: %s\n"
               "                [sencpath <path>, default: " SENC "]\n"
               "                [scrtpath <path>, default: " SCRT "]\n"
               "                [skeypath <path>, default: " SKEY "]\n"
               "                [cencpath <path>, default: " CENC "]\n"
               "                [ccrtpath <path>, default: " CCRT "]\n"
               "                [ckeypath <path>, default: " CKEY "]\n"
               "\n"
               "where LB_POLICY in {" RR " " SPILL "}\n",
                NAME_SIZE, RR);
}

static int cp_chk_path(char *       buf,
                       const char * path)
{
        char * rp = realpath(path, NULL);
        if (rp == NULL) {
                printf("Failed to check path %s: %s\n.",
                       path, strerror(errno));
                goto fail_rp;
        }

        if (strlen(rp) > NAME_PATH_SIZE) {
                printf("File path too long: %s.\n", rp);
                goto fail_len;
        }

        strcpy(buf, rp);
        free(rp);

        return 0;

 fail_len:
        free(rp);
 fail_rp:
        return -1;
}

int do_create_name(int     argc,
                   char ** argv)
{
        struct name_info info = {};
        char * name = NULL;
        char * sencpath = NULL;
        char * scrtpath = NULL;
        char * skeypath = NULL;
        char * cencpath = NULL;
        char * ccrtpath = NULL;
        char * ckeypath = NULL;
        char * lb_pol = RR;

        name = *(argv++);
        --argc;

        while (argc > 0) {
                if (matches(*argv, "lb") == 0) {
                        lb_pol = *(argv + 1);
                } else if (matches(*argv, "sencpath") == 0) {
                        sencpath = *(argv + 1);
                } else if (matches(*argv, "scrtpath") == 0) {
                        scrtpath = *(argv + 1);
                } else if (matches(*argv, "skeypath") == 0) {
                        skeypath = *(argv + 1);
                } else if (matches(*argv, "cencpath") == 0) {
                        cencpath = *(argv + 1);
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

        if (sencpath != NULL && cp_chk_path(info.s.enc, sencpath) < 0)
                goto fail;

        if (scrtpath != NULL && cp_chk_path(info.s.crt, scrtpath) < 0)
                goto fail;

        if (skeypath != NULL && cp_chk_path(info.s.key, skeypath) < 0)
                goto fail;

        if (cencpath != NULL && cp_chk_path(info.c.enc, cencpath) < 0)
                goto fail;

        if (ccrtpath != NULL && cp_chk_path(info.c.crt, ccrtpath) < 0)
                goto fail;

        if (ckeypath != NULL && cp_chk_path(info.c.key, ckeypath) < 0)
                goto fail;

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
