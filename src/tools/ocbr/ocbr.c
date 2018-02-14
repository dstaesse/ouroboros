/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * CBR traffic generator
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#define _POSIX_C_SOURCE 199506L
#define __XSI_VISIBLE 500

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <limits.h>
#include <time.h>
#include <stdbool.h>

#define BUF_SIZE 1500

#include "ocbr_client.c"

struct s {
        long interval;
        long timeout;
} server_settings;

#include "ocbr_server.c"

static void usage(void)
{
        printf("Usage: cbr [OPTION]...\n"
               "Sends SDUs from client to server at a constant bit rate.\n\n"
               "  -l, --listen              Run in server mode\n"
               "\n"
               "Server options:\n"
               "  -i, --interval            Server report interval (s)\n"
               "  -t, --timeout             Server timeout interval (s)\n"
               "\n"
               "Client options:\n"
               "  -n, --server_apn          Specify the name of the server.\n"
               "  -d, --duration            Duration for sending (s)\n"
               "  -f, --flood               Send SDUs as fast as possible\n"
               "  -s, --size                SDU size (B)\n"
               "  -r, --rate                Rate (b/s)\n"
               "      --sleep               Sleep in between sending SDUs\n"
               "\n\n"
               "      --help                Display this help text and exit\n");
}

int main(int argc, char ** argv)
{
        int    duration = 60;  /* One minute test */
        int    size = 1000;    /* 1000 byte SDUs */
        long   rate = 1000000; /* 1 Mb/s */
        bool   flood = false;
        bool   sleep = false;
        int    ret = 0;
        char * rem = NULL;
        char * s_apn = NULL;

        bool server = false;

        server_settings.interval = 1; /* One second reporting interval */
        server_settings.timeout  = 1;

        argc--;
        argv++;
        while (argc > 0) {
                if (strcmp(*argv, "-i") == 0 ||
                    strcmp(*argv, "--interval") == 0) {
                        server_settings.interval = strtol(*(++argv), &rem, 10);
                        --argc;
                } else if (strcmp(*argv, "-t") == 0 ||
                           strcmp(*argv, "--timeout") == 0) {
                        server_settings.timeout = strtol(*(++argv), &rem, 10);
                        --argc;
                } else if (strcmp(*argv, "-n") == 0 ||
                           strcmp(*argv, "--server_apn") == 0) {
                        s_apn = *(++argv);
                        --argc;
                } else if (strcmp(*argv, "-d") == 0 ||
                           strcmp(*argv, "--duration") == 0) {
                        duration = strtol(*(++argv), &rem, 10);
                        --argc;
                } else if (strcmp(*argv, "-s") == 0 ||
                           strcmp(*argv, "--size") == 0) {
                        size = strtol(*(++argv), &rem, 10);
                        --argc;
                } else if (strcmp(*argv, "-r") == 0 ||
                           strcmp(*argv, "--rate") == 0) {
                        rate = strtol(*(++argv), &rem, 10);
                        if (*rem == 'k')
                                rate *= 1000;
                        if (*rem == 'M')
                                rate *= MILLION;
                        if (*rem == 'G')
                                rate *= BILLION;
                        --argc;
                } else if (strcmp(*argv, "-l") == 0 ||
                           strcmp(*argv, "--listen") == 0) {
                        server = true;
                } else if (strcmp(*argv, "-f") == 0 ||
                           strcmp(*argv, "--flood") == 0) {
                        flood = true;
                } else if (strcmp(*argv, "--sleep") == 0) {
                        sleep = true;
                } else {
                        usage();
                        return 0;
                }
                argc--;
                argv++;
        }

        if (server) {
                ret = server_main();
        } else {
                if (s_apn == NULL) {
                        printf("No server specified.\n");
                        usage();
                        return 0;
                }

                ret = client_main(s_apn, duration, size, rate, flood, sleep);
        }

        return ret;
}
