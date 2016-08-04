/*
 * Ouroboros - Copyright (C) 2016
 *
 * CBR traffic generator
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#define _POSIX_C_SOURCE 199506L

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <limits.h>
#include <time.h>
#include <stdbool.h>

#define BUF_SIZE 1500

#include "cbr_client.c"

struct s {
        long interval;
        long timeout;
} server_settings;

#include "cbr_server.c"

static void usage(void)
{
        printf("Usage: cbr [OPTION]...\n"
               "Sends SDU's from client to server at a constant bit rate.\n\n"
               "  -l, --listen              Run in server mode\n"
               "\n"
               "Server options:\n"
               "  -i, --interval            Server report interval (s)\n"
               "  -t, --timeout             Server timeout interval (s)\n"
               "\n"
               "Client options:\n"
               "  -n, --server_apn          Specify the name of the server.\n"
               "  -d, --duration            Duration for sending (s)\n"
               "  -f, --flood               Send SDU's as fast as possible\n"
               "  -s, --size                SDU size (B)\n"
               "  -r, --rate                Rate (b/s)\n"
               "      --sleep               Sleep in between sending sdu's\n"
               "\n\n"
               "      --help                Display this help text and exit\n");
}

int main(int argc, char ** argv)
{
        int    duration = 60;      /* One minute test */
        int    size = 1000;    /* 1000 byte SDU's */
        long   rate = 1000000; /* 1 Mb/s */
        bool   flood = false;
        bool   sleep = false;
        int    ret = 0;
        char * rem = NULL;
        char * s_apn = NULL;

        bool server = false;

        /* FIXME: should be argv[0] */
        ap_init(argv[0]);

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

        ap_fini();

        return ret;
}
