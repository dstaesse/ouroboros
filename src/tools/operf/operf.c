/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Ouroboros perf application
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 199506L
#define __XSI_VISIBLE   500

#include <ouroboros/fqueue.h>
#include <ouroboros/dev.h>

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

#define OPERF_BUF_SIZE (1024 * 1024)

#define OPERF_MAX_FLOWS 256

struct c {
        char * s_apn;
        int    size;
        long   rate;
        bool   flood;
        bool   sleep;
        int    duration;

        unsigned long sent;
        unsigned long rcvd;

        pthread_t reader_pt;
        pthread_t writer_pt;
} client;

struct s {
        struct timespec times[OPERF_MAX_FLOWS];
        fset_t *        flows;
        fqueue_t *      fq;
        pthread_mutex_t lock;

        uint8_t buffer[OPERF_BUF_SIZE];
        ssize_t timeout;

        pthread_t cleaner_pt;
        pthread_t accept_pt;
        pthread_t server_pt;
} server;

#include "operf_client.c"
#include "operf_server.c"

static void usage(void)
{
        printf("Usage: operf [OPTION]...\n"
               "Measures bandwidth between a client and a server\n"
               "  -l, --listen              Run in server mode\n"
               "\n"
               "  -n, --server-apn          Name of the operf server\n"
               "  -d, --duration            Test duration (s, default 60)\n"
               "  -r, --rate                Rate (b/s)\n"
               "  -s, --size                Payload size (B, default 1500)\n"
               "  -f, --flood               Send SDUs as fast as possible\n"
               "      --sleep               Sleep in between sending SDUs\n"
               "      --help                Display this help text and exit\n");
}

int main(int argc, char ** argv)
{
        int ret = -1;
        char * rem = NULL;
        bool serv = false;

        argc--;
        argv++;

        client.s_apn = NULL;
        client.size = 1500;
        client.duration = 60000;
        server.timeout = 1000; /* ms */
        client.rate = 1000000;
        client.flood = false;
        client.sleep = false;

        while (argc > 0) {
                if (strcmp(*argv, "-n") == 0 ||
                           strcmp(*argv, "--server_apn") == 0) {
                        client.s_apn = *(++argv);
                        --argc;
                } else if (strcmp(*argv, "-s") == 0 ||
                           strcmp(*argv, "--size") == 0) {
                        client.size = strtol(*(++argv), &rem, 10);
                        --argc;
                } else if (strcmp(*argv, "-d") == 0 ||
                           strcmp(*argv, "--duration") == 0) {
                        client.duration = strtol(*(++argv), &rem, 10) * 1000;
                        --argc;
                } else if (strcmp(*argv, "-r") == 0 ||
                           strcmp(*argv, "--rate") == 0) {
                        client.rate = strtol(*(++argv), &rem, 10);
                        if (*rem == 'k')
                                client.rate *= 1000;
                        if (*rem == 'M')
                                client.rate *= MILLION;
                        if (*rem == 'G')
                                client.rate *= BILLION;
                        --argc;
                } else if (strcmp(*argv, "-f") == 0 ||
                           strcmp(*argv, "--flood") == 0) {
                        client.flood = true;
                } else if (strcmp(*argv, "--sleep") == 0) {
                        client.sleep = true;
                } else if (strcmp(*argv, "-l") == 0 ||
                           strcmp(*argv, "--listen") == 0) {
                        serv = true;
                } else {
                        usage();
                        exit(EXIT_SUCCESS);
                }
                argc--;
                argv++;
        }

        if (serv) {
                ret = server_main();
        } else {
                if (client.s_apn == NULL) {
                        printf("No server specified.\n");
                        usage();
                        exit(EXIT_SUCCESS);
                }
                if (client.size > OPERF_BUF_SIZE) {
                        printf("Packet size truncated to %d bytes.\n",
                               OPERF_BUF_SIZE);
                        client.size = OPERF_BUF_SIZE;
                }

                if (client.size < 64) {
                        printf("Packet size set to 64 bytes.\n");
                        client.size = 64;
                }

                ret = client_main();
        }

        if (ret < 0)
                exit(EXIT_FAILURE);

        exit(EXIT_SUCCESS);
}
