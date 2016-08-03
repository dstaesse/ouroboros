/*
 * Ouroboros - Copyright (C) 2016
 *
 * Ouroboros ping application
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
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>

#define OPING_BUF_SIZE 1500

#define ECHO_REQUEST 0
#define ECHO_REPLY 1

#define OPING_MAX_FLOWS 256

struct c {
        char * s_apn;
        int    interval;
        int    count;
        int    size;

        /* stats */
        int    sent;
        int    rcvd;
        float  rtt_min;
        float  rtt_max;
        float  rtt_avg;
        float  rtt_m2;

        /* needs locking */
        struct timespec * times;
        pthread_mutex_t lock;

        pthread_t reader_pt;
        pthread_t writer_pt;
} client;

struct s {
        struct timespec times[OPING_MAX_FLOWS];
        pthread_mutex_t lock;

        pthread_t cleaner_pt;
        pthread_t accept_pt;
        pthread_t server_pt;
} server;

struct oping_msg {
        uint32_t type;
        uint32_t id;
};


#include "oping_client.c"
#include "oping_server.c"

static void usage()
{
        printf("Usage: oping [OPTION]...\n"
               "Checks liveness between a client and a server\n"
               "and reports the Round Trip Time (RTT)\n\n"
               "  -l, --listen              Run in server mode\n"
               "\n"
               "  -c, --count               Number of packets (default 1000)\n"
               "  -i, --interval            Interval (ms, default 1000)\n"
               "  -n, --server-apn          Name of the oping server\n"
               "  -s, --size                Payload size (b, default 64)\n"
               "      --help                Display this help text and exit\n");
}

int main(int argc, char ** argv)
{
        int ret = -1;
        char * rem = NULL;
        bool serv = false;

        if (ap_init(argv[0])) {
                printf("Failed to init AP.\n");
                exit(EXIT_FAILURE);
        }

        argc--;
        argv++;

        client.s_apn = NULL;
        client.interval = 1000;
        client.size = 64;
        client.count = 1000;

        while (argc > 0) {
                if (strcmp(*argv, "-i") == 0 ||
                    strcmp(*argv, "--interval") == 0) {
                        client.interval = strtol(*(++argv), &rem, 10);
                        --argc;
                } else if (strcmp(*argv, "-n") == 0 ||
                           strcmp(*argv, "--server_apn") == 0) {
                        client.s_apn = *(++argv);
                        --argc;
                } else if (strcmp(*argv, "-c") == 0 ||
                           strcmp(*argv, "--count") == 0) {
                        client.count = strtol(*(++argv), &rem, 10);
                        --argc;
                } else if (strcmp(*argv, "-s") == 0 ||
                           strcmp(*argv, "--size") == 0) {
                        client.size = strtol(*(++argv), &rem, 10);
                        --argc;
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
                if (client.interval > 10000) {
                        printf("Ping interval truncated to 10s.\n");
                        client.interval = 10000;
                }
                if (client.size > OPING_BUF_SIZE) {
                        printf("Packet size truncated to 1500 bytes.\n");
                        client.size = 1500;
                }

                if (client.size < 2) {
                        printf("Packet size set to 64 bytes.\n");
                        client.size = 64;
                }

                if (client.count > 1000000) {
                        printf("Count truncated to 1 million SDUs.\n");
                        client.count = 1000000;
                }

                ret = client_main();
        }

        ap_fini();

        if (ret < 0)
                exit(EXIT_FAILURE);

        exit(EXIT_SUCCESS);
}
