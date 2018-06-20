/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Ouroboros perf application
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
#define __XSI_VISIBLE   500

#include <ouroboros/dev.h>
#include <ouroboros/fccntl.h>
#include <ouroboros/fqueue.h>

#include "time_utils.h"

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <math.h>
#include <errno.h>
#include <float.h>

#define OPERF_BUF_SIZE (1024 * 1024)

#define OPERF_MAX_FLOWS 256

#define TEST_TYPE_UNI 0
#define TEST_TYPE_BI  1

struct conf {
        uint32_t test_type;
} __attribute__((packed));

struct msg {
        uint32_t id;
} __attribute__((packed));

struct c {
        char * server_name;
        long   rate;
        bool   flood;
        bool   sleep;
        int    duration;
        int    size;

        unsigned long sent;
        unsigned long rcvd;

        pthread_t reader_pt;
        pthread_t writer_pt;

        struct conf conf;
} client;

struct s {
        struct timespec times[OPERF_MAX_FLOWS];
        fset_t *        flows;
        fqueue_t *      fq;
        pthread_mutex_t lock;
        struct conf     conf[OPERF_MAX_FLOWS];

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
               "  -t, --test                The type of test [uni, bi]"
               " (default uni)\n"
               "  -n, --server-name         Name of the operf server\n"
               "  -d, --duration            Test duration (default 60s)\n"
               "  -r, --rate                Rate (b/s)\n"
               "  -s, --size                Payload size (B, default 1500)\n"
               "  -f, --flood               Send SDUs as fast as possible\n"
               "      --sleep               Sleep in between sending SDUs\n"
               "\n"
               "      --help                Display this help text and exit\n");
}

/* Times are in ms. */
static int time_mul(const char * rem)
{
        if (strcmp(rem, "ms") == 0 || strcmp(rem, "") == 0)
                return 1;
        else if(strcmp(rem, "s") == 0)
                return 1000;
        else if (strcmp(rem, "m") == 0)
                return 60 * 1000;
        else if (strcmp(rem, "h") == 0)
                return 60 * 60 * 1000;
        else if (strcmp(rem, "d") == 0)
                return 60 * 60 * 24 * 1000;

        printf("Unknown time unit: %s.\n", rem);

        exit(EXIT_FAILURE);
}

static int rate_mul(const char * rem)
{
        if (strcmp(rem, "k") == 0 || strcmp(rem, "") == 0)
                return 1000;
        else if(strcmp(rem, "M") == 0)
                return MILLION;
        else if (strcmp(rem, "G") == 0)
                return BILLION;

        printf("Unknown rate unit: %s.\n", rem);

        exit(EXIT_FAILURE);
}

int main(int argc, char ** argv)
{
        int    ret       = -1;
        char * rem       = NULL;
        bool   serv      = false;
        char * type      = "uni";

        argc--;
        argv++;

        client.server_name = NULL;
        client.size = 1500;
        client.duration = 60000;
        server.timeout = 1000; /* ms */
        client.rate = 1000000;
        client.flood = false;
        client.sleep = false;

        while (argc > 0) {
                if (strcmp(*argv, "-n") == 0 ||
                           strcmp(*argv, "--server-name") == 0) {
                        client.server_name = *(++argv);
                        --argc;
                } else if (strcmp(*argv, "-s") == 0 ||
                           strcmp(*argv, "--size") == 0) {
                        client.size = strtol(*(++argv), &rem, 10);
                        --argc;
                } else if (strcmp(*argv, "-d") == 0 ||
                           strcmp(*argv, "--duration") == 0) {
                        client.duration = strtol(*(++argv), &rem, 10);
                        client.duration *= time_mul(rem);
                        --argc;
                } else if (strcmp(*argv, "-r") == 0 ||
                           strcmp(*argv, "--rate") == 0) {
                        client.rate = strtol(*(++argv), &rem, 10);
                        client.rate *= rate_mul(rem);
                        --argc;
                } else if (strcmp(*argv, "-f") == 0 ||
                           strcmp(*argv, "--flood") == 0) {
                        client.flood = true;
                } else if (strcmp(*argv, "--sleep") == 0) {
                        client.sleep = true;
                } else if (strcmp(*argv, "-l") == 0 ||
                           strcmp(*argv, "--listen") == 0) {
                        serv = true;
                } else if (strcmp(*argv, "-t") == 0 ||
                           strcmp(*argv, "--test") == 0) {
                        type = *(++argv);
                        --argc;
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
                if (client.server_name == NULL) {
                        printf("No server specified.\n");
                        exit(EXIT_FAILURE);
                }

                if (strcmp(type, "uni") == 0)
                        client.conf.test_type = TEST_TYPE_UNI;
                else if (strcmp(type, "bi") == 0)
                        client.conf.test_type = TEST_TYPE_BI;
                else {
                        printf("Invalid test type.\n");
                        exit(EXIT_FAILURE);
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
