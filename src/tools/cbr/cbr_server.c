/*
 * Ouroboros - Copyright (C) 2016
 *
 * A simple CBR generator
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

#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#include <ouroboros/dev.h>
#include <ouroboros/time_utils.h>

#define DIF_NAME "*"


void shutdown_server(int signo)
{
        char * dif = DIF_NAME;

        if (ap_unreg(&dif, 1)) {
                printf("Failed to unregister application.\n");
                ap_fini();
                exit(EXIT_FAILURE);
        }

        ap_fini();
        exit(EXIT_SUCCESS);
}

void * handleflow(void * o)
{
        ssize_t count = 0;
        int fd = *((int *) o);
        char buf[BUF_SIZE];

        struct timespec now;
        struct timespec alive;
        struct timespec intv = {server_settings.interval, 0};

        struct timespec iv_start;
        struct timespec iv_end;

        bool stop = false;

        long sdus            = 0;
        long sdus_intv       = 0;
        long bytes_read      = 0;
        long bytes_read_intv = 0;


        clock_gettime(CLOCK_REALTIME, &iv_start);
        alive = iv_start;
        ts_add(&iv_start, &intv, &iv_end);

        flow_cntl(fd, FLOW_F_SETFL, FLOW_O_NONBLOCK);

        while (!stop) {
                clock_gettime(CLOCK_REALTIME, &now);

                count = flow_read(fd, buf, BUF_SIZE);

                if (count > 0) {
                        clock_gettime(CLOCK_REALTIME, &alive);
                        sdus++;
                        bytes_read += count;
                }

                if (ts_diff_us(&alive, &now)
                    > server_settings.timeout * MILLION) {
                        printf("Test on flow %d timed out\n", fd);
                        stop = true;
                }

                if (stop || ts_diff_ms(&now, &iv_end) < 0) {
                        long us = ts_diff_us(&iv_start, &now);
                        printf("Flow %4d: %9ld SDUs (%12ld bytes) in %9ld ms"
                               " => %9.4f p/s, %9.4f Mb/s\n",
                               fd,
                               sdus-sdus_intv,
                               bytes_read-bytes_read_intv,
                               us / 1000,
                               ((sdus-sdus_intv) / (float) us) * MILLION,
                               8 * (bytes_read-bytes_read_intv)
                               / (float)(us));
                        iv_start=iv_end;
                        sdus_intv = sdus;
                        bytes_read_intv = bytes_read;
                        ts_add(&iv_start, &intv, &iv_end);
                }
        }

        return 0;
}

int server_main()
{
        int    server_fd = 0;
        int    client_fd = 0;

        char * dif         = DIF_NAME;
        char * client_name = NULL;

        int i = 0;

        pthread_t * threads = malloc(sizeof(*threads) * 10);
        if (threads == NULL)
                EXIT_FAILURE;

        printf("Server started, interval is %ld s, timeout is %ld s.\n",
               server_settings.interval, server_settings.timeout);

        /* Manual cleanup is required for now */
        if (signal(SIGINT, shutdown_server) == SIG_ERR) {
                printf("Can't install signal handler.\n");
                return -1;
        }

        if (ap_init(SERVER_AP_NAME)) {
                printf("Failed to init AP.\n");
                return -1;
        }

        server_fd = ap_reg(&dif, 1);
        if (server_fd < 0) {
                printf("Failed to register application.\n");
                ap_fini();
                return -1;
        }

        while (true) {
                client_fd = flow_accept(server_fd,
                                        &client_name, NULL);
                if (client_fd < 0) {
                        printf("Failed to accept flow.\n");
                        break;
                }

                printf("New flow from %s.\n", client_name);

                if (flow_alloc_resp(client_fd, 0)) {
                        printf("Failed to give an allocate response.\n");
                        flow_dealloc(client_fd);
                        continue;
                }

                if (i < 10) {
                        pthread_create(&threads[i++],
                                       NULL,
                                       handleflow,
                                       &client_fd);
                }
        }

        ap_fini();

        return 0;
}
