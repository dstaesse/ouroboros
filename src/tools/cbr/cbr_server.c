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

#define THREADS_SIZE 10

pthread_t       listen_thread;
pthread_t       threads[THREADS_SIZE];
int             fds[THREADS_SIZE];
int             fds_count = 0;
int             fds_index = 0;
pthread_mutex_t fds_lock;
pthread_cond_t  fds_signal;

void shutdown_server(int signo, siginfo_t * info, void * c)
{
        int i;

        switch(signo) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                pthread_cancel(listen_thread);

                for (i = 0; i < THREADS_SIZE; i++) {
                        pthread_cancel(threads[i]);
                }

        default:
                return;
        }
}

void handle_flow(int fd)
{
        ssize_t count = 0;
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
}

void * worker(void * o)
{
        int cli_fd;

        while (true) {
                pthread_mutex_lock(&fds_lock);
                pthread_cleanup_push((void(*)(void *)) pthread_mutex_unlock,
                                     (void *) &fds_lock);
                while (fds[fds_index] == -1) {
                        pthread_cond_wait(&fds_signal, &fds_lock);
                }

                cli_fd = fds[fds_index];
                fds[fds_index] = -1;
                pthread_cleanup_pop(1);

                handle_flow(cli_fd);

                pthread_mutex_lock(&fds_lock);
                fds_count--;
                pthread_mutex_unlock(&fds_lock);
        }

        return 0;
}

void * listener(void * o)
{
        int client_fd = 0;
        int response = 0;

        printf("Server started, interval is %ld s, timeout is %ld s.\n",
               server_settings.interval, server_settings.timeout);

        while (true) {
                client_fd = flow_accept(NULL);
                if (client_fd < 0) {
                        printf("Failed to accept flow.\n");
                        break;
                }

                printf("New flow.\n");

                pthread_mutex_lock(&fds_lock);

                response = (fds_count < THREADS_SIZE) ? 0 : -1;

                if (flow_alloc_resp(client_fd, response)) {
                        printf("Failed to give an allocate response.\n");
                        flow_dealloc(client_fd);
                        pthread_mutex_unlock(&fds_lock);
                        continue;
                }

                if (response) {
                        printf("Can't accept any more flows, denying.\n");
                        continue;
                }

                fds_count++;
                fds_index = (fds_index + 1) % THREADS_SIZE;
                fds[fds_index] = client_fd;

                pthread_mutex_unlock(&fds_lock);
                pthread_cond_signal(&fds_signal);
        }

        return 0;
}

int server_main()
{
        struct sigaction sig_act;
        int i;

        memset(&sig_act, 0, sizeof sig_act);
        sig_act.sa_sigaction = &shutdown_server;
        sig_act.sa_flags = 0;

        for (i = 0; i < THREADS_SIZE; i++)
                fds[i] = -1;

        if (sigaction(SIGINT,  &sig_act, NULL) ||
            sigaction(SIGTERM, &sig_act, NULL) ||
            sigaction(SIGHUP,  &sig_act, NULL) ||
            sigaction(SIGPIPE, &sig_act, NULL)) {
                printf("Failed to install sighandler.\n");
                exit(EXIT_FAILURE);
        }

        if (pthread_mutex_init(&fds_lock, NULL)) {
                printf("Failed to init mutex.\n");
                exit(EXIT_FAILURE);
        }

        if (pthread_cond_init(&fds_signal, NULL)) {
                printf("Failed to init cond.\n");
                exit(EXIT_FAILURE);
        }

        for (i = 0; i < THREADS_SIZE; i++) {
                pthread_create(&threads[i], NULL,
                               worker, NULL);
        }

        pthread_create(&listen_thread, NULL,
                       listener, NULL);

        pthread_join(listen_thread, NULL);

        for (i = 0; i < THREADS_SIZE; i++) {
                pthread_join(threads[i], NULL);
        }

        return 0;
}
