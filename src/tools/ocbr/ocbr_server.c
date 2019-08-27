/*
 * Ouroboros - Copyright (C) 2016 - 2019
 *
 * A simple CBR generator
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

#include <ouroboros/dev.h>
#include <ouroboros/fccntl.h>

#include <stdbool.h>

#ifdef __FreeBSD__
#define __XSI_VISIBLE 500
#endif

#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#define THREADS_SIZE 10

pthread_t       listen_thread;
pthread_t       threads[THREADS_SIZE];
int             fds[THREADS_SIZE];
int             fds_count = 0;
int             fds_index = 0;
pthread_mutex_t fds_lock;
pthread_cond_t  fds_signal;

static void shutdown_server(int signo, siginfo_t * info, void * c)
{
        (void) info;
        (void) c;

        switch(signo) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                pthread_cancel(listen_thread);
        default:
                return;
        }
}

static void handle_flow(int fd)
{
        int count = 0;
        char buf[BUF_SIZE];

        struct timespec now;
        struct timespec alive;
        struct timespec intv = {server_settings.interval, 0};

        struct timespec iv_start;
        struct timespec iv_end;

        bool stop = false;

        long packets         = 0;
        long packets_intv    = 0;
        long bytes_read      = 0;
        long bytes_read_intv = 0;


        clock_gettime(CLOCK_REALTIME, &iv_start);
        alive = iv_start;
        ts_add(&iv_start, &intv, &iv_end);

        fccntl(fd, FLOWSFLAGS, FLOWFRNOBLOCK | FLOWFRDWR | FLOWFRNOPART);

        while (!stop) {
                clock_gettime(CLOCK_REALTIME, &now);

                count = flow_read(fd, buf, BUF_SIZE);

                if (count > 0) {
                        clock_gettime(CLOCK_REALTIME, &alive);
                        packets++;
                        bytes_read += count;
                }

                if (ts_diff_us(&alive, &now)
                    > server_settings.timeout * MILLION) {
                        printf("Test on flow %d timed out\n", fd);
                        stop = true;
                }

                if (stop || ts_diff_ms(&now, &iv_end) < 0) {
                        long us = ts_diff_us(&iv_start, &now);
                        printf("Flow %4d: %9ld packets (%12ld bytes) in %9ld ms"
                               " => %9.4f pps, %9.4f Mbps\n",
                               fd,
                               packets - packets_intv,
                               bytes_read - bytes_read_intv,
                               us / 1000,
                               ((packets - packets_intv) / (double) us)
                               * MILLION,
                               8 * ((bytes_read - bytes_read_intv)
                                    / (double)(us)));
                        iv_start = iv_end;
                        packets_intv = packets;
                        bytes_read_intv = bytes_read;
                        ts_add(&iv_start, &intv, &iv_end);
                }
        }

        flow_dealloc(fd);
}

static void * worker(void * o)
{
        int cli_fd;

        (void) o;

        while (true) {
                pthread_mutex_lock(&fds_lock);
                pthread_cleanup_push((void(*)(void *)) pthread_mutex_unlock,
                                     (void *) &fds_lock);
                while (fds[fds_index] == -1)
                        pthread_cond_wait(&fds_signal, &fds_lock);

                cli_fd = fds[fds_index];
                fds[fds_index] = -1;

                pthread_cleanup_pop(true);

                handle_flow(cli_fd);

                pthread_mutex_lock(&fds_lock);
                fds_count--;

                pthread_cond_signal(&fds_signal);
                pthread_mutex_unlock(&fds_lock);
        }

        return 0;
}

static void * listener(void * o)
{
        int fd = 0;
        qosspec_t qs;

        (void) o;

        printf("Server started, interval is %ld s, timeout is %ld s.\n",
               server_settings.interval, server_settings.timeout);

        while (true) {
                pthread_mutex_lock(&fds_lock);
                pthread_cleanup_push((void(*)(void *)) pthread_mutex_unlock,
                                     (void *) &fds_lock);

                while (fds_count == THREADS_SIZE) {
                        printf("Can't accept any more flows, waiting.\n");
                        pthread_cond_wait(&fds_signal, &fds_lock);
                }

                pthread_cleanup_pop(true);

                fd = flow_accept(&qs, NULL);
                if (fd < 0) {
                        printf("Failed to accept flow.\n");
                        break;
                }

                printf("New flow.\n");

                pthread_mutex_lock(&fds_lock);

                fds_count++;
                fds_index = (fds_index + 1) % THREADS_SIZE;
                fds[fds_index] = fd;

                pthread_cond_signal(&fds_signal);
                pthread_mutex_unlock(&fds_lock);
        }

        return 0;
}

int server_main(void)
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
                return -1;
        }

        if (pthread_mutex_init(&fds_lock, NULL)) {
                printf("Failed to init mutex.\n");
                exit(EXIT_FAILURE);
        }

        if (pthread_cond_init(&fds_signal, NULL)) {
                printf("Failed to init cond.\n");
                return -1;
        }

        for (i = 0; i < THREADS_SIZE; i++)
                pthread_create(&threads[i], NULL, worker, NULL);

        pthread_create(&listen_thread, NULL, listener, NULL);

        pthread_join(listen_thread, NULL);

        for (i = 0; i < THREADS_SIZE; i++)
                pthread_cancel(threads[i]);

        for (i = 0; i < THREADS_SIZE; i++)
                pthread_join(threads[i], NULL);

        return 0;
}
