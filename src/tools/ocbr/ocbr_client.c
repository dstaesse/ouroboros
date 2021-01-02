/*
 * Ouroboros - Copyright (C) 2016 - 2021
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

#include <signal.h>

volatile bool stop;

static void shutdown_client(int signo, siginfo_t * info, void * c)
{
        (void) info;
        (void) c;

        switch(signo) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                stop = true;
        default:
                return;
        }
}

static void busy_wait_until(const struct timespec * deadline)
{
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        while (now.tv_sec < deadline->tv_sec)
                clock_gettime(CLOCK_REALTIME, &now);
        while (now.tv_sec == deadline->tv_sec
               && now.tv_nsec < deadline->tv_nsec)
                clock_gettime(CLOCK_REALTIME, &now);
}

int client_main(char * server,
                int duration,
                int size,
                long rate,
                bool flood,
                bool sleep)
{
        struct sigaction sig_act;

        int fd = 0;
        char buf[BUF_SIZE];
        long seqnr = 0;
        long gap = size * 8.0 * (BILLION / (double) rate);

        struct timespec start;
        struct timespec end;
        struct timespec intv = {(gap / BILLION), gap % BILLION};
        int ms;

        stop = false;

        memset(&sig_act, 0, sizeof sig_act);
        sig_act.sa_sigaction = &shutdown_client;
        sig_act.sa_flags = 0;

        if (sigaction(SIGINT,  &sig_act, NULL) ||
            sigaction(SIGTERM, &sig_act, NULL) ||
            sigaction(SIGHUP,  &sig_act, NULL) ||
            sigaction(SIGPIPE, &sig_act, NULL)) {
                printf("Failed to install sighandler.\n");
                return -1;
        }

        printf("Client started, duration %d, rate %lu b/s, size %d B.\n",
               duration, rate, size);

        fd = flow_alloc(server, NULL, NULL);
        if (fd < 0) {
                printf("Failed to allocate flow.\n");
                return -1;
        }

        clock_gettime(CLOCK_REALTIME, &start);
        if (!flood) {
                while (!stop) {
                        clock_gettime(CLOCK_REALTIME, &end);
                        ts_add(&end, &intv, &end);
                        memcpy(buf, &seqnr, sizeof(seqnr));

                        if (flow_write(fd, buf, size) < 0) {
                                stop = true;
                                continue;
                        }

                        if (sleep)
                                nanosleep(&intv, NULL);
                        else
                                busy_wait_until(&end);

                        ++seqnr;

                        if (ts_diff_us(&start, &end) / MILLION >= duration)
                                stop = true;
                }
        } else { /* flood */
                while (!stop) {
                        clock_gettime(CLOCK_REALTIME, &end);
                        if (flow_write(fd, buf, size) < 0) {
                                stop = true;
                                continue;
                        }

                        ++seqnr;

                        if (ts_diff_us(&start, &end) / MILLION
                            >= (long) duration)
                                stop = true;
                }

        }

        clock_gettime(CLOCK_REALTIME, &end);

        ms = ts_diff_ms(&start, &end);

        printf("sent statistics: "
               "%9ld packets, %12ld bytes in %9d ms, %4.4f Mb/s\n",
               seqnr, seqnr * size, ms, (seqnr / (ms * 1000.0)) * size * 8.0);

        flow_dealloc(fd);

        return 0;
}
