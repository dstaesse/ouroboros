/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Ouroboros ping application
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

volatile bool stop;

void shutdown_client(int signo, siginfo_t * info, void * c)
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

void * reader(void * o)
{
        struct timespec timeout = {client.interval / 1000 + 2, 0};
        struct timespec now = {0, 0};
        struct timespec sent;

        char               buf[OPING_BUF_SIZE];
        struct oping_msg * msg = (struct oping_msg *) buf;
        int                fd      = *((int *) o);
        int                msg_len = 0;
        double             ms      = 0;
        double             d       = 0;
        uint32_t           exp_id  = 0;

        fccntl(fd, FLOWSRCVTIMEO, &timeout);

        while (!stop && client.rcvd != client.count) {
                uint32_t id;

                msg_len = flow_read(fd, buf, OPING_BUF_SIZE);
                if (msg_len == -ETIMEDOUT) {
                        printf("Server timed out.\n");
                        stop = true;
                        break;
                }

                if (msg_len < 0)
                        continue;

                if (ntohl(msg->type) != ECHO_REPLY) {
                        printf("Invalid message on fd %d.\n", fd);
                        continue;
                }

                id = (uint32_t) ntohl(msg->id);
                if (id >= client.count) {
                        printf("Invalid id.\n");
                        continue;
                }

                ++client.rcvd;

                clock_gettime(CLOCK_MONOTONIC, &now);

                sent.tv_sec = msg->tv_sec;
                sent.tv_nsec = msg->tv_nsec;

                ms = ts_diff_us(&sent, &now) / 1000.0;

                if (id < exp_id)
                        ++client.ooo;

                if (!client.quiet) {
                        if (client.timestamp) {
                                struct timespec rtc;
                                clock_gettime(CLOCK_REALTIME, &rtc);
                                printf("[%zd.%06zu] ",
                                       (ssize_t) rtc.tv_sec,
                                       (size_t) rtc.tv_nsec / 1000);
                        }

                        printf("%d bytes from %s: seq=%d time=%.3f ms%s\n",
                               msg_len,
                               client.s_apn,
                               ntohl(msg->id),
                               ms,
                               id < exp_id ? " [out-of-order]" : "");
                }

                if (ms < client.rtt_min)
                        client.rtt_min = ms;
                if (ms > client.rtt_max)
                        client.rtt_max = ms;

                d = (ms - client.rtt_avg);
                client.rtt_avg += d / client.rcvd;
                client.rtt_m2 += d * (ms - client.rtt_avg);

                if (id >= exp_id)
                        exp_id = id + 1;
        }

        return (void *) 0;
}

void * writer(void * o)
{
        int * fdp = (int *) o;
        struct timespec now;
        struct timespec wait = {client.interval / 1000,
                                (client.interval % 1000) * MILLION};
        struct oping_msg * msg;
        char * buf = malloc(client.size);

        if (buf == NULL)
                return (void *) -ENOMEM;

        if (fdp == NULL) {
                free(buf);
                return (void *) -EINVAL;
        }

        memset(buf, 0, client.size);

        msg = (struct oping_msg *) buf;

        if (!client.quiet)
                printf("Pinging %s with %d bytes of data (%u packets):\n\n",
                       client.s_apn, client.size, client.count);

        pthread_cleanup_push((void (*) (void *)) free, buf);

        while (!stop && client.sent < client.count) {
                nanosleep(&wait, NULL);

                clock_gettime(CLOCK_MONOTONIC, &now);

                msg->type = htonl(ECHO_REQUEST);
                msg->id = htonl(client.sent++);
                msg->tv_sec = now.tv_sec;
                msg->tv_nsec = now.tv_nsec;

                if (flow_write(*fdp, buf, client.size) == -1) {
                        printf("Failed to send SDU.\n");
                        flow_dealloc(*fdp);
                        free(buf);
                        return (void *) -1;
                }
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

static int client_init(void)
{
        stop = false;
        client.sent = 0;
        client.rcvd = 0;
        client.rtt_min = FLT_MAX;
        client.rtt_max = 0;
        client.rtt_avg = 0;
        client.rtt_m2 = 0;

        return 0;
}

static void client_fini(void)
{
        return;
}

static int client_main(void)
{
        struct sigaction sig_act;

        struct timespec tic;
        struct timespec toc;

        int fd;

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

        if (client_init()) {
                printf("Failed to initialize client.\n");
                return -1;
        }

        fd = flow_alloc(client.s_apn, &client.qs, NULL);
        if (fd < 0) {
                printf("Failed to allocate flow.\n");
                client_fini();
                return -1;
        }

        fccntl(fd, FLOWSFLAGS, FLOWFRDWR | FLOWFRNOPART);

        clock_gettime(CLOCK_REALTIME, &tic);

        pthread_create(&client.reader_pt, NULL, reader, &fd);
        pthread_create(&client.writer_pt, NULL, writer, &fd);

        pthread_join(client.writer_pt, NULL);
        pthread_join(client.reader_pt, NULL);

        clock_gettime(CLOCK_REALTIME, &toc);

        printf("\n");
        printf("--- %s ping statistics ---\n", client.s_apn);
        printf("%d SDUs transmitted, ", client.sent);
        printf("%d received, ", client.rcvd);
        printf("%zd out-of-order, ", client.ooo);
        printf("%.0lf%% packet loss, ", client.sent == 0 ? 0 :
               ceil(100 - (100 * (client.rcvd / (float) client.sent))));
        printf("time: %.3f ms\n", ts_diff_us(&tic, &toc) / 1000.0);

        if (client.rcvd > 0) {
                printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/",
                       client.rtt_min,
                       client.rtt_avg,
                       client.rtt_max);
                if (client.rcvd > 1)
                        printf("%.3f ms\n",
                               sqrt(client.rtt_m2 / (client.rcvd - 1)));
                else
                        printf("NaN ms\n");
        }

        flow_dealloc(fd);

        client_fini();

        return 0;
}
