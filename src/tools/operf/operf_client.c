/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Ouroboros ping application
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

bool stop;

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
        struct timespec timeout = {2, 0};

        char buf[OPERF_BUF_SIZE];
        int fd = *((int *) o);
        int msg_len = 0;

        fccntl(fd, FLOWSRCVTIMEO, &timeout);

        while (!stop) {
                msg_len = flow_read(fd, buf, OPERF_BUF_SIZE);
                if (msg_len == -ETIMEDOUT) {
                        printf("Server timed out.\n");
                        stop = true;
                        break;
                }

                if (msg_len != client.size) {
                        printf("Invalid message on fd %d.\n", fd);
                        continue;
                }

                ++client.rcvd;
        }

        return (void *) 0;
}

void * writer(void * o)
{
        int * fdp = (int *) o;
        long gap = client.size * 8.0 * (BILLION / (double) client.rate);

        struct timespec now;
        struct timespec start;
        struct timespec intv = {(gap / BILLION), gap % BILLION};
        struct timespec end = {0, 0};

        char *       buf;
        struct msg * msg;

        buf = malloc(client.size);
        if (buf == NULL)
                return (void *) -ENOMEM;

        if (fdp == NULL) {
                free(buf);
                return (void *) -EINVAL;
        }

        memset(buf, 0, client.size);

        msg = (struct msg *) buf;

        if (client.flood)
                printf("Flooding %s with %d byte packets for %d seconds.\n\n",
                       client.server_name, client.size,
                       client.duration / 1000);
        else
                printf("Sending %d byte packets for %d s to %s "
                       "at %.3lf Mb/s.\n\n",
                       client.size, client.duration / 1000,
                       client.server_name,
                       client.rate / (double) MILLION);

        clock_gettime(CLOCK_REALTIME, &start);
        clock_gettime(CLOCK_REALTIME, &now);

        while (!stop && ts_diff_ms(&start, &now) < client.duration) {
                if (!client.flood) {
                        clock_gettime(CLOCK_REALTIME, &now);
                        ts_add(&now, &intv, &end);
                }

                msg->id = client.sent;

                if (flow_write(*fdp, buf, client.size) < 0) {
                        printf("Failed to send packet.\n");
                        flow_dealloc(*fdp);
                        free(buf);
                        return (void *) -1;
                }

                ++client.sent;

                if (!client.flood) {
                        if (client.sleep)
                                nanosleep(&intv, NULL);
                        else
                                busy_wait_until(&end);
                } else {
                        clock_gettime(CLOCK_REALTIME, &now);
                }
        }

        free(buf);

        printf("Test finished.\n");

        return (void *) 0;
}

int client_main(void)
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

        client.sent = 0;
        client.rcvd = 0;
        stop = false;

        /* FIXME: Allow selecting QoS. */
        fd = flow_alloc(client.server_name, NULL, NULL);
        if (fd < 0) {
                printf("Failed to allocate flow.\n");
                return -1;
        }

        if (client.conf.test_type == TEST_TYPE_BI)
                printf("Doing a bidirectional test.\n");
        else
                printf("Doing a unidirectional test.\n");

        if (flow_write(fd, &client.conf, sizeof(client.conf)) < 0) {
                printf("Failed to send configuration.\n");
                flow_dealloc(fd);
                return -1;
        }

        sleep(1);

        clock_gettime(CLOCK_REALTIME, &tic);

        if (client.conf.test_type == TEST_TYPE_BI)
                pthread_create(&client.reader_pt, NULL, reader, &fd);

        pthread_create(&client.writer_pt, NULL, writer, &fd);
        pthread_join(client.writer_pt, NULL);

        if (client.conf.test_type == TEST_TYPE_BI){
                clock_gettime(CLOCK_REALTIME, &toc);
                pthread_join(client.reader_pt, NULL);

                printf("\n");
                printf("--- %s perf statistics ---\n", client.server_name);
                printf("%ld packets transmitted, ", client.sent);
                printf("%ld received, ", client.rcvd);
                printf("%ld%% packet loss, ", client.sent == 0 ? 0 :
                       100 - ((100 * client.rcvd) / client.sent));
                printf("time: %.3f ms, ", ts_diff_us(&tic, &toc) / 1000.0);
                printf("bandwidth: %.3lf Mb/s.\n",
                       (client.rcvd * client.size * 8)
                       / (double) ts_diff_us(&tic, &toc));
        }

        flow_dealloc(fd);

        return 0;
}
