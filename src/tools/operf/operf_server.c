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

void shutdown_server(int signo, siginfo_t * info, void * c)
{
        (void) info;
        (void) c;

        switch(signo) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                pthread_cancel(server.accept_pt);
        default:
                return;
        }
}

void * cleaner_thread(void * o)
{
        int i = 0;
        struct timespec now = {0, 0};

        (void) o;

        while (true) {
                clock_gettime(CLOCK_REALTIME, &now);
                pthread_mutex_lock(&server.lock);
                for (i = 0; i < OPERF_MAX_FLOWS; ++i)
                        if (fset_has(server.flows, i) &&
                            ts_diff_ms(&server.times[i], &now)
                            > server.timeout) {
                                printf("Flow %d timed out.\n", i);
                                fset_del(server.flows, i);
                                flow_dealloc(i);
                        }

                pthread_mutex_unlock(&server.lock);
                sleep(1);
        }
}

void * server_thread(void *o)
{
        int msg_len = 0;
        struct timespec timeout = {0, 100 * MILLION};
        struct timespec now = {0, 0};
        int fd;

        (void) o;

        while (fevent(server.flows, server.fq, &timeout))
                while ((fd = fqueue_next(server.fq)) >= 0) {
                        msg_len = flow_read(fd, server.buffer, OPERF_BUF_SIZE);
                        if (msg_len < 0)
                                continue;

                        clock_gettime(CLOCK_REALTIME, &now);

                        pthread_mutex_lock(&server.lock);
                        server.times[fd] = now;
                        pthread_mutex_unlock(&server.lock);

                        if (flow_write(fd, server.buffer, msg_len) < 0) {
                                printf("Error writing to flow (fd %d).\n", fd);
                                flow_dealloc(fd);
                        }
                }

        return (void *) 0;
}

void * accept_thread(void * o)
{
        int fd = 0;
        struct timespec now = {0, 0};
        qosspec_t qs;

        (void) o;

        printf("Ouroboros perf server started.\n");

        while (true) {
                fd = flow_accept(&qs, NULL);
                if (fd < 0) {
                        printf("Failed to accept flow.\n");
                        break;
                }

                printf("New flow %d.\n", fd);

                clock_gettime(CLOCK_REALTIME, &now);

                pthread_mutex_lock(&server.lock);
                fset_add(server.flows, fd);
                server.times[fd] = now;
                pthread_mutex_unlock(&server.lock);
        }

        return (void *) 0;
}

int server_main(void)
{
        struct sigaction sig_act;

        memset(&sig_act, 0, sizeof sig_act);
        sig_act.sa_sigaction = &shutdown_server;
        sig_act.sa_flags = 0;

        if (sigaction(SIGINT,  &sig_act, NULL) ||
            sigaction(SIGTERM, &sig_act, NULL) ||
            sigaction(SIGHUP,  &sig_act, NULL) ||
            sigaction(SIGPIPE, &sig_act, NULL)) {
                printf("Failed to install sighandler.\n");
                return -1;
        }

        server.flows = fset_create();
        if (server.flows == NULL)
                return 0;

        server.fq = fqueue_create();
        if (server.fq == NULL) {
                fset_destroy(server.flows);
                return -1;
        }

        pthread_create(&server.cleaner_pt, NULL, cleaner_thread, NULL);
        pthread_create(&server.accept_pt, NULL, accept_thread, NULL);
        pthread_create(&server.server_pt, NULL, server_thread, NULL);

        pthread_join(server.accept_pt, NULL);

        pthread_cancel(server.server_pt);
        pthread_cancel(server.cleaner_pt);

        fset_destroy(server.flows);
        fqueue_destroy(server.fq);

        pthread_join(server.server_pt, NULL);
        pthread_join(server.cleaner_pt, NULL);

        return 0;
}
