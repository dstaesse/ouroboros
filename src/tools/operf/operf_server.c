/*
 * Ouroboros - Copyright (C) 2016
 *
 * Ouroboros perf application
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifdef __FreeBSD__
#define __XSI_VISIBLE 500
#endif

#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>

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
                        if (flow_set_has(server.flows, i) &&
                            ts_diff_ms(&server.times[i], &now)
                            > server.timeout) {
                                printf("Flow %d timed out.\n", i);
                                flow_set_del(server.flows, i);
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

        while (flow_event_wait(server.flows, server.fq, &timeout))
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
                fd = flow_accept(NULL, &qs);
                if (fd < 0) {
                        printf("Failed to accept flow.\n");
                        break;
                }

                printf("New flow %d.\n", fd);

                if (flow_alloc_resp(fd, 0)) {
                        printf("Failed to give an allocate response.\n");
                        flow_dealloc(fd);
                        continue;
                }

                clock_gettime(CLOCK_REALTIME, &now);

                pthread_mutex_lock(&server.lock);
                flow_set_add(server.flows, fd);
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

        server.flows = flow_set_create();
        if (server.flows == NULL)
                return 0;

        server.fq = fqueue_create();
        if (server.fq == NULL) {
                flow_set_destroy(server.flows);
                return -1;
        }

        pthread_create(&server.cleaner_pt, NULL, cleaner_thread, NULL);
        pthread_create(&server.accept_pt, NULL, accept_thread, NULL);
        pthread_create(&server.server_pt, NULL, server_thread, NULL);

        pthread_join(server.accept_pt, NULL);

        pthread_cancel(server.server_pt);
        pthread_cancel(server.cleaner_pt);

        flow_set_destroy(server.flows);
        fqueue_destroy(server.fq);

        pthread_join(server.server_pt, NULL);
        pthread_join(server.cleaner_pt, NULL);

        return 0;
}
