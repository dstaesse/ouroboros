/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Ouroboros ping application
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

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
        int deadline_ms = 10000;

        (void) o;

        while (true) {
                clock_gettime(CLOCK_REALTIME, &now);
                pthread_mutex_lock(&server.lock);
                for (i = 0; i < OPING_MAX_FLOWS; ++i)
                        if (fset_has(server.flows, i) &&
                            ts_diff_ms(&server.times[i], &now) > deadline_ms) {
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
        char buf[OPING_BUF_SIZE];
        int msg_len = 0;
        struct oping_msg * msg = (struct oping_msg *) buf;
        struct timespec now = {0, 0};
        struct timespec timeout = {0, 100 * MILLION};
        int fd;

        (void) o;

        while (true) {
                if (fevent(server.flows, server.fq, &timeout) == -ETIMEDOUT)
                        continue;

                while ((fd = fqueue_next(server.fq)) >= 0) {
                        msg_len = flow_read(fd, buf, OPING_BUF_SIZE);
                        if (msg_len < 0)
                                continue;

                        if (ntohl(msg->type) != ECHO_REQUEST) {
                                printf("Invalid message on fd %d.", fd);
                                continue;
                        }

                        clock_gettime(CLOCK_REALTIME, &now);

                        pthread_mutex_lock(&server.lock);
                        server.times[fd] = now;
                        pthread_mutex_unlock(&server.lock);

                        msg->type = htonl(ECHO_REPLY);

                        if (flow_write(fd, buf, msg_len) < 0)
                                printf("Error writing to flow (fd %d).\n", fd);
                }
        }

        return (void *) 0;
}

void * accept_thread(void * o)
{
        int fd;
        struct timespec now;
        qosspec_t qs;

        (void) o;

        printf("Ouroboros ping server started.\n");

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

                fccntl(fd, FLOWSFLAGS, FLOWFNONBLOCK | FLOWFRDWR);
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
