/*
 * Ouroboros - Copyright (C) 2016
 *
 * Ouroboros ping application
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

#include <ouroboros/dev.h>

#ifdef __FreeBSD__
#define __XSI_VISIBLE 500
#endif

#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>

void shutdown_server(int signo, siginfo_t * info, void * c)
{
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

        while (true) {
                clock_gettime(CLOCK_REALTIME, &now);
                pthread_mutex_lock(&server.lock);
                for (i = 0; i < OPING_MAX_FLOWS; ++i)
                        if (ts_diff_ms(&server.times[i], &now) > deadline_ms)
                                flow_dealloc(i);

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

        while (true) {

                int fd = flow_select(NULL);
                while (!((msg_len = flow_read(fd, buf, OPING_BUF_SIZE)) < 0)) {
                        if (msg_len < 0)
                                continue;

                        if (ntohl(msg->type) != ECHO_REQUEST) {
                                printf("Invalid message received.\n");
                                continue;
                        }

                        clock_gettime(CLOCK_REALTIME, &now);

                        pthread_mutex_lock(&server.lock);
                        server.times[fd] = now;
                        pthread_mutex_unlock(&server.lock);

                        msg->type = htonl((uint32_t) ECHO_REPLY);

                        if (flow_write(fd, buf, msg_len) < 0) {
                                printf("Error writing to flow (fd %d).\n", fd);
                                flow_dealloc(fd);
                        }
                }
        }

        return (void *) 0;
}

void * accept_thread(void * o)
{
        int fd = 0;
        struct timespec now = {0, 0};

        printf("Ouroboros ping server started.\n");

        while (true) {
                fd = flow_accept(NULL);
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
                server.times[fd] = now;
                pthread_mutex_unlock(&server.lock);

                flow_cntl(fd, FLOW_F_SETFL, FLOW_O_NONBLOCK);
        }

        return (void *) 0;
}

int server_main()
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

        pthread_create(&server.cleaner_pt, NULL, cleaner_thread, NULL);
        pthread_create(&server.accept_pt, NULL, accept_thread, NULL);
        pthread_create(&server.server_pt, NULL, server_thread, NULL);

        pthread_join(server.accept_pt, NULL);

        pthread_cancel(server.server_pt);
        pthread_cancel(server.cleaner_pt);

        pthread_join(server.server_pt, NULL);
        pthread_join(server.cleaner_pt, NULL);

        return 0;
}
