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

#include <ouroboros/dev.h>
#include <ouroboros/fcntl.h>
#include <ouroboros/time_utils.h>

#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <math.h>
#include <errno.h>
#include <float.h>

void shutdown_client(int signo, siginfo_t * info, void * c)
{
        (void) info;
        (void) c;

        switch(signo) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                pthread_cancel(client.reader_pt);
                pthread_cancel(client.writer_pt);
        default:
                return;
        }
}

void * reader(void * o)
{
        struct timespec timeout = {2, 0};
        struct timespec now = {0, 0};

        char buf[OPING_BUF_SIZE];
        struct oping_msg * msg = (struct oping_msg *) buf;
        int fd = *((int *) o);
        int msg_len = 0;
        double ms = 0;
        double d = 0;

        flow_set_timeout(fd, &timeout);

        while (client.rcvd != client.count) {
                msg_len = flow_read(fd, buf, OPING_BUF_SIZE);
                if (msg_len == -ETIMEDOUT)
                        break;

                if (msg_len < 0)
                        continue;

                if (ntohl(msg->type) != ECHO_REPLY) {
                        printf("Invalid message on fd %d.\n", fd);
                        continue;
                }

                if (ntohl(msg->id) >= client.count) {
                        printf("Invalid id.\n");
                        continue;
                }

                ++client.rcvd;

                clock_gettime(CLOCK_MONOTONIC, &now);

                pthread_mutex_lock(&client.lock);
                ms = ts_diff_us(&client.times[ntohl(msg->id)], &now)
                        / 1000.0;
                pthread_mutex_unlock(&client.lock);

                printf("%d bytes from %s: seq=%d time=%.3f ms\n",
                       msg_len,
                       client.s_apn,
                       ntohl(msg->id),
                       ms);

                if (ms < client.rtt_min)
                        client.rtt_min = ms;
                if (ms > client.rtt_max)
                        client.rtt_max = ms;

                d = (ms - client.rtt_avg);
                client.rtt_avg += d / client.rcvd;
                client.rtt_m2 += d * (ms - client.rtt_avg);
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

        if (fdp == NULL)
                return (void *) -EINVAL;

        memset(buf, 0, client.size);

        msg = (struct oping_msg *) buf;

        printf("Pinging %s with %d bytes of data:\n\n",
               client.s_apn, client.size);

        pthread_cleanup_push((void (*) (void *)) free, buf);

        while (client.sent < client.count) {
                nanosleep(&wait, NULL);
                msg->type = htonl(ECHO_REQUEST);
                msg->id = htonl(client.sent);

                clock_gettime(CLOCK_MONOTONIC, &now);

                pthread_mutex_lock(&client.lock);
                client.times[client.sent++] = now;
                pthread_mutex_unlock(&client.lock);

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
        client.times = malloc(sizeof(struct timespec) * client.count);
        if (client.times == NULL) {
                pthread_mutex_unlock(&client.lock);
                return -ENOMEM;
        }

        client.sent = 0;
        client.rcvd = 0;
        client.rtt_min = FLT_MAX;
        client.rtt_max = 0;
        client.rtt_avg = 0;
        client.rtt_m2 = 0;

        pthread_mutex_init(&client.lock, NULL);

        return 0;
}

void client_fini(void)
{
        if (client.times != NULL)
                free(client.times);
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

        if (client_init()) {
                printf("Failed to initialize client.\n");
                return -1;
        }

        fd = flow_alloc(client.s_apn, NULL, NULL);
        if (fd < 0) {
                printf("Failed to allocate flow.\n");
                client_fini();
                return -1;
        }

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
