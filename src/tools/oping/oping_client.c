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
#include <ouroboros/errno.h>
#include <ouroboros/time_utils.h>

#ifdef __FreeBSD__
#define __XSI_VISIBLE 500
#endif

#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <math.h>
#include <float.h>

void shutdown_client(int signo, siginfo_t * info, void * c)
{
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

        struct oping_msg * msg;
        char buf[OPING_BUF_SIZE];
        int fd = 0;
        int msg_len = 0;
        float ms = 0;
        float d = 0;

        msg = (struct oping_msg *) buf;

        /* FIXME: use flow timeout option once we have it */
        while(client.rcvd != client.count &&
              (fd = flow_select(&timeout)) != -ETIMEDOUT) {
                flow_cntl(fd, FLOW_F_SETFL, FLOW_O_NONBLOCK);
                while (!((msg_len = flow_read(fd, buf, OPING_BUF_SIZE)) < 0)) {
                        if (msg_len < 0)
                                continue;

                        if (ntohl(msg->type) != ECHO_REPLY) {
                                printf("Invalid message received (%d).\n",
                                       msg->type);
                                continue;
                        }

                        if (ntohl(msg->id) >= client.count) {
                                printf("Invalid id.\n");
                                continue;
                        }

                        ++client.rcvd;

                        clock_gettime(CLOCK_REALTIME, &now);

                        pthread_mutex_lock(&client.lock);
                        ms = ts_diff_us(&client.times[ntohl(msg->id)], &now)
                                /1000.0;
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
                        client.rtt_avg += d  / (float) client.rcvd;
                        client.rtt_m2 += d * (ms - client.rtt_avg);
                }
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
                msg->id = htonl(client.sent);
                if (flow_write(*fdp, buf, client.size) == -1) {
                        printf("Failed to send SDU.\n");
                        flow_dealloc(*fdp);
                        free(buf);
                        return (void *) -1;
                }

                clock_gettime(CLOCK_REALTIME, &now);

                pthread_mutex_lock(&client.lock);
                client.times[client.sent++] = now;
                pthread_mutex_unlock(&client.lock);
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

int client_main()
{
        struct sigaction sig_act;

        struct timespec tic;
        struct timespec toc;

        int fd = flow_alloc(client.s_apn, NULL, NULL);
        if (fd < 0) {
                printf("Failed to allocate flow.\n");
                return -1;
        }

        if (flow_alloc_res(fd)) {
                printf("Flow allocation refused.\n");
                flow_dealloc(fd);
                return -1;
        }

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

        pthread_mutex_init(&client.lock, NULL);
        pthread_mutex_lock(&client.lock);
        client.sent = 0;
        client.rcvd = 0;
        client.rtt_min = FLT_MAX;
        client.rtt_max = 0;
        client.rtt_avg = 0;
        client.rtt_m2 = 0;
        client.times = malloc(sizeof(struct timespec) * client.count);
        if (client.times == NULL) {
                pthread_mutex_unlock(&client.lock);
                return -ENOMEM;
        }

        pthread_mutex_unlock(&client.lock);

        clock_gettime(CLOCK_REALTIME, &tic);

        pthread_create(&client.reader_pt, NULL, reader, NULL);
        pthread_create(&client.writer_pt, NULL, writer, &fd);

        pthread_join(client.writer_pt, NULL);
        pthread_join(client.reader_pt, NULL);

        clock_gettime(CLOCK_REALTIME, &toc);

        printf("\n");
        printf("--- %s ping statistics ---\n", client.s_apn);
        printf("%d SDUs transmitted, ", client.sent);
        printf("%d received, ", client.rcvd);
        printf("%d%% packet loss, ", client.sent == 0 ? 0 :
               100 - ((100 * client.rcvd) / client.sent));
        printf("time: %.3f ms\n", ts_diff_us(&tic, &toc) / 1000.0);

        if (client.rcvd > 0) {
                printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/",
                       client.rtt_min,
                       client.rtt_avg,
                       client.rtt_max);
                if (client.rcvd > 1)
                        printf("%.3f ms\n",
                               sqrt(client.rtt_m2 / (float) (client.rcvd - 1)));
                else
                        printf("NaN ms\n");
        }

        pthread_mutex_lock(&client.lock);
        free(client.times);
        pthread_mutex_unlock(&client.lock);
        pthread_mutex_destroy(&client.lock);

        flow_dealloc(fd);

        return 0;
}
