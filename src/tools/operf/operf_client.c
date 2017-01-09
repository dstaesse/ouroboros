/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Ouroboros ping application
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

#include <ouroboros/dev.h>
#include <ouroboros/fcntl.h>
#include <ouroboros/time_utils.h>

#ifdef __FreeBSD__
#define __XSI_VISIBLE 500
#endif

#include <signal.h>
#include <stdlib.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <math.h>
#include <errno.h>
#include <float.h>

static void busy_wait_until(const struct timespec * deadline)
{
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);
        while (now.tv_sec < deadline->tv_sec)
                clock_gettime(CLOCK_REALTIME, &now);
        while (now.tv_sec == deadline->tv_sec
               && now.tv_nsec < deadline->tv_nsec)
                clock_gettime(CLOCK_REALTIME, &now);
        pthread_testcancel();
}

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

        char buf[OPERF_BUF_SIZE];
        int fd = *((int *) o);
        int msg_len = 0;

        flow_set_timeout(fd, &timeout);

        while ((msg_len = flow_read(fd, buf, OPERF_BUF_SIZE)) != -ETIMEDOUT) {
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

        char * buf = malloc(client.size);
        if (buf == NULL)
                return (void *) -ENOMEM;

        if (fdp == NULL)
                return (void *) -EINVAL;

        memset(buf, 0, client.size);

        if (client.flood)
                printf("Flooding %s with %d byte SDUs for %d seconds.\n\n",
                       client.s_apn, client.size, client.duration / 1000);
        else
                printf("Sending %d byte SDUs for %d s to %s at %.3lf Mb/s.\n\n",
                       client.size, client.duration / 1000, client.s_apn,
                       client.rate / (double) MILLION);

        clock_gettime(CLOCK_REALTIME, &start);
        clock_gettime(CLOCK_REALTIME, &now);

        pthread_cleanup_push((void (*) (void *)) free, buf);

        if (client.flood) {
                while (ts_diff_ms(&start, &now) < client.duration) {
                        if (flow_write(*fdp, buf, client.size) == -1) {
                                printf("Failed to send SDU.\n");
                                flow_dealloc(*fdp);
                                free(buf);
                                return (void *) -1;
                        }

                        ++client.sent;

                        clock_gettime(CLOCK_REALTIME, &now);
                }
        } else {
                while (ts_diff_ms(&start, &now) < client.duration) {
                        clock_gettime(CLOCK_REALTIME, &now);
                        ts_add(&now, &intv, &end);

                        if (flow_write(*fdp, buf, client.size) == -1) {
                                printf("Failed to send SDU.\n");
                                flow_dealloc(*fdp);
                                free(buf);
                                return (void *) -1;
                        }

                        ++client.sent;
                        if (client.sleep)
                                nanosleep(&intv, NULL);
                        else
                                busy_wait_until(&end);
                }
        }

        pthread_cleanup_pop(true);

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

        fd = flow_alloc(client.s_apn, NULL, NULL);
        if (fd < 0) {
                printf("Failed to allocate flow.\n");
                return -1;
        }

        if (flow_alloc_res(fd)) {
                printf("Flow allocation refused.\n");
                flow_dealloc(fd);
                return -1;
        }

        clock_gettime(CLOCK_REALTIME, &tic);

        pthread_create(&client.reader_pt, NULL, reader, &fd);
        pthread_create(&client.writer_pt, NULL, writer, &fd);

        pthread_join(client.writer_pt, NULL);

        clock_gettime(CLOCK_REALTIME, &toc);

        pthread_join(client.reader_pt, NULL);

        printf("\n");
        printf("--- %s perf statistics ---\n", client.s_apn);
        printf("%ld SDUs transmitted, ", client.sent);
        printf("%ld received, ", client.rcvd);
        printf("%ld%% packet loss, ", client.sent == 0 ? 0 :
               100 - ((100 * client.rcvd) / client.sent));
        printf("time: %.3f ms, ", ts_diff_us(&tic, &toc) / 1000.0);
        printf("bandwidth: %.3lf Mb/s.\n",
               (client.rcvd * client.size * 8)
               / (double) ts_diff_us(&tic, &toc));

        flow_dealloc(fd);

        return 0;
}
