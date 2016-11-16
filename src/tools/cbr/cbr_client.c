/*
 * Ouroboros - Copyright (C) 2016
 *
 * A simple CBR generator
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
#include <ouroboros/time_utils.h>

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
        int fd = 0;
        int result = 0;
        bool stop = false;
        char buf[size];
        long seqnr = 0;
        long gap = size * 8.0 * (BILLION / (double) rate);

        struct timespec start;
        struct timespec end;
        struct timespec intv = {(gap / BILLION), gap % BILLION};
        int ms;

        printf("Client started, duration %d, rate %lu b/s, size %d B.\n",
               duration, rate, size);

        fd = flow_alloc(server, NULL, NULL);
        if (fd < 0) {
                printf("Failed to allocate flow.\n");
                return -1;
        }

        result = flow_alloc_res(fd);
        if (result < 0) {
                printf("Flow allocation refused.\n");
                flow_dealloc(fd);
                return -1;
        }

        clock_gettime(CLOCK_REALTIME, &start);
        if (!flood) {
                while (!stop) {
                        clock_gettime(CLOCK_REALTIME, &end);
                        ts_add(&end, &intv, &end);
                        memcpy(buf, &seqnr, sizeof(seqnr));

                        if (flow_write(fd, buf, size) == -1) {
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
                        if (flow_write(fd, buf, (size_t) size) == -1) {
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
               "%9ld SDUs, %12ld bytes in %9d ms, %4.4f Mb/s\n",
               seqnr, seqnr * size, ms, (seqnr / (ms * 1000.0)) * size * 8.0);

        flow_dealloc(fd);

        return 0;
}
