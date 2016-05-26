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

int client_main(int duration, int size, long rate)
{
        int fd = 0;
        int result = 0;
        bool stop = false;
        char buf[size];
        long seqnr = 0;
        unsigned long gap = size * 8 * (BILLION / rate); /* ns */

        struct timespec start;
        struct timespec end;
        struct timespec interval = {(gap / BILLION), gap % BILLION};
        int ms;

        if (ap_init(CLIENT_AP_NAME)) {
                printf("Failed to init AP.\n");
                return -1;
        }

        printf("Client started, duration %d, rate %lu b/s, size %d B.\n",
                duration, rate, size);

        fd = flow_alloc(SERVER_AP_NAME, NULL, NULL);
        if (fd < 0) {
                printf("Failed to allocate flow.\n");
                ap_fini();
                return -1;
        }

        result = flow_alloc_res(fd);
        if (result < 0) {
                printf("Flow allocation refused.\n");
                flow_dealloc(fd);
                ap_fini();
                return -1;
        }

        clock_gettime(CLOCK_REALTIME, &start);
        while (!stop) {
                memcpy(buf, &seqnr, sizeof(seqnr));

                if (flow_write(fd, buf, size) == -1) {
                        printf("Failed to write SDU.\n");
                        stop = true;
                        continue;
                }

                nanosleep(&interval, NULL);

                seqnr++;

                clock_gettime(CLOCK_REALTIME, &end);

                if (duration != 0
                    && ts_diff_us(&start, &end) / MILLION >= (long) duration)
                        stop = true;
        }

        clock_gettime(CLOCK_REALTIME, &end);

        ms = ts_diff_ms(&start, &end);

        printf("sent statistics: "
               "%9ld SDUs, %12ld bytes in %9d ms, %4.4f Mb/s\n",
               seqnr, seqnr * size, ms, (seqnr * size * 8.0)/(ms * 1000));

        flow_dealloc(fd);

        ap_fini();

        return 0;
}
