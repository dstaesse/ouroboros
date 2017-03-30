/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * A simple echo application
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

#include <ouroboros/dev.h>

void shutdown_server(int signo)
{
        (void) signo;

        ap_fini();
        exit(EXIT_SUCCESS);
}

int server_main(void)
{
        int    fd = 0;
        char   buf[BUF_SIZE];
        ssize_t count = 0;
        qosspec_t qs;

        printf("Starting the server.\n");

        /* Manual cleanup is required for now */
        if (signal(SIGINT, shutdown_server) == SIG_ERR) {
                printf("Can't install signal handler.\n");
                return -1;
        }

        while (true) {
                fd = flow_accept(&qs, NULL);
                if (fd < 0) {
                        printf("Failed to accept flow.\n");
                        break;
                }

                printf("New flow.\n");

                count = flow_read(fd, &buf, BUF_SIZE);
                if (count < 0) {
                        printf("Failed to read SDU.\n");
                        flow_dealloc(fd);
                        continue;
                }

                printf("Message from client is %.*s.\n", (int) count, buf);

                if (flow_write(fd, buf, count) == -1) {
                        printf("Failed to write SDU.\n");
                        flow_dealloc(fd);
                        continue;
                }

                flow_dealloc(fd);
        }

        return 0;
}
