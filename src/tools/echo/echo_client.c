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

#include <ouroboros/dev.h>
#include <stdlib.h>

int client_main(void)
{
        int fd = 0;
        int result = 0;
        char buf[BUF_SIZE];
        char * message  = "Client says hi!";
        ssize_t count = 0;

        fd = flow_alloc("echo", NULL);
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

        if (flow_write(fd, message, strlen(message) + 1) == -1) {
                printf("Failed to write SDU.\n");
                flow_dealloc(fd);
                return -1;
        }

        count = flow_read(fd, buf, BUF_SIZE);
        if (count < 0) {
                printf("Failed to read SDU.\n");
                flow_dealloc(fd);
                return -1;
        }

        printf("Server replied with %.*s\n", (int) count, buf);

        flow_dealloc(fd);

        return 0;
}
