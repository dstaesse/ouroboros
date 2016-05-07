/*
 * Ouroboros - Copyright (C) 2016
 *
 * A simple echo application
 *
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

#include <ouroboros/config.h>

#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

#include <ouroboros/dev.h>

#ifdef OUROBOROS_CONFIG_DEBUG
 #define OUROBOROS_PREFIX "echo-server"
 #include <ouroboros/logs.h>
#endif

#define DIF_NAME "*"

void shutdown_server(int signo)
{
        char * dif = DIF_NAME;

        if (ap_unreg(&dif, 1)) {
                printf("Failed to unregister application.\n");
                ap_fini();
                exit(EXIT_FAILURE);
        }

        ap_fini();
        exit(EXIT_SUCCESS);
}

int server_main()
{
        int    server_fd = 0;
        int    client_fd = 0;
        char * dif = DIF_NAME;
        char * client_name = NULL;
        char   buf[BUF_SIZE];
        ssize_t count = 0;

        printf("Starting the server.\n");

        /* Manual cleanup is required for now */
        if (signal(SIGINT, shutdown_server) == SIG_ERR) {
                printf("Can't install signal handler.\n");
                return -1;
        }

        if(ap_init(SERVER_AP_NAME)) {
                return -1;
        }

        server_fd = ap_reg(&dif, 1);
        if (server_fd < 0) {
                printf("Failed to register application.\n");
                ap_fini();
                return -1;
        }

        while (true) {
                client_fd = flow_accept(server_fd,
                                        &client_name, NULL);
                if (client_fd < 0) {
                        printf("Failed to accept flow.\n");
                        break;
                }

                printf("New flow from %s.\n", client_name);

                if (flow_alloc_resp(client_fd, 0)) {
                        printf("Failed to give an allocate response.\n");
                        flow_dealloc(client_fd);
                        continue;
                }

                count = flow_read(client_fd, (void **) &buf, BUF_SIZE);
                if (count < 0) {
                        printf("Failed to read SDU.\n");
                        flow_dealloc(client_fd);
                        continue;
                }

                printf("Message from client is %.*s.\n", (int) count, buf);

                if (flow_write(client_fd, buf, count) == -1) {
                        printf("Failed to write SDU.\n");
                        flow_dealloc(client_fd);
                        continue;
                }

                flow_dealloc(client_fd);
        }

        ap_fini();

        return 0;
}
