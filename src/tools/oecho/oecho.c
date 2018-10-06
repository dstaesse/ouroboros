/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * A simple echo application
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#define _POSIX_C_SOURCE 199309L

#include <ouroboros/dev.h>

#include <stdio.h>
#include <string.h>

#define BUF_SIZE 256

static void usage(void)
{
        printf("Usage: oecho [OPTION]...\n"
               "Sends an echo between a server and a client\n\n"
               "  -l, --listen              Run in server mode\n"
               "      --help                Display this help text and exit\n");
}

static int server_main(void)
{
        int     fd = 0;
        char    buf[BUF_SIZE];
        ssize_t count = 0;

        printf("Starting the server.\n");

        while (true) {
                fd = flow_accept(NULL, NULL);
                if (fd < 0) {
                        printf("Failed to accept flow.\n");
                        break;
                }

                printf("New flow.\n");

                count = flow_read(fd, &buf, BUF_SIZE);
                if (count < 0) {
                        printf("Failed to read packet.\n");
                        flow_dealloc(fd);
                        continue;
                }

                printf("Message from client is %.*s.\n", (int) count, buf);

                if (flow_write(fd, buf, count) == -1) {
                        printf("Failed to write packet.\n");
                        flow_dealloc(fd);
                        continue;
                }

                flow_dealloc(fd);
        }

        return 0;
}

static int client_main(void)
{
        int     fd      = 0;
        char    buf[BUF_SIZE];
        char *  message = "Client says hi!";
        ssize_t count   = 0;

        fd = flow_alloc("oecho", NULL, NULL);
        if (fd < 0) {
                printf("Failed to allocate flow.\n");
                return -1;
        }

        if (flow_write(fd, message, strlen(message) + 1) < 0) {
                printf("Failed to write packet.\n");
                flow_dealloc(fd);
                return -1;
        }

        count = flow_read(fd, buf, BUF_SIZE);
        if (count < 0) {
                printf("Failed to read packet.\n");
                flow_dealloc(fd);
                return -1;
        }

        printf("Server replied with %.*s\n", (int) count, buf);

        flow_dealloc(fd);

        return 0;
}

int main(int argc, char ** argv)
{
        int ret = -1;
        bool server = false;

        argc--;
        argv++;
        while (argc > 0) {
                if (strcmp(*argv, "-l") == 0 ||
                    strcmp(*argv, "--listen") == 0) {
                        server = true;
                } else {
                        usage();
                        return 0;
                }
                argc--;
                argv++;
        }

        if (server)
                ret = server_main();
        else
                ret = client_main();

        return ret;
}
