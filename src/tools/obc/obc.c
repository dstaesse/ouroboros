/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * A simple broadcast application
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
#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 256

static void usage(void)
{
        printf("Usage: obc [OPTION]...\n"
               "Sends a message to a broadcast network\n\n"
               "  -n --name                 Name of the broadcast layer\n"
               "  -m --message              A message to send\n"
               "  [-l, --listen             Listen mode]\n"
               "      --help                Display this help text and exit\n");
}

static int reader_main(const char * dst)
{
        int    fd;
        char   buf[BUF_SIZE];

        printf("Starting a reader.\n");

        fd = flow_join(dst, NULL, NULL);
        if (fd < 0) {
                printf("Failed to join broadcast.\n");
                return -1;
        }

        printf("New flow.\n");

        while (true) {
                ssize_t count = flow_read(fd, &buf, BUF_SIZE);
                if (count < 0) {
                        printf("Failed to read.\n");
                        flow_dealloc(fd);
                        break;
                }

                printf("Message is %.*s.\n", (int) count, buf);
        }

        return 0;
}

static int writer_main(const char * dst,
                       const char * message)
{
        int     fd  = 0;
        size_t  len = strlen(message) + 1;

        fd = flow_join(dst, NULL, NULL);
        if (fd < 0) {
                printf("Failed to join broadcast.\n");
                return -1;
        }

        if (flow_write(fd, message, len) < 0) {
                printf("Failed to write packet.\n");
                flow_dealloc(fd);
                return -1;
        }

        flow_dealloc(fd);

        return 0;
}

int main(int     argc,
         char ** argv)
{
        int    ret    = -1;
        bool   reader = false;
        char * name   = NULL;
        char * msg    = "Ouroboros multicast rocks!";

        argc--;
        argv++;
        while (argc > 0) {
                if (strcmp(*argv, "-l") == 0 ||
                    strcmp(*argv, "--listen") == 0) {
                        reader = true;
                } else if (strcmp(*argv, "-n") == 0 ||
                           strcmp(*argv, "--name") == 0) {
                        name = *(argv + 1);
                        argc--;
                        argv++;
                } else if (strcmp(*argv, "-m") == 0 ||
                           strcmp(*argv, "--message") == 0) {
                        msg = *(argv + 1);
                        argc--;
                        argv++;
                } else {
                        usage();
                        return 0;
                }
                argc--;
                argv++;
        }

        if (name == NULL) {
                printf("Please specify a name.\n\n");
                usage();
                exit(EXIT_FAILURE);
        }

        if (reader)
                ret = reader_main(name);
        else
                ret = writer_main(name, msg);

        return ret;
}
