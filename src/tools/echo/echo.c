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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 199309L

#include <stdio.h>
#include <string.h>

#define BUF_SIZE 256

#include "echo_client.c"
#include "echo_server.c"

static void usage(void)
{
        printf("Usage: echo-app [OPTION]...\n"
               "Sends an echo between a server and a client\n\n"
               "  -l, --listen              Run in server mode\n"
               "      --help                Display this help text and exit\n");
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
