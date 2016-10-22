/*
 * Ouroboros - Copyright (C) 2016
 *
 * A tool to instruct the IRM daemon
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

#include <ouroboros/irm.h>
#include <stdio.h>
#include <string.h>

#include "irm_ops.h"
#include "irm_utils.h"

static void usage(void)
{
        printf("Usage: irm [OPERATION]\n\n"
               "where OPERATION = {ipcp bind unbind\n"
               "                   register unregister\n");
}

static int do_help(int argc, char **argv)
{
        (void) argc;
        (void) argv;

        usage();
        return 0;
}

static const struct cmd {
        const char * cmd;
        int (* func)(int argc, char ** argv);
} cmds[] = {
        { "ipcp",            ipcp_cmd },
        { "bind",            bind_cmd },
        { "unbind",          unbind_cmd },
        { "register",        do_register },
        { "unregister",      do_unregister },
        { "help",            do_help },
        { 0 }
};

static int do_cmd(const char * argv0,
                  int argc,
                  char ** argv)
{
        const struct cmd * c;

        for (c = cmds; c->cmd; ++c) {
                if (matches(argv0, c->cmd) == 0)
                        return c->func(argc - 1, argv + 1);
        }

        fprintf(stderr, "\"%s\" is unknown, try \"irm help\".\n", argv0);

        return -1;
}

int main(int argc, char ** argv) {

        if (argc < 2) {
                usage();
                return -1;
        }

        return do_cmd(argv[1], argc - 1, argv + 1);
}
