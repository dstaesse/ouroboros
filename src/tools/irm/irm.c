/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * A tool to instruct the IRM daemon
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#include <ouroboros/irm.h>
#include <ouroboros/errno.h>

#include "irm_ops.h"
#include "irm_utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

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
        { "ipcp",       ipcp_cmd },
        { "bind",       bind_cmd },
        { "unbind",     unbind_cmd },
        { "register",   do_register },
        { "unregister", do_unregister },
        { "help",       do_help },
        { NULL,         NULL }
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

int main(int argc, char ** argv)
{
        int ret = 0;

        if (argc < 2) {
                usage();
                return -1;
        }

        ret = do_cmd(argv[1], argc - 1, argv + 1);

        if (ret == -EIRMD)
                printf("Failed to communicate with the "
                       "Ouroboros IPC Resource Manager daemon.\n");

        if (ret)
                exit(EXIT_FAILURE);

        exit(EXIT_SUCCESS);
}
