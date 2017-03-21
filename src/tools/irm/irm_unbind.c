/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Unbind names in the processing system
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

#include <stdio.h>

#include <ouroboros/irm.h>

#include "irm_ops.h"
#include "irm_utils.h"

static void usage(void)
{
        printf("Usage: irm unbind [OPERATION]\n"
               "\n"
               "where OPERATION = {ap api ipcp help}\n");
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
        { "ap",   do_unbind_ap },
        { "api",  do_unbind_api },
        { "ipcp", do_unbind_ipcp },
        { "help", do_help },
        { NULL,   NULL }
};

static int do_cmd(const char * argv0, int argc, char ** argv)
{
        const struct cmd * c;

        for (c = cmds; c->cmd; ++c)
                if (!matches(argv0, c->cmd))
                        return c->func(argc, argv);

        fprintf(stderr, "\"%s\" is unknown, try \"irm unbind help\".\n", argv0);

        return -1;
}

int unbind_cmd(int argc, char ** argv)
{
        if (argc < 1) {
                usage();
                return -1;
        }

        return do_cmd(argv[0], argc, argv);
}
