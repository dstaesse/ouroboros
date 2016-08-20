/*
 * Ouroboros - Copyright (C) 2016
 *
 * Bind names in the processing system
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#include <stdio.h>

#include <ouroboros/irm.h>

#include "irm_ops.h"
#include "irm_utils.h"

static void usage()
{
        printf("Usage: irm bind [OPERATION]\n"
               "where OPERATION = {ap api ipcp help}\n");
}

static int do_help(int argc, char **argv)
{
        usage();
        return 0;
}

static const struct cmd {
        const char * cmd;
        int (* func)(int argc, char ** argv);
} cmds[] = {
        { "ap",   do_bind_ap },
        { "api",  do_bind_api },
        { "ipcp", do_bind_ipcp },
        { "help", do_help },
        { 0 }
};

static int do_cmd(const char * argv0,
                  int argc,
                  char ** argv)
{
        const struct cmd * c;

        for (c = cmds; c->cmd; ++c) {
                if (!matches(argv0, c->cmd))
                        return c->func(argc, argv);
        }

        fprintf(stderr, "\"%s\" is unknown, try \"irm bind help\".\n", argv0);

        return -1;
}

int bind_cmd(int argc, char ** argv)
{
        if (argc < 1) {
                usage();
                return -1;
        }

        return do_cmd(argv[0], argc, argv);
}
