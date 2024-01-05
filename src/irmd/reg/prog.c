/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - Programs
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <ouroboros/errno.h>
#include <ouroboros/irm.h>
#include <ouroboros/utils.h>

#include "prog.h"
#include "utils.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>


static char ** create_argv(const char *  prog,
                           size_t        argc,
                           char **       argv)
{
        char ** argv2;
        size_t  i;

        argv2 = malloc((argc + 2) * sizeof(*argv2)); /* prog + args + NULL */
        if (argv2 == 0)
                goto fail_malloc;

        argv2[0] = strdup(prog);
        if (argv2[0] == NULL)
                goto fail_prog;

        for (i = 1; i <= argc; ++i) {
                argv2[i] = strdup(argv[i - 1]);
                if (argv2[i] == NULL)
                        goto fail_arg;
        }

        argv2[argc + 1] = NULL;

        return argv2;

 fail_arg:
        argvfree(argv2);
 fail_prog:
        free(argv2);
 fail_malloc:
        return NULL;
}

struct reg_prog * reg_prog_create(const char * prog,
                                  uint32_t     flags,
                                  int          argc,
                                  char **      argv)
{
        struct reg_prog * p;

        assert(prog);

        p = malloc(sizeof(*p));
        if (p == NULL)
                goto fail_malloc;

        memset(p, 0, sizeof(*p));

        p->prog  = strdup(path_strip(prog));
        if (p->prog == NULL)
                goto fail_prog;

        if (argc > 0 && flags & BIND_AUTO) {
                p->argv = create_argv(prog, argc, argv);
                if (p->argv == NULL)
                        goto fail_argv;
        }

        list_head_init(&p->next);
        list_head_init(&p->names);

        p->flags = flags;

        return p;

 fail_argv:
        free(p->prog);
 fail_prog:
        free(p);
 fail_malloc:
        return NULL;
}

void reg_prog_destroy(struct reg_prog * prog)
{
        struct list_head * p;
        struct list_head * h;

        if (prog == NULL)
                return;

        list_for_each_safe(p, h, &prog->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                list_del(&s->next);
                free(s->str);
                free(s);
        }

        argvfree(prog->argv);
        free(prog->prog);
        free(prog);
}

int reg_prog_add_name(struct reg_prog * prog,
                      const char *      name)
{
        struct str_el * s;

        if (prog == NULL || name == NULL)
                return -EINVAL;

        s = malloc(sizeof(*s));
        if (s == NULL)
                goto fail_malloc;

        s->str = strdup(name);
        if(s->str == NULL)
                goto fail_name;

        list_add(&s->next, &prog->names);

        return 0;

 fail_name:
        free(s);
 fail_malloc:
        return -ENOMEM;
}

void reg_prog_del_name(struct reg_prog * prog,
                       const char *      name)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &prog->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                if (!strcmp(name, s->str)) {
                        list_del(&s->next);
                        free(s->str);
                        free(s);
                }
        }
}
