/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Handy utilities
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _DEFAULT_SOURCE

#include "config.h"

#include <ouroboros/utils.h>

#include <ctype.h>
#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <string.h>

int bufcmp(const buffer_t * a,
           const buffer_t * b)
{
        if (a->len != b->len)
                return a->len < b->len ? -1 : 1;

        return memcmp(a->data, b->data, a->len);
}


int n_digits(unsigned i)
{
        int n = 1;

        while (i > 9) {
                ++n;
                i /= 10;
        }

        return n;
}

char * path_strip(const char * src)
{
        char * dst;

        if (src == NULL)
                return NULL;

        dst = (char *) src + strlen(src);

        while (dst > src && *dst != '/')
                --dst;

        if (*dst == '/')
                ++dst;

        return dst;
}

char * trim_whitespace(char * str)
{
        char * end;

        while (isspace((unsigned char) *str))
                str++;

        if (*str == '\0')
                return str;

        /* Trim trailing space */
        end = str + strlen(str) - 1;
        while (end > str && isspace((unsigned char)*end))
                *end-- = '\0';

        return str;
}

size_t argvlen(const char ** argv)
{
        size_t argc   = 0;

        if (argv == NULL)
                return 0;

        while (*argv++ != NULL)
                argc++;

        return argc;
}

void argvfree(char ** argv)
{
        char ** argv_dup;

        if (argv == NULL)
                return;

        argv_dup = argv;
        while (*argv_dup != NULL)
                free(*(argv_dup++));

        free(argv);
}

char ** argvdup(char ** argv)
{
        int     argc = 0;
        char ** argv_dup = argv;
        int     i;

        if (argv == NULL)
                return NULL;

        while (*(argv_dup++) != NULL)
                argc++;

        argv_dup = malloc((argc + 1) * sizeof(*argv_dup));
        if (argv_dup == NULL)
                return NULL;

        for (i = 0; i < argc; ++i) {
                argv_dup[i] = strdup(argv[i]);
                if (argv_dup[i] == NULL) {
                        argvfree(argv_dup);
                        return NULL;
                }
        }

        argv_dup[argc] = NULL;

        return argv_dup;
}

bool is_ouroboros_member_uid(uid_t uid)
{
        struct group *  grp;
        struct passwd * pw;
#ifdef __APPLE__
        unsigned int    gid;
        int *           groups = NULL;
#else
        gid_t           gid;
        gid_t *         groups = NULL;
#endif
        int             ngroups;
        int             i;

        /* Root is always privileged */
        if (uid == 0)
                return true;

        grp = getgrnam("ouroboros");
        if (grp == NULL)
                return false;

        gid = grp->gr_gid;

        pw = getpwuid(uid);
        if (pw == NULL)
                return false;

        if (pw->pw_gid == gid)
                return true;

        ngroups = 0;
        getgrouplist(pw->pw_name, pw->pw_gid, NULL, &ngroups);
        if (ngroups <= 0)
                return false;

        groups = malloc(ngroups * sizeof(*groups));
        if (groups == NULL)
                return false;

        if (getgrouplist(pw->pw_name, pw->pw_gid, groups, &ngroups) < 0) {
                free(groups);
                return false;
        }

        for (i = 0; i < ngroups; i++) {
#ifdef __APPLE__
                if (groups[i] == (int) gid) {
#else
                if (groups[i] == gid) {
#endif
                        free(groups);
                        return true;
                }
        }

        free(groups);

        return false;
}

bool is_ouroboros_member(void)
{
        return is_ouroboros_member_uid(getuid());
}
