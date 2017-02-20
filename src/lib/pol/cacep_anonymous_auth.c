/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Anonymous policy for CACEP
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <ouroboros/config.h>
#include <ouroboros/cacep.h>
#include <ouroboros/time_utils.h>

#include "cacep_anonymous_auth.h"

#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <stdio.h>

#define NAME_LEN 8

/* this policy generates a hex string */
static struct cacep_info * anonymous_info(void)
{
        struct cacep_info * info;
        struct timespec t;

        info = malloc(sizeof(*info));
        if (info == NULL)
                return NULL;

        info->name = malloc(NAME_LEN + 1);
        if (info->name == NULL) {
                free(info);
                return NULL;
        }

        clock_gettime(CLOCK_REALTIME, &t);
        srand(t.tv_nsec);

        sprintf(info->name, "%8x",
                (uint32_t)((rand() % RAND_MAX) & 0xFFFFFFFF));

        info->addr = 0;

        return info;
}

struct cacep_info * cacep_anonymous_auth(int                       fd,
                                         const struct cacep_info * info)
{
        (void) fd;
        (void) info;

        return anonymous_info();
}


struct cacep_info * cacep_anonymous_auth_wait(int                       fd,
                                              const struct cacep_info * info)
{
        (void) fd;
        (void) info;

        return anonymous_info();
}
