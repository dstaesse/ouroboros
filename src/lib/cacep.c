/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The Common Application Connection Establishment Phase
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "cacep"

#include <ouroboros/config.h>
#include <ouroboros/cacep.h>
#include <ouroboros/dev.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>

#include "pol/cacep_anonymous_auth.h"
#include "pol/cacep_simple_auth.h"

#include <stdlib.h>
#include <string.h>

#define BUF_SIZE 2048

int conn_info_init(struct conn_info * info)
{
        if (info == NULL)
                return -EINVAL;

        info->proto.protocol = NULL;
        info->name = NULL;

        return 0;
}

void conn_info_fini(struct conn_info * info)
{
        if (info == NULL)
                return;

        if (info->proto.protocol != NULL) {
                free(info->proto.protocol);
                info->proto.protocol = NULL;
        }

        if (info->name != NULL) {
                free(info->name);
                info->name = NULL;
        }
}

struct conn_info * cacep_auth(int                      fd,
                              enum pol_cacep           pc,
                              const struct conn_info * info,
                              const void *             auth)
{
        if (info == NULL) {
                log_err("No info provided.");
                return NULL;
        }

        switch (pc) {
        case ANONYMOUS_AUTH:
                return cacep_anonymous_auth(fd, info, auth);
        case SIMPLE_AUTH:
                if (info == NULL)
                        return NULL;
                return cacep_simple_auth_auth(fd, info, auth);
        default:
                log_err("Unsupported CACEP policy.");
                return NULL;
        }
}

struct conn_info * cacep_auth_wait(int                      fd,
                                   enum pol_cacep           pc,
                                   const struct conn_info * info,
                                   const void *             auth)
{
        if (info == NULL) {
                log_err("No info provided.");
                return NULL;
        }

        switch (pc) {
        case ANONYMOUS_AUTH:
                return cacep_anonymous_auth_wait(fd, info, auth);
        case SIMPLE_AUTH:
                if (info == NULL)
                        return NULL;
                return cacep_simple_auth_auth_wait(fd, info, auth);
        default:
                log_err("Unsupported CACEP policy.");
                return NULL;
        }
}
