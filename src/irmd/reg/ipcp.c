/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - IPCPs
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

#define _POSIX_C_SOURCE 200809L

#define OUROBOROS_PREFIX "reg/ipcp"

#include <ouroboros/logs.h>
#include <ouroboros/time.h>

#include "ipcp.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct reg_ipcp * reg_ipcp_create(const struct ipcp_info * info)
{
        struct reg_ipcp * ipcp;

        assert(info != NULL);
        assert(info->state == IPCP_BOOT);

        ipcp = malloc(sizeof(*ipcp));
        if (ipcp == NULL) {
                log_err("Failed to malloc ipcp.");
                goto fail_malloc;
        }

        memset(ipcp, 0, sizeof(*ipcp));
        memset(&ipcp->layer, 0, sizeof(ipcp->layer));

        list_head_init(&ipcp->next);

        ipcp->info = *info;
        ipcp->info.state = IPCP_BOOT;

        strcpy(ipcp->layer.name, "Not enrolled.");

        return ipcp;

 fail_malloc:
        return NULL;
}

void reg_ipcp_destroy(struct reg_ipcp * ipcp)
{
        assert(ipcp != NULL);

        assert(list_is_empty(&ipcp->next));

        free(ipcp);
}

void reg_ipcp_update(struct reg_ipcp *        ipcp,
                     const struct ipcp_info * info)
{
        assert(ipcp != NULL);
        assert(info->state != IPCP_INIT);

        ipcp->info = *info;
}

void reg_ipcp_set_layer(struct reg_ipcp *         ipcp,
                        const struct layer_info * info)
{
        assert(ipcp != NULL);
        assert(ipcp->info.state == IPCP_OPERATIONAL);

        ipcp->layer = *info;
}
