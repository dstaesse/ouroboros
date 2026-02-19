/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * The IPC Resource Manager - Registry - Flows
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

#define OUROBOROS_PREFIX "reg/flow"

#include <ouroboros/logs.h>

#include "flow.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>

struct reg_flow * reg_flow_create(const struct flow_info * info)
{
        struct reg_flow * flow;

        assert(info != NULL);
        assert(info->id > 0);
        assert(info->n_pid != 0);
        assert(info->n_1_pid == 0);
        assert(info->mpl == 0);
        assert(info->state == FLOW_INIT);

        flow = malloc(sizeof(*flow));
        if (flow == NULL) {
                log_err("Failed to malloc flow.");
                goto fail_malloc;
        }

        memset(flow, 0, sizeof(*flow));

        clock_gettime(PTHREAD_COND_CLOCK, &flow->t0);
        list_head_init(&flow->next);

        flow->info = *info;

        return flow;

 fail_malloc:
        return NULL;
}

static void destroy_rbuffs(struct reg_flow * flow)
{
        if (flow->n_rb != NULL)
                ssm_rbuff_destroy(flow->n_rb);
        flow->n_rb = NULL;

        if (flow->n_1_rb != NULL)
                ssm_rbuff_destroy(flow->n_1_rb);
        flow->n_1_rb = NULL;
}

void reg_flow_destroy(struct reg_flow * flow)
{
        assert(flow != NULL);

        switch(flow->info.state) {
        case FLOW_ACCEPT_PENDING:
                clrbuf(flow->req_data);
                /* FALLTHRU */
        default:
                destroy_rbuffs(flow);
                break;
        }

        assert(flow->n_rb == NULL);
        assert(flow->n_1_rb == NULL);
        assert(flow->req_data.data == NULL);
        assert(flow->req_data.len == 0);
        assert(flow->rsp_data.data == NULL);
        assert(flow->rsp_data.len == 0);

        assert(list_is_empty(&flow->next));

        free(flow);
}

static int create_rbuffs(struct reg_flow *  flow,
                         struct flow_info * info)
{
        assert(flow != NULL);
        assert(info != NULL);

        flow->n_rb = ssm_rbuff_create(info->n_pid, info->id);
        if (flow->n_rb == NULL)
                goto fail_n_rb;

        if (ssm_rbuff_mlock(flow->n_rb) < 0)
                log_warn("Failed to mlock n_rb for flow %d.", info->id);

        assert(flow->info.n_1_pid == 0);
        assert(flow->n_1_rb == NULL);

        flow->info.n_1_pid = info->n_1_pid;
        flow->n_1_rb = ssm_rbuff_create(info->n_1_pid, info->id);
        if (flow->n_1_rb == NULL)
                goto fail_n_1_rb;

        if (ssm_rbuff_mlock(flow->n_1_rb) < 0)
                log_warn("Failed to mlock n_1_rb for flow %d.", info->id);

        return 0;

 fail_n_1_rb:
        ssm_rbuff_destroy(flow->n_rb);
 fail_n_rb:
        return -ENOMEM;
}

int reg_flow_update(struct reg_flow *  flow,
                    struct flow_info * info)
{
        assert(flow != NULL);
        assert(info != NULL);

        assert(flow->info.id == info->id);

        switch(info->state) {
        case FLOW_ACCEPT_PENDING:
                assert(flow->info.state == FLOW_INIT);
                flow->info.n_pid = info->n_pid;
                break;
        case FLOW_ALLOC_PENDING:
                assert(flow->info.state == FLOW_INIT);
                assert(info->n_1_pid != 0);

                if (create_rbuffs(flow, info) < 0)
                        goto fail;

                break;
        case FLOW_ALLOCATED:
                assert(info->n_1_pid != 0);
                assert(flow->info.state > FLOW_INIT);
                assert(flow->info.state < FLOW_ALLOCATED);
                assert(flow->info.n_pid != 0);
                assert(info->mpl != 0);

                flow->info.mpl = info->mpl;

                if (flow->info.state == FLOW_ALLOC_PENDING)
                        break;

                flow->info.qs  = info->qs;

                if (create_rbuffs(flow, info) < 0)
                        goto fail;
                break;
        case FLOW_DEALLOCATED:
                destroy_rbuffs(flow);
                break;
        case FLOW_DEALLOC_PENDING:
                break;
        default:
                assert(false);
                return -EPERM;
        }

        flow->info.state = info->state;
        flow->info.uid   = info->uid;

        *info = flow->info;

        return 0;
 fail:
        return -ENOMEM;
}
