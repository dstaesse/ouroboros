/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Normal IPC Process - Authenticated CDAP Flow Allocator
 *
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
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

#define OUROBOROS_PREFIX "cdap-flow"

#include <ouroboros/config.h>
#include <ouroboros/dev.h>
#include <ouroboros/logs.h>

#include "cdap_flow.h"

#include <stdlib.h>
#include <assert.h>

static void cdap_flow_destroy(struct cdap_flow * flow)
{
        assert(flow);

        if (flow->ci != NULL)
                cdap_destroy(flow->ci);

        if (flow->info != NULL) {
                if (flow->info->name != NULL)
                        free(flow->info->name);
                if (flow->info->data != NULL)
                        free(flow->info->data);
        }

        free(flow);
}

struct cdap_flow * cdap_flow_arr(int                       fd,
                                 int                       resp,
                                 enum pol_cacep            pc,
                                 const struct cacep_info * info)
{
        struct cdap_flow *  flow;

        if (flow_alloc_resp(fd, resp) < 0) {
                log_err("Could not respond to new flow.");
                return NULL;
        }

        if (resp)
                return NULL;

        flow = malloc(sizeof(*flow));
        if (flow == NULL) {
                log_err("Failed to malloc.");
                return NULL;
        }

        flow->fd = fd;
        flow->ci = NULL;

        flow->info = cacep_auth_wait(fd, pc, info);
        if (flow->info == NULL) {
                log_err("Other side failed to authenticate.");
                cdap_flow_destroy(flow);
                return NULL;
        }

        flow->ci = cdap_create(fd);
        if (flow->ci == NULL) {
                log_err("Failed to create CDAP instance.");
                cdap_flow_destroy(flow);
                return NULL;
        }

        return flow;
}

struct cdap_flow * cdap_flow_alloc(const char *              dst_name,
                                   const char *              ae_name,
                                   qosspec_t *               qs,
                                   enum pol_cacep            pc,
                                   const struct cacep_info * info)
{
        struct cdap_flow *  flow;
        int                 fd;

        log_dbg("Allocating flow to %s.", dst_name);

        if (dst_name == NULL || ae_name == NULL) {
                log_err("Not enough info to establish flow.");
                return NULL;
        }

        fd = flow_alloc(dst_name, ae_name, qs);
        if (fd < 0) {
                log_err("Failed to allocate flow to %s.", dst_name);
                return NULL;
        }

        if (flow_alloc_res(fd)) {
                log_err("Flow allocation to %s failed.", dst_name);
                return NULL;
        }

        flow = malloc(sizeof(*flow));
        if (flow == NULL) {
                log_err("Failed to malloc.");
                flow_dealloc(fd);
                return NULL;
        }

        flow->fd = fd;
        flow->ci = NULL;

        flow->info = cacep_auth(fd, pc, info);
        if (flow->info == NULL) {
                log_err("Failed to authenticate.");
                cdap_flow_dealloc(flow);
                return NULL;
        }

        flow->ci = cdap_create(fd);
        if (flow->ci == NULL) {
                log_err("Failed to create CDAP instance.");
                cdap_flow_dealloc(flow);
                return NULL;
        }

        return flow;
}

void cdap_flow_dealloc(struct cdap_flow * flow)
{
        int fd = flow->fd;

        cdap_flow_destroy(flow);

        flow_dealloc(fd);
}
