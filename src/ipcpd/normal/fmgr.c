/*
 * Ouroboros - Copyright (C) 2016
 *
 * Flow manager of the IPC Process
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "flow-manager"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/dev.h>
#include <ouroboros/list.h>

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>

#include "fmgr.h"
#include "ribmgr.h"
#include "frct.h"
#include "ipcp.h"

extern struct ipcp * _ipcp;

struct n_1_flow {
        int fd;
        char * ae_name;
        struct list_head next;
};

struct fmgr {
        pthread_t listen_thread;

        struct list_head n_1_flows;
        pthread_mutex_t n_1_flows_lock;

} * fmgr = NULL;

static int add_n_1_fd(int fd,
                      char * ae_name)
{
        struct n_1_flow * tmp;

        if (ae_name == NULL)
                return -1;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return -1;

        tmp->fd = fd;
        tmp->ae_name = ae_name;

        pthread_mutex_lock(&fmgr->n_1_flows_lock);
        list_add(&tmp->next, &fmgr->n_1_flows);
        pthread_mutex_unlock(&fmgr->n_1_flows_lock);

        return 0;
}

static void * fmgr_listen(void * o)
{
        int fd;
        char * ae_name;
        bool bound = false;

        while (true) {
                pthread_mutex_lock(&_ipcp->state_lock);
                while (!(_ipcp->state == IPCP_ENROLLED ||
                         _ipcp->state == IPCP_SHUTDOWN))
                        pthread_cond_wait(&_ipcp->state_cond,
                                          &_ipcp->state_lock);

                if (_ipcp->state == IPCP_SHUTDOWN) {
                        pthread_mutex_unlock(&_ipcp->state_lock);
                        return 0;
                }
                pthread_mutex_unlock(&_ipcp->state_lock);

                if (!bound && api_bind(_ipcp->data->dif_name) < 0) {
                        LOG_ERR("Failed to bind the server instance.");
                        pthread_mutex_unlock(&_ipcp->state_lock);
                        return (void *) -1;
                }

                bound = true;

                fd = flow_accept(&ae_name);
                if (fd < 0) {
                        LOG_ERR("Failed to accept flow.");
                        continue;
                }

                if (!(strcmp(ae_name, MGMT_AE) == 0 ||
                      strcmp(ae_name, DT_AE) == 0)) {
                        if (flow_alloc_resp(fd, -1))
                                LOG_ERR("Failed to reply to flow allocation.");
                        flow_dealloc(fd);
                        continue;
                }

                if (flow_alloc_resp(fd, 0)) {
                        LOG_ERR("Failed to reply to flow allocation.");
                        flow_dealloc(fd);
                        continue;
                }

                LOG_DBG("Accepted new flow allocation request for AE %s.",
                        ae_name);

                if (strcmp(ae_name, MGMT_AE) == 0) {
                        if (ribmgr_add_flow(fd)) {
                                LOG_ERR("Failed to hand fd to RIB.");
                                flow_dealloc(fd);
                                continue;
                        }
                }

                if (strcmp(ae_name, DT_AE) == 0) {
                        if (frct_dt_flow(fd)) {
                                LOG_ERR("Failed to hand fd to FRCT.");
                                flow_dealloc(fd);
                                continue;
                        }
                }

                if (add_n_1_fd(fd, ae_name)) {
                        LOG_ERR("Failed to add file descriptor to list.");
                        flow_dealloc(fd);
                        continue;
                }
        }

        return (void *) 0;
}

int fmgr_init()
{
        fmgr = malloc(sizeof(*fmgr));
        if (fmgr == NULL)
                return -1;

        INIT_LIST_HEAD(&fmgr->n_1_flows);

        pthread_mutex_init(&fmgr->n_1_flows_lock, NULL);

        pthread_create(&fmgr->listen_thread,
                       NULL,
                       fmgr_listen,
                       NULL);

        return 0;
}

int fmgr_fini()
{
        struct list_head * pos = NULL;

        pthread_cancel(fmgr->listen_thread);

        pthread_join(fmgr->listen_thread,
                     NULL);

        list_for_each(pos, &fmgr->n_1_flows) {
                struct n_1_flow * e =
                        list_entry(pos, struct n_1_flow, next);
                if (e->ae_name != NULL)
                        free(e->ae_name);
                if (ribmgr_remove_flow(e->fd))
                    LOG_ERR("Failed to remove management flow.");
        }

        free(fmgr);

        return 0;
}

int fmgr_mgmt_flow(char * dst_name)
{
        int fd;
        int result;

        /* FIXME: Request retransmission. */
        fd = flow_alloc(dst_name, MGMT_AE, NULL);
        if (fd < 0) {
                LOG_ERR("Failed to allocate flow to %s", dst_name);
                return -1;
        }

        result = flow_alloc_res(fd);
        if (result < 0) {
                LOG_ERR("Result of flow allocation to %s is %d",
                        dst_name, result);
                return -1;
        }

        if (ribmgr_add_flow(fd)) {
                LOG_ERR("Failed to hand file descriptor to RIB manager");
                flow_dealloc(fd);
                return -1;
        }

        if (add_n_1_fd(fd, strdup(MGMT_AE))) {
                LOG_ERR("Failed to add file descriptor to list.");
                flow_dealloc(fd);
                return -1;
        }

        return 0;
}

int fmgr_dt_flow(char * dst_name)
{
        LOG_MISSING;

        return -1;
}

int fmgr_flow_alloc(pid_t         n_api,
                    int           port_id,
                    char *        dst_ap_name,
                    char *        src_ae_name,
                    enum qos_cube qos)
{
        LOG_MISSING;

        return -1;
}

int fmgr_flow_alloc_resp(pid_t n_api,
                         int   port_id,
                         int   response)
{
        LOG_MISSING;

        return -1;
}

int fmgr_flow_dealloc(int port_id)
{
        LOG_MISSING;

        return -1;
}
