/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Graph adjacency manager for IPC Process components
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "graph-adjacency-manager"

#include <ouroboros/config.h>
#include <ouroboros/cdap.h>
#include <ouroboros/dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/list.h>
#include <ouroboros/errno.h>
#include <ouroboros/rib.h>

#include "ipcp.h"
#include "gam.h"
#include "pol-gam-ops.h"
#include "pol/complete.h"

#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

struct ga {
        struct list_head    next;

        qosspec_t           qs;
        int                 fd;
        struct conn_info *  info;
};

struct gam {
        struct list_head     gas;
        pthread_mutex_t      gas_lock;
        pthread_cond_t       gas_cond;

        struct pol_gam_ops * ops;
        void *               ops_o;
};

struct gam * gam_create(enum pol_gam gam_type)
{
        struct gam * tmp;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return NULL;

        switch (gam_type) {
        case COMPLETE:
                tmp->ops = &complete_ops;
                break;
        default:
                log_err("Unknown gam policy: %d.", gam_type);
                free(tmp);
                return NULL;
        }

        list_head_init(&tmp->gas);

        if (pthread_mutex_init(&tmp->gas_lock, NULL)) {
                free(tmp);
                return NULL;
        }

        if (pthread_cond_init(&tmp->gas_cond, NULL)) {
                pthread_mutex_destroy(&tmp->gas_lock);
                free(tmp);
                return NULL;
        }

        tmp->ops_o = tmp->ops->create(tmp);
        if (tmp->ops_o == NULL) {
                pthread_cond_destroy(&tmp->gas_cond);
                pthread_mutex_destroy(&tmp->gas_lock);
                free(tmp);
                return NULL;
        }

        if (tmp->ops->start(tmp->ops_o)) {
                pthread_cond_destroy(&tmp->gas_cond);
                pthread_mutex_destroy(&tmp->gas_lock);
                free(tmp);
                return NULL;
        }

        return tmp;
}

void gam_destroy(struct gam * instance)
{
        struct list_head * p = NULL;
        struct list_head * n = NULL;

        assert(instance);

        instance->ops->stop(instance->ops_o);

        pthread_mutex_lock(&instance->gas_lock);

        list_for_each_safe(p, n, &instance->gas) {
                struct ga * e = list_entry(p, struct ga, next);
                list_del(&e->next);
                free(e->info);
                free(e);
        }

        pthread_mutex_unlock(&instance->gas_lock);

        pthread_mutex_destroy(&instance->gas_lock);
        pthread_cond_destroy(&instance->gas_cond);

        instance->ops->destroy(instance->ops_o);
        free(instance);
}

static int add_ga(struct gam *       instance,
                  int                fd,
                  qosspec_t          qs,
                  struct conn_info * info)
{
        struct ga * ga;

        ga = malloc(sizeof(*ga));
        if (ga == NULL)
                return -ENOMEM;

        ga->fd = fd;
        ga->info = info;
        ga->qs = qs;

        list_head_init(&ga->next);

        pthread_mutex_lock(&instance->gas_lock);
        list_add(&ga->next, &instance->gas);
        pthread_cond_signal(&instance->gas_cond);
        pthread_mutex_unlock(&instance->gas_lock);

        log_info("Added flow.");

        return 0;
}

int gam_flow_arr(struct gam * instance,
                 int          fd,
                 qosspec_t    qs)
{
        struct conn_info * rcv_info;
        struct conn_info snd_info;

        if (flow_alloc_resp(fd, instance->ops->accept_new_flow(instance->ops_o))
            < 0) {
                log_err("Could not respond to new flow.");
                return -1;
        }

        rcv_info = malloc(sizeof(*rcv_info));
        if (rcv_info == NULL)
                return -ENOMEM;

        memset(&snd_info, 0, sizeof(snd_info));
        memset(rcv_info, 0, sizeof(*rcv_info));

        /* FIXME: send correct AE */
        strcpy(snd_info.ae_name, "FIXME:CORRECT_AE");
        strcpy(snd_info.protocol, CDAP_PROTO);
        snd_info.pref_version = 1;
        snd_info.pref_syntax = PROTO_GPB;
        snd_info.ae.addr = ipcpi.address;

        if (cacep_listen(fd, &snd_info, rcv_info)) {
                log_err("Failed to create application connection.");
                flow_dealloc(fd);
                free(rcv_info);
                return -1;
        }

        if (instance->ops->accept_flow(instance->ops_o, qs, rcv_info)) {
                flow_dealloc(fd);
                free(rcv_info);
                return 0;
        }

        if (add_ga(instance, fd, qs, rcv_info)) {
                log_err("Failed to add ga to graph adjacency manager list.");
                flow_dealloc(fd);
                free(rcv_info);
                return -1;
        }

        return 0;
}

int gam_flow_alloc(struct gam * instance,
                   char *       dst_name,
                   qosspec_t    qs)
{
        struct conn_info * rcv_info;
        struct conn_info snd_info;
        int                 fd;

        log_dbg("Allocating flow to %s.", dst_name);

        rcv_info = malloc(sizeof(*rcv_info));
        if (rcv_info == NULL)
                return -ENOMEM;

        fd = flow_alloc(dst_name, NULL);
        if (fd < 0) {
                log_err("Failed to allocate flow to %s.", dst_name);
                return -1;
        }

        if (flow_alloc_res(fd)) {
                log_err("Flow allocation to %s failed.", dst_name);
                flow_dealloc(fd);
                return -1;
        }

        memset(&snd_info, 0, sizeof(snd_info));
        memset(rcv_info, 0, sizeof(*rcv_info));

        /* FIXME: send correct AE */
        strcpy(snd_info.ae_name, "FIXME:CORRECT_AE");
        strcpy(snd_info.protocol, CDAP_PROTO);
        snd_info.pref_version = 1;
        snd_info.pref_syntax = PROTO_GPB;
        snd_info.ae.addr = ipcpi.address;

        if (cacep_connect(fd, &snd_info, rcv_info)) {
                log_err("Failed to create application connection.");
                flow_dealloc(fd);
                free(rcv_info);
                return -1;
        }

        if (instance->ops->accept_flow(instance->ops_o, qs, rcv_info)) {
                flow_dealloc(fd);
                free(rcv_info);
                return 0;
        }

        if (add_ga(instance, fd, qs, rcv_info)) {
                log_err("Failed to add GA to graph adjacency manager list.");
                flow_dealloc(fd);
                free(rcv_info);
                return -1;
        }

        return 0;
}

int gam_flow_wait(struct gam *        instance,
                  int *               fd,
                  struct conn_info ** info,
                  qosspec_t *         qs)
{
        struct ga * ga;

        assert(fd);
        assert(info);
        assert(qs);

        pthread_mutex_lock(&instance->gas_lock);

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) &instance->gas_lock);

        while (list_is_empty(&instance->gas))
                pthread_cond_wait(&instance->gas_cond, &instance->gas_lock);

        ga = list_first_entry((&instance->gas), struct ga, next);
        if (ga == NULL) {
                pthread_mutex_unlock(&instance->gas_lock);
                return -1;
        }

        *fd   = ga->fd;
        *info = ga->info;
        *qs   = ga->qs;

        list_del(&ga->next);
        free(ga);

        pthread_cleanup_pop(true);

        return 0;
}
