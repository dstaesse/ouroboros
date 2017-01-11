/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Graph adjacency manager for IPC Process components
 *
 *    Dimitri Staeesens <dimitri.staessens@intec.ugent.be>
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
#include <ouroboros/dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/cacep.h>
#include <ouroboros/list.h>
#include <ouroboros/errno.h>

#include "ribmgr.h"
#include "ipcp.h"
#include "ro.h"
#include "pathname.h"
#include "gam.h"

#include <assert.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#define RO_DIR "neighbors"

struct ga {
        struct list_head    next;

        qosspec_t           qs;
        int                 fd;
        struct cacep_info * info;
};

struct gam {
        struct list_head gas;
        pthread_mutex_t  gas_lock;
        pthread_cond_t   gas_cond;

        char *           ae_name;

        /* FIXME: Keep a list of known members */

        pthread_t        allocator;
};

static void * allocator(void * o)
{
        qosspec_t    qs;
        ssize_t      len;
        char **      children;
        struct gam * instance;
        int          i;
        char *       ro_name;

        instance = (struct gam *) o;

        qs.delay = 0;
        qs.jitter = 0;

        ro_name = pathname_create(RO_DIR);
        if (ro_name == NULL)
                return (void *) -1;

        len = ro_children(ro_name, &children);
        if (len > 0) {
                for (i = 0; i < len; i++) {
                        if (strcmp(children[i], ipcpi.name) == 0)
                                continue;
                        gam_flow_alloc(instance, children[i], qs);
                }
        }

        pathname_destroy(ro_name);

        return (void *) 0;
}

struct gam * gam_create(char * ae_name)
{
        struct gam *   tmp;
        struct ro_attr attr;
        char *         ro_name;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return NULL;

        list_head_init(&tmp->gas);

        tmp->ae_name = strdup(ae_name);
        if (tmp->ae_name == NULL) {
                free(tmp);
                return NULL;
        }

        if (pthread_mutex_init(&tmp->gas_lock, NULL)) {
                free(tmp->ae_name);
                free(tmp);
                return NULL;
        }

        if (pthread_cond_init(&tmp->gas_cond, NULL)) {
                pthread_mutex_destroy(&tmp->gas_lock);
                free(tmp->ae_name);
                free(tmp);
                return NULL;
        }

        ro_attr_init(&attr);
        attr.enrol_sync = true;
        attr.recv_set = ALL_MEMBERS;

        ro_name = pathname_create(RO_DIR);
        if (ro_name == NULL) {
                pthread_mutex_destroy(&tmp->gas_lock);
                free(tmp->ae_name);
                free(tmp);
                return NULL;
        }

        if (!ro_exists(RO_DIR)) {
                if (ro_create(ro_name, &attr, NULL, 0)) {
                        pathname_destroy(ro_name);
                        pthread_mutex_destroy(&tmp->gas_lock);
                        free(tmp->ae_name);
                        free(tmp);
                        return NULL;
                }
        }

        ro_name = pathname_append(ro_name, ipcpi.name);
        if (ro_name == NULL) {
                pathname_destroy(ro_name);
                pthread_mutex_destroy(&tmp->gas_lock);
                free(tmp->ae_name);
                free(tmp);
                return NULL;
        }

        if (ro_create(ro_name, &attr, NULL, 0)) {
                pathname_destroy(ro_name);
                pthread_mutex_destroy(&tmp->gas_lock);
                free(tmp->ae_name);
                free(tmp);
                return NULL;
        }
        pathname_destroy(ro_name);

        if (pthread_create(&tmp->allocator, NULL, allocator, (void *) tmp)) {
                pthread_cond_destroy(&tmp->gas_cond);
                pthread_mutex_destroy(&tmp->gas_lock);
                free(tmp->ae_name);
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

        pthread_cancel(instance->allocator);
        pthread_join(instance->allocator, NULL);

        pthread_mutex_destroy(&instance->gas_lock);
        pthread_cond_destroy(&instance->gas_cond);

        list_for_each_safe(p, n, &instance->gas) {
                struct ga * e = list_entry(p, struct ga, next);
                list_del(&e->next);
                free(e->info);
                free(e);
        }

        free(instance->ae_name);
        free(instance);
}

static int add_ga(struct gam *        instance,
                  int                 fd,
                  qosspec_t           qs,
                  struct cacep_info * info)
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

        return 0;
}

int gam_flow_arr(struct gam * instance,
                 int          fd,
                 qosspec_t    qs)
{
        struct cacep *      cacep;
        struct cacep_info * info;

        if (flow_alloc_resp(fd, 0) < 0) {
                LOG_ERR("Could not respond to new flow.");
                return -1;
        }

        cacep = cacep_create(fd, ipcpi.name, ribmgr_address());
        if (cacep == NULL) {
                LOG_ERR("Failed to create CACEP instance.");
                return -1;
        }

        info = cacep_auth_wait(cacep);
        if (info == NULL) {
                LOG_ERR("Other side failed to authenticate.");
                cacep_destroy(cacep);
                return -1;
        }
        cacep_destroy(cacep);

        if (add_ga(instance, fd, qs, info)) {
                LOG_ERR("Failed to add ga to graph adjacency manager list.");
                free(info);
                return -1;
        }

        return 0;
}

int gam_flow_alloc(struct gam * instance,
                   char *       dst_name,
                   qosspec_t    qs)
{
        struct cacep *      cacep;
        struct cacep_info * info;
        int                 fd;

        fd = flow_alloc(dst_name, instance->ae_name, NULL);
        if (fd < 0) {
                LOG_ERR("Failed to allocate flow to %s.", dst_name);
                return -1;
        }

        if (flow_alloc_res(fd)) {
                LOG_ERR("Flow allocation to %s failed.", dst_name);
                flow_dealloc(fd);
                return -1;
        }

        cacep = cacep_create(fd, ipcpi.name, ribmgr_address());
        if (cacep == NULL) {
                LOG_ERR("Failed to create CACEP instance.");
                return -1;
        }

        info = cacep_auth(cacep);
        if (info == NULL) {
                LOG_ERR("Failed to authenticate.");
                cacep_destroy(cacep);
                return -1;
        }
        cacep_destroy(cacep);

        if (add_ga(instance, fd, qs, info)) {
                LOG_ERR("Failed to add ga to graph adjacency manager list.");
                free(info);
                return -1;
        }

        return 0;
}

int gam_flow_wait(struct gam *         instance,
                  int *                fd,
                  struct cacep_info ** info,
                  qosspec_t *          qs)
{
        struct ga * ga;

        assert(fd);
        assert(info);
        assert(qs);

        pthread_mutex_lock(&instance->gas_lock);

        while (list_is_empty(&instance->gas))
                pthread_cond_wait(&instance->gas_cond, &instance->gas_lock);

        ga = list_first_entry((&instance->gas), struct ga, next);
        if (ga == NULL) {
                pthread_mutex_unlock(&instance->gas_lock);
                LOG_ERR("Ga was NULL.");
                return -1;
        }

        *fd   = ga->fd;
        *info = ga->info;
        *qs   = ga->qs;

        list_del(&ga->next);
        free(ga);

        pthread_mutex_unlock(&instance->gas_lock);

        return 0;
}
