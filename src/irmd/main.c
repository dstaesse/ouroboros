/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The IPC Resource Manager
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#define _POSIX_C_SOURCE 200812L
#define __XSI_VISIBLE   500

#include "config.h"

#define OUROBOROS_PREFIX "irmd"

#include <ouroboros/hash.h>
#include <ouroboros/errno.h>
#include <ouroboros/sockets.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/irm.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/shm_flow_set.h>
#include <ouroboros/shm_rbuff.h>
#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/qos.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/tpm.h>
#include <ouroboros/logs.h>

#include "utils.h"
#include "registry.h"
#include "irm_flow.h"
#include "api_table.h"
#include "ipcp.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/wait.h>

#define IRMD_CLEANUP_TIMER ((IRMD_FLOW_TIMEOUT / 20) * MILLION) /* ns */
#define SHM_SAN_HOLDOFF 1000 /* ms */
#define IPCP_HASH_LEN(e) hash_len(e->dir_hash_algo)
#define IB_LEN IRM_MSG_BUF_SIZE

enum init_state {
        IPCP_NULL = 0,
        IPCP_BOOT,
        IPCP_LIVE
};

struct ipcp_entry {
        struct list_head next;

        char *           name;
        pid_t            api;
        enum ipcp_type   type;
        enum hash_algo   dir_hash_algo;
        char *           dif_name;

        enum init_state  init_state;
        pthread_cond_t   init_cond;
        pthread_mutex_t  init_lock;
};

enum irm_state {
        IRMD_NULL = 0,
        IRMD_RUNNING
};

struct {
        struct list_head     registry;     /* registered names known     */

        struct list_head     ipcps;        /* list of ipcps in system    */

        struct list_head     api_table;    /* ap instances               */
        struct list_head     apn_table;    /* ap names known             */
        struct list_head     spawned_apis; /* child ap instances         */
        pthread_rwlock_t     reg_lock;     /* lock for registration info */

        struct bmp *         port_ids;     /* port_ids for flows         */
        struct list_head     irm_flows;    /* flow information           */
        pthread_rwlock_t     flows_lock;   /* lock for flows             */

        struct lockfile *    lf;           /* single irmd per system     */
        struct shm_rdrbuff * rdrb;         /* rdrbuff for SDUs           */

        int                  sockfd;       /* UNIX socket                */

        uint8_t              cbuf[IB_LEN]; /* cmd message buffer         */
        size_t               cmd_len;      /* length of cmd in cbuf      */
        int                  csockfd;      /* cmd UNIX socket            */
        pthread_cond_t       acc_cond;     /* cmd accepted condvar       */
        pthread_cond_t       cmd_cond;     /* cmd signal condvar         */
        pthread_mutex_t      cmd_lock;     /* cmd signal lock            */

        enum irm_state       state;        /* state of the irmd          */
        pthread_rwlock_t     state_lock;   /* lock for the entire irmd   */

        pthread_t            irm_sanitize; /* clean up irmd resources    */
        pthread_t            shm_sanitize; /* keep track of rdrbuff use  */
        pthread_t            acceptor;     /* accept new commands        */
} irmd;

static enum irm_state irmd_get_state(void)
{
        enum irm_state state;

        pthread_rwlock_rdlock(&irmd.state_lock);

        state = irmd.state;

        pthread_rwlock_unlock(&irmd.state_lock);

        return state;
}

static void irmd_set_state(enum irm_state state)
{
        pthread_rwlock_wrlock(&irmd.state_lock);

        irmd.state = state;

        pthread_rwlock_unlock(&irmd.state_lock);
}

static void clear_irm_flow(struct irm_flow * f) {
        ssize_t idx;

        assert(f);

        while ((idx = shm_rbuff_read(f->n_rb)) >= 0)
                shm_rdrbuff_remove(irmd.rdrb, idx);

        while ((idx = shm_rbuff_read(f->n_1_rb)) >= 0)
                shm_rdrbuff_remove(irmd.rdrb, idx);
}

static struct irm_flow * get_irm_flow(int port_id)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &irmd.irm_flows) {
                struct irm_flow * e = list_entry(pos, struct irm_flow, next);
                if (e->port_id == port_id)
                        return e;
        }

        return NULL;
}

static struct irm_flow * get_irm_flow_n(pid_t n_api)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &irmd.irm_flows) {
                struct irm_flow * e = list_entry(pos, struct irm_flow, next);
                if (e->n_api == n_api &&
                    irm_flow_get_state(e) == FLOW_ALLOC_PENDING)
                        return e;
        }

        return NULL;
}

static struct ipcp_entry * ipcp_entry_create(void)
{
        struct ipcp_entry * e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        e->name = NULL;
        e->dif_name = NULL;

        list_head_init(&e->next);

        return e;
}

static void ipcp_entry_destroy(struct ipcp_entry * e)
{
        assert(e);

        pthread_mutex_lock(&e->init_lock);

        while (e->init_state == IPCP_BOOT)
                pthread_cond_wait(&e->init_cond, &e->init_lock);

        pthread_mutex_unlock(&e->init_lock);

        if (e->name != NULL)
                free(e->name);

        if (e->dif_name != NULL)
                free(e->dif_name);

        free(e);
}

static struct ipcp_entry * get_ipcp_entry_by_api(pid_t api)
{
        struct list_head * p = NULL;

        list_for_each(p, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (api == e->api)
                        return e;
        }

        return NULL;
}

static struct ipcp_entry * get_ipcp_entry_by_name(const char * name)
{
        struct list_head * p = NULL;

        list_for_each(p, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (strcmp(name, e->name) == 0)
                        return e;
        }

        return NULL;
}

static struct ipcp_entry * get_ipcp_by_dst_name(const char * name,
                                                pid_t        src)
{
        struct list_head * p;
        struct list_head * h;
        uint8_t *          hash;
        pid_t              api;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        list_for_each_safe(p, h, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (e->dif_name == NULL || e->api == src)
                        continue;

                hash = malloc(IPCP_HASH_LEN(e));
                if  (hash == NULL)
                        return NULL;

                str_hash(e->dir_hash_algo, hash, name);

                api = e->api;

                pthread_rwlock_unlock(&irmd.reg_lock);

                if (ipcp_query(api, hash, IPCP_HASH_LEN(e)) == 0) {
                        free(hash);
                        return e;
                }

                free(hash);

                pthread_rwlock_rdlock(&irmd.reg_lock);
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return NULL;
}

static pid_t create_ipcp(char *         name,
                         enum ipcp_type ipcp_type)
{
        struct pid_el *     api   = NULL;
        struct ipcp_entry * tmp   = NULL;
        struct list_head *  p     = NULL;
        struct ipcp_entry * entry = NULL;
        int                 ret   = 0;
        pthread_condattr_t  cattr;
        struct timespec     dl;
        struct timespec     to = {SOCKET_TIMEOUT / 1000,
                                  (SOCKET_TIMEOUT % 1000) * MILLION};
        pid_t               ipcp_pid;

        api = malloc(sizeof(*api));
        if (api == NULL)
                return -ENOMEM;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_name(name);
        if (entry != NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                free(api);
                log_err("IPCP by that name already exists.");
                return -1;
        }

        api->pid = ipcp_create(name, ipcp_type);
        if (api->pid == -1) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                free(api);
                log_err("Failed to create IPCP.");
                return -1;
        }

        tmp = ipcp_entry_create();
        if (tmp == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                free(api);
                return -1;
        }

        list_head_init(&tmp->next);

        tmp->name = strdup(name);
        if (tmp->name  == NULL) {
                ipcp_entry_destroy(tmp);
                pthread_rwlock_unlock(&irmd.reg_lock);
                free(api);
                return -1;
        }

        pthread_condattr_init(&cattr);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif

        pthread_cond_init(&tmp->init_cond, &cattr);

        pthread_condattr_destroy(&cattr);

        pthread_mutex_init(&tmp->init_lock, NULL);

        tmp->api           = api->pid;
        tmp->dif_name      = NULL;
        tmp->type          = ipcp_type;
        tmp->init_state    = IPCP_BOOT;
        tmp->dir_hash_algo = -1;
        ipcp_pid           = tmp->api;

        list_for_each(p, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (e->type > ipcp_type)
                        break;
        }

        list_add_tail(&tmp->next, p);

        list_add(&api->next, &irmd.spawned_apis);

        pthread_rwlock_unlock(&irmd.reg_lock);

        pthread_mutex_lock(&tmp->init_lock);

        clock_gettime(PTHREAD_COND_CLOCK, &dl);
        ts_add(&dl, &to, &dl);

        while (tmp->init_state == IPCP_BOOT && ret != -ETIMEDOUT)
                ret = -pthread_cond_timedwait(&tmp->init_cond,
                                              &tmp->init_lock,
                                              &dl);

        if (ret == -ETIMEDOUT) {
                kill(tmp->api, SIGKILL);
                tmp->init_state = IPCP_NULL;
                pthread_cond_signal(&tmp->init_cond);
                pthread_mutex_unlock(&tmp->init_lock);
                log_err("IPCP %d failed to respond.", ipcp_pid);
                return -1;
        }

        pthread_mutex_unlock(&tmp->init_lock);

        log_info("Created IPCP %d.", ipcp_pid);

        return ipcp_pid;
}

static int create_ipcp_r(pid_t api,
                         int   result)
{
        struct list_head * pos = NULL;

        if (result != 0)
                return result;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        list_for_each(pos, &irmd.ipcps) {
                struct ipcp_entry * e =
                        list_entry(pos, struct ipcp_entry, next);

                if (e->api == api) {
                        pthread_mutex_lock(&e->init_lock);
                        e->init_state = IPCP_LIVE;
                        pthread_cond_broadcast(&e->init_cond);
                        pthread_mutex_unlock(&e->init_lock);
                }
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;
}

static void clear_spawned_api(pid_t api)
{
        struct list_head * pos = NULL;
        struct list_head * n   = NULL;

        list_for_each_safe(pos, n, &(irmd.spawned_apis)) {
                struct pid_el * a = list_entry(pos, struct pid_el, next);
                if (api == a->pid) {
                        list_del(&a->next);
                        free(a);
                }
        }
}

static int destroy_ipcp(pid_t api)
{
        struct list_head * pos = NULL;
        struct list_head * n   = NULL;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        list_for_each_safe(pos, n, &(irmd.ipcps)) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);

                if (api == tmp->api) {
                        clear_spawned_api(api);
                        if (ipcp_destroy(api))
                                log_err("Could not destroy IPCP.");
                        list_del(&tmp->next);
                        ipcp_entry_destroy(tmp);

                        log_info("Destroyed IPCP %d.", api);
                }
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;
}

static int bootstrap_ipcp(pid_t               api,
                          ipcp_config_msg_t * conf)
{
        struct ipcp_entry * entry = NULL;
        struct dif_info     info;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_api(api);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -1;
        }

        if (entry->type != (enum ipcp_type) conf->ipcp_type) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Configuration does not match IPCP type.");
                return -1;
        }

        if (ipcp_bootstrap(entry->api, conf, &info)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Could not bootstrap IPCP.");
                return -1;
        }

        entry->dif_name = strdup(info.dif_name);
        if (entry->dif_name == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_warn("Failed to set name of DIF.");
                return -ENOMEM;
        }

        entry->dir_hash_algo = info.dir_hash_algo;

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Bootstrapped IPCP %d in DIF %s.",
                 entry->api, conf->dif_info->dif_name);

        return 0;
}

static int enroll_ipcp(pid_t  api,
                       char * dst_name)
{
        struct ipcp_entry * entry = NULL;
        struct dif_info     info;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_api(api);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -1;
        }

        if (entry->dif_name != NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("IPCP in wrong state");
                return -1;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (ipcp_enroll(api, dst_name, &info) < 0) {
                log_err("Could not enroll IPCP %d.", api);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_api(api);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -1;
        }

        entry->dif_name = strdup(info.dif_name);
        if (entry->dif_name == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Failed to strdup dif_name.");
                return -ENOMEM;
        }

        entry->dir_hash_algo = info.dir_hash_algo;

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Enrolled IPCP %d in DIF %s.",
                 api, info.dif_name);

        return 0;
}

static int connect_ipcp(pid_t        api,
                        const char * dst,
                        const char * component)
{
        struct ipcp_entry * entry = NULL;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_api(api);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -EIPCP;
        }

        if (entry->type != IPCP_NORMAL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Cannot establish connections for this IPCP type.");
                return -EIPCP;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_dbg("Connecting %s to %s.", component, dst);

        if (ipcp_connect(api, dst, component)) {
                log_err("Could not connect IPCP.");
                return -EPERM;
        }

        log_info("Established %s connection between IPCP %d and %s.",
                 component, api, dst);

        return 0;
}

static int disconnect_ipcp(pid_t        api,
                           const char * dst,
                           const char * component)
{
        struct ipcp_entry * entry = NULL;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_api(api);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -EIPCP;
        }

        if (entry->type != IPCP_NORMAL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Cannot tear down connections for this IPCP type.");
                return -EIPCP;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (ipcp_disconnect(api, dst, component)) {
                log_err("Could not disconnect IPCP.");
                return -EPERM;
        }

        log_info("%s connection between IPCP %d and %s torn down.",
                 component, api, dst);

        return 0;
}

static int bind_ap(char *   ap,
                   char *   name,
                   uint16_t flags,
                   int      argc,
                   char **  argv)
{
        char * aps;
        char * apn;
        char ** argv_dup = NULL;
        int i;
        char * name_dup = NULL;
        struct apn_entry * e = NULL;
        struct reg_entry * re = NULL;

        if (ap == NULL || name == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        e = apn_table_get(&irmd.apn_table, path_strip(ap));

        if (e == NULL) {
                aps = strdup(path_strip(ap));
                if (aps == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        return -ENOMEM;
                }

                apn = strdup(name);
                if (apn == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        free(aps);
                        return -ENOMEM;
                }

                if ((flags & BIND_AP_AUTO) && argc) {
                /* We need to duplicate argv and set argv[0] to ap. */
                        argv_dup = malloc((argc + 2) * sizeof(*argv_dup));
                        argv_dup[0] = strdup(ap);
                        for (i = 1; i <= argc; ++i) {
                                argv_dup[i] = strdup(argv[i - 1]);
                                if (argv_dup[i] == NULL) {
                                        pthread_rwlock_unlock(&irmd.reg_lock);
                                        argvfree(argv_dup);
                                        log_err("Failed to bind ap %s to  %s.",
                                                ap, name);
                                        free(aps);
                                        free(apn);
                                        return -ENOMEM;
                                }
                        }
                        argv_dup[argc + 1] = NULL;
                }
                e = apn_entry_create(apn, aps, flags, argv_dup);
                if (e == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        free(aps);
                        free(apn);
                        argvfree(argv_dup);
                        return -ENOMEM;
                }

                apn_table_add(&irmd.apn_table, e);

        }

        name_dup = strdup(name);
        if (name_dup == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -ENOMEM;
        }

        if (apn_entry_add_name(e, name_dup)) {
                log_err("Failed adding name.");
                pthread_rwlock_unlock(&irmd.reg_lock);
                free(name_dup);
                return -ENOMEM;
        }

        re = registry_get_entry(&irmd.registry, name);
        if (re != NULL && reg_entry_add_apn(re, e) < 0)
                log_err("Failed adding AP %s for name %s.", ap, name);

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Bound AP %s to name %s.", ap, name);

        return 0;
}

static int bind_api(pid_t  api,
                    char * name)
{
        char * name_dup = NULL;
        struct api_entry * e = NULL;
        struct reg_entry * re = NULL;

        if (name == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        e = api_table_get(&irmd.api_table, api);
        if (e == NULL) {
                log_err("AP-I %d does not exist.", api);
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -1;
        }

        name_dup = strdup(name);
        if (name_dup == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -ENOMEM;
        }

        if (api_entry_add_name(e, name_dup)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Failed to add name %s to api %d.", name, api);
                free(name_dup);
                return -1;
        }

        re = registry_get_entry(&irmd.registry, name);
        if (re != NULL && reg_entry_add_api(re, api) < 0)
                log_err("Failed adding AP-I %d for name %s.", api, name);

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Bound AP-I %d to name %s.", api, name);

        return 0;
}

static int unbind_ap(char * ap,
                     char * name)
{
        struct reg_entry * e;

        if (ap == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (name == NULL)
                apn_table_del(&irmd.apn_table, ap);
        else {
                struct apn_entry * e = apn_table_get(&irmd.apn_table, ap);
                apn_entry_del_name(e, name);
        }

        e = registry_get_entry(&irmd.registry, name);
        if (e != NULL)
                reg_entry_del_apn(e, ap);

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (name  == NULL)
                log_info("AP %s removed.", ap);
        else
                log_info("All names matching %s cleared for %s.", name, ap);

        return 0;
}

static int unbind_api(pid_t        api,
                      const char * name)
{
        struct reg_entry * e;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (name == NULL)
                api_table_del(&irmd.api_table, api);
        else {
                struct api_entry * e = api_table_get(&irmd.api_table, api);
                api_entry_del_name(e, name);
        }

        e = registry_get_entry(&irmd.registry, name);
        if (e != NULL)
                reg_entry_del_api(e, api);

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (name  == NULL)
                log_info("AP-I %d removed.", api);
        else
                log_info("All names matching %s cleared for %d.", name, api);

        return 0;
}

static ssize_t list_ipcps(char *   name,
                          pid_t ** apis)
{
        struct list_head * pos = NULL;
        size_t count = 0;
        int i = 0;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        list_for_each(pos, &irmd.ipcps) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);
                if (wildcard_match(name, tmp->name) == 0)
                        count++;
        }

        if (count == 0) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                return 0;
        }

        *apis = malloc(count * sizeof(pid_t));
        if (*apis == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -1;
        }

        list_for_each(pos, &irmd.ipcps) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);
                if (wildcard_match(name, tmp->name) == 0)
                        (*apis)[i++] = tmp->api;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return count;
}

static int name_reg(const char *  name,
                    char **       difs,
                    size_t        len)
{
        size_t i;
        int ret = 0;
        struct list_head * p = NULL;

        assert(name);
        assert(len);
        assert(difs);
        assert(difs[0]);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (list_is_empty(&irmd.ipcps)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -1;
        }

        if (!registry_has_name(&irmd.registry, name)) {
                struct reg_entry * re =
                        registry_add_name(&irmd.registry, name);
                if (re == NULL) {
                        log_err("Failed creating registry entry for %s.", name);
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        return -1;
                }

                /* check the tables for client APs */
                list_for_each(p, &irmd.api_table) {
                        struct list_head * q;
                        struct api_entry * e =
                                list_entry(p, struct api_entry, next);
                        list_for_each(q, &e->names) {
                                struct str_el * s =
                                        list_entry(q, struct str_el, next);
                                if (!strcmp(s->str, name))
                                        reg_entry_add_api(re, e->api);
                        }
                }

                list_for_each(p, &irmd.apn_table) {
                        struct list_head * q;
                        struct apn_entry * e =
                                list_entry(p, struct apn_entry, next);
                        list_for_each(q, &e->names) {
                                struct str_el * s =
                                        list_entry(q, struct str_el, next);
                                if (!strcmp(s->str, name))
                                        reg_entry_add_apn(re, e);
                        }
                }
        }

        list_for_each(p, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (e->dif_name == NULL)
                        continue;

                for (i = 0; i < len; ++i) {
                        uint8_t * hash;
                        pid_t     api;
                        size_t    len;

                        if (wildcard_match(difs[i], e->dif_name))
                                continue;

                        hash = malloc(IPCP_HASH_LEN(e));
                        if (hash == NULL)
                                break;

                        str_hash(e->dir_hash_algo, hash, name);

                        api = e->api;
                        len = IPCP_HASH_LEN(e);

                        pthread_rwlock_unlock(&irmd.reg_lock);

                        if (ipcp_reg(api, hash, len)) {
                                log_err("Could not register " HASH_FMT
                                        " with IPCP %d.",
                                        HASH_VAL(hash), api);
                                pthread_rwlock_wrlock(&irmd.reg_lock);
                                free(hash);
                                break;
                        }

                        pthread_rwlock_wrlock(&irmd.reg_lock);

                        if (registry_add_name_to_dif(&irmd.registry,
                                                     name,
                                                     e->dif_name,
                                                     e->type) < 0)
                                log_warn("Registered unbound name %s. "
                                         "Registry may be corrupt.",
                                         name);
                        log_info("Registered %s in %s as " HASH_FMT ".",
                                 name, e->dif_name, HASH_VAL(hash));
                        ++ret;

                        free(hash);
                }
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return (ret > 0 ? 0 : -1);
}

static int name_unreg(const char *  name,
                      char **       difs,
                      size_t        len)
{
        size_t i;
        int ret = 0;
        struct list_head * pos = NULL;

        assert(name);
        assert(len);
        assert(difs);
        assert(difs[0]);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        list_for_each(pos, &irmd.ipcps) {
                struct ipcp_entry * e =
                        list_entry(pos, struct ipcp_entry, next);

                if (e->dif_name == NULL)
                        continue;

                for (i = 0; i < len; ++i) {
                        uint8_t * hash;
                        pid_t     api;
                        size_t    len;

                        if (wildcard_match(difs[i], e->dif_name))
                                continue;

                        hash = malloc(IPCP_HASH_LEN(e));
                        if  (hash == NULL)
                                break;

                        str_hash(e->dir_hash_algo, hash, name);

                        api = e->api;
                        len = IPCP_HASH_LEN(e);

                        pthread_rwlock_unlock(&irmd.reg_lock);

                        if (ipcp_unreg(api, hash, len)) {
                                log_err("Could not unregister %s with IPCP %d.",
                                        name, api);
                                pthread_rwlock_wrlock(&irmd.reg_lock);
                                free(hash);
                                break;
                        }

                        pthread_rwlock_wrlock(&irmd.reg_lock);

                        registry_del_name_from_dif(&irmd.registry,
                                                   name,
                                                   e->dif_name);
                        log_info("Unregistered %s from %s.",
                                 name, e->dif_name);
                        ++ret;

                        free(hash);
                }
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return (ret > 0 ? 0 : -1);
}

static int api_announce(pid_t  api,
                        char * apn)
{
        struct api_entry * e = NULL;
        struct apn_entry * a = NULL;
        char * apn_dup;
        if (apn == NULL)
                return -EINVAL;

        apn_dup = strdup(apn);
        if (apn_dup == NULL) {
                return -ENOMEM;
        }

        e = api_entry_create(api, apn_dup);
        if (e == NULL) {
                return -ENOMEM;
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        api_table_add(&irmd.api_table, e);

        /* Copy listen names from apn if it exists. */

        a = apn_table_get(&irmd.apn_table, e->apn);
        if (a != NULL) {
                struct list_head * p;
                list_for_each(p, &a->names) {
                        struct str_el * s = list_entry(p, struct str_el, next);
                        struct str_el * n = malloc(sizeof(*n));
                        if (n == NULL) {
                                pthread_rwlock_unlock(&irmd.reg_lock);
                                return -ENOMEM;
                        }

                        n->str = strdup(s->str);
                        if (n->str == NULL) {
                                pthread_rwlock_unlock(&irmd.reg_lock);
                                free(n);
                                return -ENOMEM;
                        }

                        list_add(&n->next, &e->names);
                        log_dbg("AP-I %d inherits listen name %s from AP %s.",
                                api, n->str, e->apn);
                }
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;
}

static int flow_accept(pid_t              api,
                       struct timespec *  timeo,
                       struct irm_flow ** fl)
{
        struct irm_flow  * f  = NULL;
        struct api_entry * e  = NULL;
        struct reg_entry * re = NULL;
        struct list_head * p  = NULL;

        struct timespec dl;
        struct timespec now;

        pid_t api_n1;
        pid_t api_n;
        int   port_id;
        int   ret;

        if (timeo != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &now);
                ts_add(&now, timeo, &dl);
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        e = api_table_get(&irmd.api_table, api);
        if (e == NULL) {
                /* Can only happen if server called ouroboros_init(NULL); */
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Unknown instance %d calling accept.", api);
                return -EINVAL;
        }

        log_dbg("New instance (%d) of %s added.", api, e->apn);
        log_dbg("This instance accepts flows for:");

        list_for_each(p, &e->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                log_dbg("        %s", s->str);
                re = registry_get_entry(&irmd.registry, s->str);
                if (re != NULL)
                        reg_entry_add_api(re, api);
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        while (true) {
                if (timeo != NULL && ts_diff_ns(&now, &dl) < 0) {
                        log_dbg("Accept timed out.");
                        return -ETIMEDOUT;
                }

                if (irmd_get_state() != IRMD_RUNNING)
                        return -EIRMD;

                ret = api_entry_sleep(e);
                if (ret == -ETIMEDOUT) {
                        clock_gettime(PTHREAD_COND_CLOCK, &now);
                        api_entry_cancel(e);
                        continue;
                }

                if (ret == -1)
                        return -EPIPE;

                if (ret == 0)
                        break;
        }

        if (irmd_get_state() != IRMD_RUNNING) {
                reg_entry_set_state(re, REG_NAME_NULL);
                return -EIRMD;
        }

        pthread_rwlock_rdlock(&irmd.flows_lock);

        f = get_irm_flow_n(api);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_warn("Port_id was not created yet.");
                return -EPERM;
        }

        api_n   = f->n_api;
        api_n1  = f->n_1_api;
        port_id = f->port_id;

        pthread_rwlock_unlock(&irmd.flows_lock);
        pthread_rwlock_rdlock(&irmd.reg_lock);

        e = api_table_get(&irmd.api_table, api);
        if (e == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                pthread_rwlock_wrlock(&irmd.flows_lock);
                list_del(&f->next);
                bmp_release(irmd.port_ids, f->port_id);
                pthread_rwlock_unlock(&irmd.flows_lock);
                ipcp_flow_alloc_resp(api_n1, port_id, api_n, -1);
                clear_irm_flow(f);
                irm_flow_set_state(f, FLOW_NULL);
                irm_flow_destroy(f);
                log_dbg("Process gone while accepting flow.");
                return -EPERM;
        }

        pthread_mutex_lock(&e->state_lock);

        re = e->re;

        pthread_mutex_unlock(&e->state_lock);

        if (reg_entry_get_state(re) != REG_NAME_FLOW_ARRIVED) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                pthread_rwlock_wrlock(&irmd.flows_lock);
                list_del(&f->next);
                bmp_release(irmd.port_ids, f->port_id);
                pthread_rwlock_unlock(&irmd.flows_lock);
                ipcp_flow_alloc_resp(api_n1, port_id, api_n, -1);
                clear_irm_flow(f);
                irm_flow_set_state(f, FLOW_NULL);
                irm_flow_destroy(f);
                log_err("Entry in wrong state.");
                return -EPERM;
        }

        registry_del_api(&irmd.registry, api);

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (ipcp_flow_alloc_resp(api_n1, port_id, api_n, 0)) {
                pthread_rwlock_wrlock(&irmd.flows_lock);
                list_del(&f->next);
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_dbg("Failed to respond to alloc. Port_id invalidated.");
                clear_irm_flow(f);
                irm_flow_set_state(f, FLOW_NULL);
                irm_flow_destroy(f);
                return -EPERM;
        }

        irm_flow_set_state(f, FLOW_ALLOCATED);

        log_info("Flow on port_id %d allocated.", f->port_id);

        *fl = f;

        return 0;
}

static int flow_alloc(pid_t              api,
                      const char *       dst,
                      qoscube_t          cube,
                      struct timespec *  timeo,
                      struct irm_flow ** e)
{
        struct irm_flow *   f;
        struct ipcp_entry * ipcp;
        int                 port_id;
        int                 state;
        uint8_t *           hash;

        ipcp = get_ipcp_by_dst_name(dst, api);
        if (ipcp == NULL) {
                log_info("Destination %s unreachable.", dst);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd.flows_lock);
        port_id = bmp_allocate(irmd.port_ids);
        if (!bmp_is_id_valid(irmd.port_ids, port_id)) {
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_err("Could not allocate port_id.");
                return -EBADF;
        }

        f = irm_flow_create(api, ipcp->api, port_id, cube);
        if (f == NULL) {
                bmp_release(irmd.port_ids, port_id);
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_err("Could not allocate port_id.");
                return -ENOMEM;
        }

        list_add(&f->next, &irmd.irm_flows);

        pthread_rwlock_unlock(&irmd.flows_lock);

        assert(irm_flow_get_state(f) == FLOW_ALLOC_PENDING);

        hash = malloc(IPCP_HASH_LEN(ipcp));
        if  (hash == NULL)
                /* sanitizer cleans this */
                return -ENOMEM;

        str_hash(ipcp->dir_hash_algo, hash, dst);

        if (ipcp_flow_alloc(ipcp->api, port_id, api, hash,
                            IPCP_HASH_LEN(ipcp), cube)) {
                /* sanitizer cleans this */
                log_info("Flow_allocation failed.");
                free(hash);
                return -EAGAIN;
        }

        free(hash);

        state = irm_flow_wait_state(f, FLOW_ALLOCATED, timeo);
        if (state != FLOW_ALLOCATED) {
                if (state == -ETIMEDOUT) {
                        log_dbg("Flow allocation timed out");
                        return -ETIMEDOUT;
                }

                log_info("Pending flow to %s torn down.", dst);
                return -EPIPE;
        }

        assert(irm_flow_get_state(f) == FLOW_ALLOCATED);

        *e = f;

        log_info("Flow on port_id %d allocated.", port_id);

        return 0;
}

static int flow_dealloc(pid_t api,
                        int   port_id)
{
        pid_t n_1_api = -1;
        int   ret = 0;

        struct irm_flow * f = NULL;

        pthread_rwlock_wrlock(&irmd.flows_lock);

        f = get_irm_flow(port_id);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_dbg("Deallocate unknown port %d by %d.", port_id, api);
                return 0;
        }

        if (api == f->n_api) {
                f->n_api = -1;
                n_1_api = f->n_1_api;
        } else if (api == f->n_1_api) {
                f->n_1_api = -1;
        } else {
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_dbg("Dealloc called by wrong AP-I.");
                return -EPERM;
        }

        if (irm_flow_get_state(f) == FLOW_DEALLOC_PENDING) {
                list_del(&f->next);
                if ((kill(f->n_api, 0) < 0 && f->n_1_api == -1) ||
                    (kill(f->n_1_api, 0) < 0 && f->n_api == -1))
                        irm_flow_set_state(f, FLOW_NULL);
                clear_irm_flow(f);
                irm_flow_destroy(f);
                bmp_release(irmd.port_ids, port_id);
                log_info("Completed deallocation of port_id %d by AP-I %d.",
                         port_id, api);
        } else {
                irm_flow_set_state(f, FLOW_DEALLOC_PENDING);
                log_dbg("Partial deallocation of port_id %d by AP-I %d.",
                        port_id, api);
        }

        pthread_rwlock_unlock(&irmd.flows_lock);

        if (n_1_api != -1)
                ret = ipcp_flow_dealloc(n_1_api, port_id);

        return ret;
}

static pid_t auto_execute(char ** argv)
{
        pid_t api;
        struct stat s;

        if (stat(argv[0], &s) != 0) {
                log_warn("Application %s does not exist.", argv[0]);
                return -1;
        }

        if (!(s.st_mode & S_IXUSR)) {
                log_warn("Application %s is not executable.", argv[0]);
                return -1;
        }

        api = fork();
        if (api == -1) {
                log_err("Failed to fork");
                return api;
        }

        if (api != 0) {
                log_info("Instantiated %s as AP-I %d.", argv[0], api);
                return api;
        }

        execv(argv[0], argv);

        log_err("Failed to execute %s.", argv[0]);

        exit(EXIT_FAILURE);
}

static struct irm_flow * flow_req_arr(pid_t           api,
                                      const uint8_t * hash,
                                      qoscube_t       cube)
{
        struct reg_entry * re = NULL;
        struct apn_entry * a  = NULL;
        struct api_entry * e  = NULL;
        struct irm_flow *  f  = NULL;

        struct pid_el *     c_api;
        struct ipcp_entry * ipcp;
        pid_t               h_api   = -1;
        int                 port_id = -1;

        struct timespec wt = {IRMD_REQ_ARR_TIMEOUT / 1000,
                              (IRMD_REQ_ARR_TIMEOUT % 1000) * MILLION};

        log_dbg("Flow req arrived from IPCP %d for " HASH_FMT ".",
                api, HASH_VAL(hash));

        pthread_rwlock_rdlock(&irmd.reg_lock);

        ipcp = get_ipcp_entry_by_api(api);
        if (ipcp == NULL) {
                log_err("IPCP died.");
                return NULL;
        }

        re = registry_get_entry_by_hash(&irmd.registry, ipcp->dir_hash_algo,
                                        hash, IPCP_HASH_LEN(ipcp));
        if (re == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Unknown hash: " HASH_FMT ".", HASH_VAL(hash));
                return NULL;
        }

        log_info("Flow request arrived for %s.", re->name);

        pthread_rwlock_unlock(&irmd.reg_lock);

        /* Give the AP a bit of slop time to call accept */
        if (reg_entry_leave_state(re, REG_NAME_IDLE, &wt) == -1) {
                log_err("No APs for " HASH_FMT ".", HASH_VAL(hash));
                return NULL;
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        switch (reg_entry_get_state(re)) {
        case REG_NAME_IDLE:
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No APs for " HASH_FMT ".", HASH_VAL(hash));
                return NULL;
        case REG_NAME_AUTO_ACCEPT:
                c_api = malloc(sizeof(*c_api));
                if (c_api == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        return NULL;
                }

                reg_entry_set_state(re, REG_NAME_AUTO_EXEC);
                a = apn_table_get_by_apn(&irmd.apn_table,
                                         reg_entry_get_apn(re));

                if (a == NULL || (c_api->pid = auto_execute(a->argv)) < 0) {
                        reg_entry_set_state(re, REG_NAME_AUTO_ACCEPT);
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        log_err("Could not get start apn for reg_entry %s.",
                                re->name);
                        free(c_api);
                        return NULL;
                }

                list_add(&c_api->next, &irmd.spawned_apis);

                pthread_rwlock_unlock(&irmd.reg_lock);

                if (reg_entry_leave_state(re, REG_NAME_AUTO_EXEC, NULL))
                        return NULL;

                pthread_rwlock_wrlock(&irmd.reg_lock);
                /* FALLTHRU */
        case REG_NAME_FLOW_ACCEPT:
                h_api = reg_entry_get_api(re);
                if (h_api == -1) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        log_err("Invalid api returned.");
                        return NULL;
                }

                break;
        default:
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("IRMd in wrong state.");
                return NULL;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);
        pthread_rwlock_wrlock(&irmd.flows_lock);
        port_id = bmp_allocate(irmd.port_ids);
        if (!bmp_is_id_valid(irmd.port_ids, port_id)) {
                pthread_rwlock_unlock(&irmd.flows_lock);
                return NULL;
        }

        f = irm_flow_create(h_api, api, port_id, cube);
        if (f == NULL) {
                bmp_release(irmd.port_ids, port_id);
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_err("Could not allocate port_id.");
                return NULL;
        }

        list_add(&f->next, &irmd.irm_flows);

        pthread_rwlock_unlock(&irmd.flows_lock);
        pthread_rwlock_rdlock(&irmd.reg_lock);

        reg_entry_set_state(re, REG_NAME_FLOW_ARRIVED);

        e = api_table_get(&irmd.api_table, h_api);
        if (e == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                pthread_rwlock_wrlock(&irmd.flows_lock);
                clear_irm_flow(f);
                bmp_release(irmd.port_ids, f->port_id);
                list_del(&f->next);
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_err("Could not get api table entry for %d.", h_api);
                irm_flow_destroy(f);
                return NULL;
        }

        api_entry_wake(e, re);

        pthread_rwlock_unlock(&irmd.reg_lock);

        reg_entry_leave_state(re, REG_NAME_FLOW_ARRIVED, NULL);

        return f;
}

static int flow_alloc_reply(int port_id,
                            int response)
{
        struct irm_flow * f;

        pthread_rwlock_rdlock(&irmd.flows_lock);

        f = get_irm_flow(port_id);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd.flows_lock);
                return -1;
        }

        if (!response)
                irm_flow_set_state(f, FLOW_ALLOCATED);
        else
                irm_flow_set_state(f, FLOW_NULL);

        pthread_rwlock_unlock(&irmd.flows_lock);

        return 0;
}

static void irm_fini(void)
{
        struct list_head * p;
        struct list_head * h;

        if (irmd_get_state() != IRMD_NULL)
                log_warn("Unsafe destroy.");

        pthread_rwlock_wrlock(&irmd.flows_lock);

        if (irmd.port_ids != NULL)
                bmp_destroy(irmd.port_ids);

        pthread_rwlock_unlock(&irmd.flows_lock);

        close(irmd.sockfd);

        if (unlink(IRM_SOCK_PATH))
                log_dbg("Failed to unlink %s.", IRM_SOCK_PATH);

        pthread_rwlock_wrlock(&irmd.reg_lock);
        /* Clear the lists. */
        list_for_each_safe(p, h, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                list_del(&e->next);
                ipcp_entry_destroy(e);
        }

        list_for_each(p, &irmd.spawned_apis) {
                struct pid_el * e = list_entry(p, struct pid_el, next);
                if (kill(e->pid, SIGTERM))
                        log_dbg("Could not send kill signal to %d.", e->pid);
        }

        list_for_each_safe(p, h, &irmd.spawned_apis) {
                struct pid_el * e = list_entry(p, struct pid_el, next);
                int status;
                if (waitpid(e->pid, &status, 0) < 0)
                        log_dbg("Error waiting for %d to exit.", e->pid);
                list_del(&e->next);
                registry_del_api(&irmd.registry, e->pid);
                free(e);
        }

        list_for_each_safe(p, h, &irmd.apn_table) {
                struct apn_entry * e = list_entry(p, struct apn_entry, next);
                list_del(&e->next);
                apn_entry_destroy(e);
        }

        registry_destroy(&irmd.registry);

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (irmd.rdrb != NULL)
                shm_rdrbuff_destroy(irmd.rdrb);

        if (irmd.lf != NULL)
                lockfile_destroy(irmd.lf);

        pthread_mutex_destroy(&irmd.cmd_lock);
        pthread_cond_destroy(&irmd.acc_cond);
        pthread_cond_destroy(&irmd.cmd_cond);
        pthread_rwlock_destroy(&irmd.reg_lock);
        pthread_rwlock_destroy(&irmd.state_lock);
}

void irmd_sig_handler(int         sig,
                      siginfo_t * info,
                      void *      c)
{
        (void) info;
        (void) c;

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                if (irmd_get_state() == IRMD_NULL) {
                        log_info("Patience is bitter, but its fruit is sweet.");
                        return;
                }

                log_info("IRMd shutting down...");
                irmd_set_state(IRMD_NULL);
                break;
        case SIGPIPE:
                log_dbg("Ignored SIGPIPE.");
        default:
                return;
        }
}

void * shm_sanitize(void * o)
{
        struct list_head * p = NULL;
        struct timespec ts = {SHM_SAN_HOLDOFF / 1000,
                              (SHM_SAN_HOLDOFF % 1000) * MILLION};
        ssize_t idx;

        (void) o;

        while (irmd_get_state() == IRMD_RUNNING) {
                if (shm_rdrbuff_wait_full(irmd.rdrb, &ts) == -ETIMEDOUT)
                        continue;

                pthread_rwlock_wrlock(&irmd.flows_lock);

                list_for_each(p, &irmd.irm_flows) {
                        struct irm_flow * f =
                                list_entry(p, struct irm_flow, next);
                        if (kill(f->n_api, 0) < 0) {
                                while ((idx = shm_rbuff_read(f->n_rb)) >= 0)
                                        shm_rdrbuff_remove(irmd.rdrb, idx);
                                continue;
                        }

                        if (kill(f->n_1_api, 0) < 0) {
                                while ((idx = shm_rbuff_read(f->n_1_rb)) >= 0)
                                        shm_rdrbuff_remove(irmd.rdrb, idx);
                                continue;
                        }
                }

                pthread_rwlock_unlock(&irmd.flows_lock);
        }

        return (void *) 0;
}

void * irm_sanitize(void * o)
{
        struct timespec now;
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        struct timespec timeout = {IRMD_CLEANUP_TIMER / BILLION,
                                   IRMD_CLEANUP_TIMER % BILLION};
        int s;

        (void) o;

        while (true) {
                if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
                        log_warn("Failed to get time.");

                if (irmd_get_state() != IRMD_RUNNING) {
                        /* Clean up all flows first to kill mainloops */
                        pthread_rwlock_wrlock(&irmd.flows_lock);
                        list_for_each_safe(p, h, &irmd.irm_flows) {
                                struct irm_flow * f =
                                        list_entry(p, struct irm_flow, next);
                                list_del(&f->next);
                                irm_flow_set_state(f, FLOW_NULL);
                                clear_irm_flow(f);
                                irm_flow_destroy(f);
                        }
                        pthread_rwlock_unlock(&irmd.flows_lock);
                        pthread_rwlock_wrlock(&irmd.reg_lock);
                        /* Clean up api entries as well */
                        list_for_each_safe(p, h, &irmd.api_table) {
                                struct api_entry * e =
                                        list_entry(p, struct api_entry, next);
                                list_del(&e->next);
                                api_entry_destroy(e);
                        }
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        return (void *) 0;
                }

                pthread_rwlock_wrlock(&irmd.reg_lock);

                list_for_each_safe(p, h, &irmd.spawned_apis) {
                        struct pid_el * e = list_entry(p, struct pid_el, next);
                        waitpid(e->pid, &s, WNOHANG);
                        if (kill(e->pid, 0) >= 0)
                                continue;
                        log_dbg("Child process %d died, error %d.", e->pid, s);
                        list_del(&e->next);
                        free(e);
                }

                list_for_each_safe(p, h, &irmd.api_table) {
                        struct api_entry * e =
                                list_entry(p, struct api_entry, next);
                        if (kill(e->api, 0) >= 0)
                                continue;
                        log_dbg("Dead AP-I removed: %d.", e->api);
                        list_del(&e->next);
                        api_entry_destroy(e);
                }

                list_for_each_safe(p, h, &irmd.ipcps) {
                        struct ipcp_entry * e =
                                list_entry(p, struct ipcp_entry, next);
                        if (kill(e->api, 0) >= 0)
                                continue;
                        log_dbg("Dead IPCP removed: %d.", e->api);
                        list_del(&e->next);
                        ipcp_entry_destroy(e);
                }

                list_for_each_safe(p, h, &irmd.registry) {
                        struct list_head * p2;
                        struct list_head * h2;
                        struct reg_entry * e =
                                list_entry(p, struct reg_entry, next);
                        list_for_each_safe(p2, h2, &e->reg_apis) {
                                struct pid_el * a =
                                        list_entry(p2, struct pid_el, next);
                                if (kill(a->pid, 0) >= 0)
                                        continue;
                                log_dbg("Dead AP-I removed from: %d %s.",
                                        a->pid, e->name);
                                reg_entry_del_pid_el(e, a);
                        }
                }

                pthread_rwlock_unlock(&irmd.reg_lock);
                pthread_rwlock_wrlock(&irmd.flows_lock);

                list_for_each_safe(p, h, &irmd.irm_flows) {
                        int ipcpi;
                        int port_id;
                        struct irm_flow * f =
                                list_entry(p, struct irm_flow, next);

                        if (irm_flow_get_state(f) == FLOW_ALLOC_PENDING
                            && ts_diff_ms(&f->t0, &now) > IRMD_FLOW_TIMEOUT) {
                                log_dbg("Pending port_id %d timed out.",
                                         f->port_id);
                                f->n_api = -1;
                                irm_flow_set_state(f, FLOW_DEALLOC_PENDING);
                                ipcpi   = f->n_1_api;
                                port_id = f->port_id;
                                pthread_rwlock_unlock(&irmd.flows_lock);
                                ipcp_flow_dealloc(ipcpi, port_id);
                                pthread_rwlock_wrlock(&irmd.flows_lock);
                                continue;
                        }

                        if (kill(f->n_api, 0) < 0) {
                                struct shm_flow_set * set;
                                log_dbg("AP-I %d gone, deallocating flow %d.",
                                         f->n_api, f->port_id);
                                set = shm_flow_set_open(f->n_api);
                                if (set != NULL)
                                        shm_flow_set_destroy(set);
                                f->n_api = -1;
                                irm_flow_set_state(f, FLOW_DEALLOC_PENDING);
                                ipcpi   = f->n_1_api;
                                port_id = f->port_id;
                                pthread_rwlock_unlock(&irmd.flows_lock);
                                ipcp_flow_dealloc(ipcpi, port_id);
                                pthread_rwlock_wrlock(&irmd.flows_lock);
                                continue;
                        }

                        if (kill(f->n_1_api, 0) < 0) {
                                struct shm_flow_set * set;
                                log_err("IPCP %d gone, flow %d removed.",
                                        f->n_1_api, f->port_id);
                                set = shm_flow_set_open(f->n_api);
                                if (set != NULL)
                                        shm_flow_set_destroy(set);
                                f->n_1_api = -1;
                                irm_flow_set_state(f, FLOW_DEALLOC_PENDING);
                        }
                }

                pthread_rwlock_unlock(&irmd.flows_lock);

                nanosleep(&timeout, NULL);
        }
}

static void * acceptloop(void * o)
{
        int            csockfd;
        struct timeval tv = {(SOCKET_TIMEOUT / 1000),
                             (SOCKET_TIMEOUT % 1000) * 1000};
#if defined(__FreeBSD__) || defined(__APPLE__)
        fd_set         fds;
        struct timeval timeout = {(IRMD_ACCEPT_TIMEOUT / 1000),
                                  (IRMD_ACCEPT_TIMEOUT % 1000) * 1000};
#endif
        (void) o;

        while (irmd_get_state() == IRMD_RUNNING) {
                ssize_t count;
#if defined(__FreeBSD__) || defined(__APPLE__)
                FD_ZERO(&fds);
                FD_SET(irmd.sockfd, &fds);
                if (select(irmd.sockfd + 1, &fds, NULL, NULL, &timeout) <= 0)
                        continue;
#endif
                csockfd = accept(irmd.sockfd, 0, 0);
                if (csockfd < 0)
                        continue;

                if (setsockopt(csockfd, SOL_SOCKET, SO_RCVTIMEO,
                               (void *) &tv, sizeof(tv)))
                        log_warn("Failed to set timeout on socket.");

                pthread_mutex_lock(&irmd.cmd_lock);

                assert(irmd.csockfd == -1);

                count = read(csockfd, irmd.cbuf, IRM_MSG_BUF_SIZE);
                if (count <= 0) {
                        pthread_mutex_unlock(&irmd.cmd_lock);
                        log_err("Failed to read from socket.");
                        close(csockfd);
                        continue;
                }

                irmd.cmd_len = count;
                irmd.csockfd = csockfd;

                pthread_cond_signal(&irmd.cmd_cond);

                while(irmd.csockfd != -1)
                        pthread_cond_wait(&irmd.acc_cond, &irmd.cmd_lock);

                pthread_mutex_unlock(&irmd.cmd_lock);
        }

        return (void *) 0;
}

void * mainloop(void * o)
{
        int             sfd;
        irm_msg_t *     msg;
        buffer_t        buffer;
        struct timespec dl;
        struct timespec to = {(IRMD_ACCEPT_TIMEOUT / 1000),
                              (IRMD_ACCEPT_TIMEOUT % 1000) * MILLION};

        (void) o;

        while (true) {
                int               ret     = 0;
                irm_msg_t         ret_msg = IRM_MSG__INIT;
                struct irm_flow * e       = NULL;
                pid_t *           apis    = NULL;
                struct timespec * timeo   = NULL;
                struct timespec   ts      = {0, 0};

                ret_msg.code = IRM_MSG_CODE__IRM_REPLY;

                clock_gettime(PTHREAD_COND_CLOCK, &dl);
                ts_add(&dl, &to, &dl);

                pthread_mutex_lock(&irmd.cmd_lock);

                while (irmd.csockfd == -1 && ret != -ETIMEDOUT)
                        ret = -pthread_cond_timedwait(&irmd.cmd_cond,
                                                      &irmd.cmd_lock,
                                                      &dl);

                sfd          = irmd.csockfd;
                irmd.csockfd = -1;

                if (sfd == -1) {
                        pthread_mutex_unlock(&irmd.cmd_lock);
                        if (tpm_check())
                                break;
                        continue;
                }

                pthread_cond_signal(&irmd.acc_cond);

                msg = irm_msg__unpack(NULL, irmd.cmd_len, irmd.cbuf);
                if (msg == NULL) {
                        pthread_mutex_unlock(&irmd.cmd_lock);
                        close(sfd);
                        continue;
                }

                pthread_mutex_unlock(&irmd.cmd_lock);

                tpm_dec();

                if (msg->has_timeo_sec) {
                        assert(msg->has_timeo_nsec);

                        ts.tv_sec  = msg->timeo_sec;
                        ts.tv_nsec = msg->timeo_nsec;
                        timeo = &ts;
                }

                switch (msg->code) {
                case IRM_MSG_CODE__IRM_CREATE_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = create_ipcp(msg->dst_name,
                                                     msg->ipcp_type);
                        break;
                case IRM_MSG_CODE__IPCP_CREATE_R:
                        ret_msg.has_result = true;
                        ret_msg.result = create_ipcp_r(msg->api, msg->result);
                        break;
                case IRM_MSG_CODE__IRM_DESTROY_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = destroy_ipcp(msg->api);
                        break;
                case IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = bootstrap_ipcp(msg->api, msg->conf);
                        break;
                case IRM_MSG_CODE__IRM_ENROLL_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = enroll_ipcp(msg->api,
                                                     msg->dif_name[0]);
                        break;
                case IRM_MSG_CODE__IRM_CONNECT_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = connect_ipcp(msg->api,
                                                      msg->dst_name,
                                                      msg->comp_name);
                        break;
                case IRM_MSG_CODE__IRM_DISCONNECT_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = disconnect_ipcp(msg->api,
                                                         msg->dst_name,
                                                         msg->comp_name);
                        break;
                case IRM_MSG_CODE__IRM_BIND_AP:
                        ret_msg.has_result = true;
                        ret_msg.result = bind_ap(msg->ap_name,
                                                 msg->dst_name,
                                                 msg->opts,
                                                 msg->n_args,
                                                 msg->args);
                        break;
                case IRM_MSG_CODE__IRM_UNBIND_AP:
                        ret_msg.has_result = true;
                        ret_msg.result = unbind_ap(msg->ap_name, msg->dst_name);
                        break;
                case IRM_MSG_CODE__IRM_API_ANNOUNCE:
                        ret_msg.has_result = true;
                        ret_msg.result = api_announce(msg->api, msg->ap_name);
                        break;
                case IRM_MSG_CODE__IRM_BIND_API:
                        ret_msg.has_result = true;
                        ret_msg.result = bind_api(msg->api, msg->dst_name);
                        break;
                case IRM_MSG_CODE__IRM_UNBIND_API:
                        ret_msg.has_result = true;
                        ret_msg.result = unbind_api(msg->api, msg->dst_name);
                        break;
                case IRM_MSG_CODE__IRM_LIST_IPCPS:
                        ret_msg.has_result = true;
                        ret_msg.n_apis = list_ipcps(msg->dst_name, &apis);
                        ret_msg.apis = apis;
                        break;
                case IRM_MSG_CODE__IRM_REG:
                        ret_msg.has_result = true;
                        ret_msg.result = name_reg(msg->dst_name,
                                                  msg->dif_name,
                                                  msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_UNREG:
                        ret_msg.has_result = true;
                        ret_msg.result = name_unreg(msg->dst_name,
                                                    msg->dif_name,
                                                    msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ACCEPT:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_accept(msg->api, timeo, &e);
                        if (ret_msg.result == 0) {
                                ret_msg.has_port_id = true;
                                ret_msg.port_id     = e->port_id;
                                ret_msg.has_api     = true;
                                ret_msg.api         = e->n_1_api;
                                ret_msg.has_qoscube = true;
                                ret_msg.qoscube     = e->qc;
                        }
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ALLOC:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_alloc(msg->api, msg->dst_name,
                                                    msg->qoscube, timeo, &e);
                        if (ret_msg.result == 0) {
                                ret_msg.has_port_id = true;
                                ret_msg.port_id     = e->port_id;
                                ret_msg.has_api     = true;
                                ret_msg.api         = e->n_1_api;
                        }
                        break;
                case IRM_MSG_CODE__IRM_FLOW_DEALLOC:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_dealloc(msg->api, msg->port_id);
                        break;
                case IRM_MSG_CODE__IPCP_FLOW_REQ_ARR:
                        e = flow_req_arr(msg->api,
                                         msg->hash.data,
                                         msg->qoscube);
                        ret_msg.has_result = true;
                        if (e == NULL) {
                                ret_msg.result = -1;
                                break;
                        }
                        ret_msg.has_port_id = true;
                        ret_msg.port_id     = e->port_id;
                        ret_msg.has_api     = true;
                        ret_msg.api         = e->n_api;
                        break;
                case IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_alloc_reply(msg->port_id,
                                                          msg->response);
                        break;
                default:
                        log_err("Don't know that message code.");
                        break;
                }

                irm_msg__free_unpacked(msg, NULL);

                if (ret_msg.result == -EPIPE || !ret_msg.has_result) {
                        close(sfd);
                        tpm_inc();
                        continue;
                }

                buffer.len = irm_msg__get_packed_size(&ret_msg);
                if (buffer.len == 0) {
                        log_err("Failed to calculate length of reply message.");
                        if (apis != NULL)
                                free(apis);
                        close(sfd);
                        tpm_inc();
                        continue;
                }

                buffer.data = malloc(buffer.len);
                if (buffer.data == NULL) {
                        if (apis != NULL)
                                free(apis);
                        close(sfd);
                        tpm_inc();
                        continue;
                }

                irm_msg__pack(&ret_msg, buffer.data);

                if (apis != NULL)
                        free(apis);

                if (write(sfd, buffer.data, buffer.len) == -1)
                        if (ret_msg.result != -EIRMD)
                                log_warn("Failed to send reply message.");

                free(buffer.data);
                close(sfd);

                tpm_inc();
        }

        tpm_exit();

        return (void *) 0;
}

static int irm_init(void)
{
        struct stat        st;
        struct timeval     timeout = {(IRMD_ACCEPT_TIMEOUT / 1000),
                                      (IRMD_ACCEPT_TIMEOUT % 1000) * 1000};
        pthread_condattr_t cattr;

        memset(&st, 0, sizeof(st));

        if (pthread_rwlock_init(&irmd.state_lock, NULL)) {
                log_err("Failed to initialize rwlock.");
                goto fail_state_lock;
        }

        if (pthread_rwlock_init(&irmd.reg_lock, NULL)) {
                log_err("Failed to initialize rwlock.");
                goto fail_reg_lock;
        }

        if (pthread_rwlock_init(&irmd.flows_lock, NULL)) {
                log_err("Failed to initialize rwlock.");
                goto fail_flows_lock;
        }

        if (pthread_mutex_init(&irmd.cmd_lock, NULL)) {
                log_err("Failed to initialize mutex.");
                goto fail_cmd_lock;
        }

        if (pthread_condattr_init(&cattr)) {
                log_err("Failed to initialize mutex.");
                goto fail_cmd_lock;
        }

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&irmd.cmd_cond, &cattr)) {
                log_err("Failed to initialize condvar.");
                pthread_condattr_destroy(&cattr);
                goto fail_cmd_cond;
        }

        if (pthread_cond_init(&irmd.acc_cond, &cattr)) {
                log_err("Failed to initialize condvar.");
                pthread_condattr_destroy(&cattr);
                goto fail_acc_cond;
        }

        pthread_condattr_destroy(&cattr);

        list_head_init(&irmd.ipcps);
        list_head_init(&irmd.api_table);
        list_head_init(&irmd.apn_table);
        list_head_init(&irmd.spawned_apis);
        list_head_init(&irmd.registry);
        list_head_init(&irmd.irm_flows);

        irmd.port_ids = bmp_create(SYS_MAX_FLOWS, 0);
        if (irmd.port_ids == NULL) {
                log_err("Failed to create port_ids bitmap.");
                goto fail_port_ids;
        }

        if ((irmd.lf = lockfile_create()) == NULL) {
                if ((irmd.lf = lockfile_open()) == NULL) {
                        log_err("Lockfile error.");
                        goto fail_lockfile;
                }

                if (kill(lockfile_owner(irmd.lf), 0) < 0) {
                        log_info("IRMd didn't properly shut down last time.");
                        shm_rdrbuff_destroy(shm_rdrbuff_open());
                        log_info("Stale resources cleaned.");
                        lockfile_destroy(irmd.lf);
                        irmd.lf = lockfile_create();
                } else {
                        log_info("IRMd already running (%d), exiting.",
                                 lockfile_owner(irmd.lf));
                        lockfile_close(irmd.lf);
                        goto fail_lockfile;
                }
        }

        if (stat(SOCK_PATH, &st) == -1) {
                if (mkdir(SOCK_PATH, 0777)) {
                        log_err("Failed to create sockets directory.");
                        goto fail_stat;
                }
        }

        irmd.sockfd = server_socket_open(IRM_SOCK_PATH);
        if (irmd.sockfd < 0) {
                log_err("Failed to open server socket.");
                goto fail_sock_path;
        }

        if (setsockopt(irmd.sockfd, SOL_SOCKET, SO_RCVTIMEO,
                       (char *) &timeout, sizeof(timeout)) < 0) {
                log_err("Failed setting socket option.");
                goto fail_sock_opt;
        }

        if (chmod(IRM_SOCK_PATH, 0666)) {
                log_err("Failed to chmod socket.");
                goto fail_sock_opt;
        }

        if (irmd.lf == NULL) {
                log_err("Failed to create lockfile.");
                goto fail_sock_opt;
        }

        if ((irmd.rdrb = shm_rdrbuff_create()) == NULL) {
                log_err("Failed to create rdrbuff.");
                goto fail_rdrbuff;
        }

        irmd.csockfd = -1;
        irmd.state   = IRMD_RUNNING;

        log_info("Ouroboros IPC Resource Manager daemon started...");

        return 0;

 fail_rdrbuff:
        shm_rdrbuff_destroy(irmd.rdrb);
 fail_sock_opt:
        close(irmd.sockfd);
 fail_sock_path:
        unlink(IRM_SOCK_PATH);
 fail_stat:
        lockfile_destroy(irmd.lf);
 fail_lockfile:
        bmp_destroy(irmd.port_ids);
 fail_port_ids:
        pthread_cond_destroy(&irmd.acc_cond);
 fail_acc_cond:
        pthread_cond_destroy(&irmd.cmd_cond);
 fail_cmd_cond:
        pthread_mutex_destroy(&irmd.cmd_lock);
 fail_cmd_lock:
        pthread_rwlock_destroy(&irmd.flows_lock);
 fail_flows_lock:
        pthread_rwlock_destroy(&irmd.reg_lock);
 fail_reg_lock:
        pthread_rwlock_destroy(&irmd.state_lock);
 fail_state_lock:
        return -1;
}

static void usage(void)
{
        log_err("Usage: irmd \n\n"
                 "         [--stdout (Print to stdout instead of logs)]\n");
}

int main(int     argc,
         char ** argv)
{
        struct sigaction sig_act;
        sigset_t  sigset;
        bool use_stdout = false;

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        if (geteuid() != 0) {
                log_err("IPC Resource Manager must be run as root.");
                exit(EXIT_FAILURE);
        }

        argc--;
        argv++;
        while (argc > 0) {
                if (strcmp(*argv, "--stdout") == 0) {
                        use_stdout = true;
                        argc--;
                        argv++;
                } else {
                        usage();
                        exit(EXIT_FAILURE);
                }
        }

        /* Init sig_act. */
        memset(&sig_act, 0, sizeof sig_act);

        /* Install signal traps. */
        sig_act.sa_sigaction = &irmd_sig_handler;
        sig_act.sa_flags     = SA_SIGINFO;

        if (sigaction(SIGINT,  &sig_act, NULL) < 0)
                exit(EXIT_FAILURE);
        if (sigaction(SIGTERM, &sig_act, NULL) < 0)
                exit(EXIT_FAILURE);
        if (sigaction(SIGHUP,  &sig_act, NULL) < 0)
                exit(EXIT_FAILURE);
        if (sigaction(SIGPIPE, &sig_act, NULL) < 0)
                exit(EXIT_FAILURE);

        log_init(!use_stdout);

        if (irm_init() < 0)
                goto fail_irm_init;

        if (tpm_init(IRMD_MIN_THREADS, IRMD_ADD_THREADS, mainloop)) {
                irmd_set_state(IRMD_NULL);
                goto fail_tpm_init;
        }

        if (tpm_start()) {
                irmd_set_state(IRMD_NULL);
                goto fail_tpm_start;
        }

        if (pthread_create(&irmd.irm_sanitize, NULL, irm_sanitize, NULL)) {
                irmd_set_state(IRMD_NULL);
                goto fail_irm_sanitize;
        }

        if (pthread_create(&irmd.shm_sanitize, NULL, shm_sanitize, irmd.rdrb)) {
                irmd_set_state(IRMD_NULL);
                goto fail_shm_sanitize;
        }

        if (pthread_create(&irmd.acceptor, NULL, acceptloop, NULL)) {
                irmd_set_state(IRMD_NULL);
                goto fail_acceptor;
        }

        pthread_join(irmd.acceptor, NULL);
        pthread_join(irmd.irm_sanitize, NULL);
        pthread_join(irmd.shm_sanitize, NULL);

        tpm_stop();

        tpm_fini();

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        irm_fini();

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        log_fini();

        log_info("Bye.");

        exit(EXIT_SUCCESS);

 fail_acceptor:
        pthread_join(irmd.shm_sanitize, NULL);
 fail_shm_sanitize:
        pthread_join(irmd.irm_sanitize, NULL);
 fail_irm_sanitize:
        tpm_stop();
 fail_tpm_start:
        tpm_fini();
 fail_tpm_init:
        irm_fini();
 fail_irm_init:
        log_fini();
        exit(EXIT_FAILURE);
}
