/*
 * Ouroboros - Copyright (C) 2016 - 2020
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#define OUROBOROS_PREFIX "irmd"

#include <ouroboros/hash.h>
#include <ouroboros/errno.h>
#include <ouroboros/sockets.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/irm.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/shm_rbuff.h>
#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/qos.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/tpm.h>
#include <ouroboros/logs.h>
#include <ouroboros/version.h>

#include "utils.h"
#include "registry.h"
#include "irm_flow.h"
#include "proc_table.h"
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
#include <spawn.h>

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#define IRMD_CLEANUP_TIMER ((IRMD_FLOW_TIMEOUT / 20) * MILLION) /* ns */
#define SHM_SAN_HOLDOFF    1000 /* ms */
#define IPCP_HASH_LEN(e)   hash_len(e->dir_hash_algo)
#define IB_LEN             SOCK_BUF_SIZE
#define BIND_TIMEOUT       10   /* ms */
#define DEALLOC_TIME       300  /*  s */

enum init_state {
        IPCP_NULL = 0,
        IPCP_BOOT,
        IPCP_LIVE
};

struct ipcp_entry {
        struct list_head next;

        char *           name;
        pid_t            pid;
        enum ipcp_type   type;
        enum hash_algo   dir_hash_algo;
        char *           layer;

        enum init_state  state;
        pthread_cond_t   cond;
        pthread_mutex_t  lock;
};

enum irm_state {
        IRMD_NULL = 0,
        IRMD_RUNNING
};

struct cmd {
        struct list_head next;

        uint8_t          cbuf[IB_LEN];
        size_t           len;
        int              fd;
};

struct {
        struct list_head     registry;     /* registered names known     */
        size_t               n_names;      /* number of names            */

        struct list_head     ipcps;        /* list of ipcps in system    */
        size_t               n_ipcps;      /* number of ipcps            */

        struct list_head     proc_table;   /* processes                  */
        struct list_head     prog_table;   /* programs known             */
        struct list_head     spawned_pids; /* child processes            */
        pthread_rwlock_t     reg_lock;     /* lock for registration info */

        struct bmp *         flow_ids;     /* flow_ids for flows         */
        struct list_head     irm_flows;    /* flow information           */
        pthread_rwlock_t     flows_lock;   /* lock for flows             */

        struct lockfile *    lf;           /* single irmd per system     */
        struct shm_rdrbuff * rdrb;         /* rdrbuff for packets        */

        int                  sockfd;       /* UNIX socket                */

        struct list_head     cmds;         /* pending commands           */
        pthread_cond_t       cmd_cond;     /* cmd signal condvar         */
        pthread_mutex_t      cmd_lock;     /* cmd signal lock            */

        enum irm_state       state;        /* state of the irmd          */
        pthread_rwlock_t     state_lock;   /* lock for the entire irmd   */

        struct tpm *         tpm;          /* thread pool manager        */

        pthread_t            irm_sanitize; /* clean up irmd resources    */
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

        if (f->len != 0) {
                free(f->data);
                f->len = 0;
        }

        while ((idx = shm_rbuff_read(f->n_rb)) >= 0)
                shm_rdrbuff_remove(irmd.rdrb, idx);

        while ((idx = shm_rbuff_read(f->n_1_rb)) >= 0)
                shm_rdrbuff_remove(irmd.rdrb, idx);
}

static struct irm_flow * get_irm_flow(int flow_id)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &irmd.irm_flows) {
                struct irm_flow * e = list_entry(pos, struct irm_flow, next);
                if (e->flow_id == flow_id)
                        return e;
        }

        return NULL;
}

static struct irm_flow * get_irm_flow_n(pid_t n_pid)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &irmd.irm_flows) {
                struct irm_flow * e = list_entry(pos, struct irm_flow, next);
                if (e->n_pid == n_pid &&
                    irm_flow_get_state(e) == FLOW_ALLOC_PENDING)
                        return e;
        }

        return NULL;
}

static struct ipcp_entry * ipcp_entry_create(const char *   name,
                                             enum ipcp_type type)
{
        struct ipcp_entry * e;
        pthread_condattr_t  cattr;

        e = malloc(sizeof(*e));
        if (e == NULL)
                goto fail_malloc;

        e->layer = NULL;
        e->type  = type;
        e->state = IPCP_BOOT;
        e->name  = strdup(name);
        if (e->name == NULL)
                goto fail_name;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&e->cond, &cattr))
                goto fail_cond;

        if (pthread_mutex_init(&e->lock, NULL))
                goto fail_mutex;


        list_head_init(&e->next);

        pthread_condattr_destroy(&cattr);

        return e;

 fail_mutex:
        pthread_cond_destroy(&e->cond);
 fail_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        free(e->name);
 fail_name:
        free(e);
 fail_malloc:
        return NULL;
}

static void ipcp_entry_destroy(struct ipcp_entry * e)
{
        assert(e);

        pthread_mutex_lock(&e->lock);

        while (e->state == IPCP_BOOT)
                pthread_cond_wait(&e->cond, &e->lock);

        pthread_mutex_unlock(&e->lock);

        free(e->name);
        free(e->layer);
        free(e);
}

static void ipcp_entry_set_state(struct ipcp_entry * e,
                                 enum init_state     state)
{
        pthread_mutex_lock(&e->lock);
        e->state = state;
        pthread_cond_broadcast(&e->cond);
        pthread_mutex_unlock(&e->lock);
}

static int ipcp_entry_wait_boot(struct ipcp_entry * e)
{
        int             ret = 0;
        struct timespec dl;
        struct timespec to = {SOCKET_TIMEOUT / 1000,
                              (SOCKET_TIMEOUT % 1000) * MILLION};

        clock_gettime(PTHREAD_COND_CLOCK, &dl);
        ts_add(&dl, &to, &dl);

        pthread_mutex_lock(&e->lock);

        while (e->state == IPCP_BOOT && ret != ETIMEDOUT)
                ret = pthread_cond_timedwait(&e->cond, &e->lock, &dl);

        if (ret == ETIMEDOUT) {
                kill(e->pid, SIGTERM);
                e->state = IPCP_NULL;
                pthread_cond_signal(&e->cond);
        }

        if (e->state != IPCP_LIVE) {
                pthread_mutex_unlock(&e->lock);
                return -1;
        }

        pthread_mutex_unlock(&e->lock);

        return 0;
}

static struct ipcp_entry * get_ipcp_entry_by_pid(pid_t pid)
{
        struct list_head * p;

        list_for_each(p, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (e->pid == pid)
                        return e;
        }

        return NULL;
}

static struct ipcp_entry * get_ipcp_entry_by_name(const char * name)
{
        struct list_head * p;

        list_for_each(p, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (strcmp(name, e->name) == 0)
                        return e;
        }

        return NULL;
}

static struct ipcp_entry * get_ipcp_entry_by_layer(const char * layer)
{
        struct list_head * p;

        list_for_each(p, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (strcmp(layer, e->layer) == 0)
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
        pid_t              pid;
        size_t             len;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        list_for_each_safe(p, h, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (e->layer == NULL || e->pid == src)
                        continue;

                len = IPCP_HASH_LEN(e);

                hash = malloc(len);
                if (hash == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        return NULL;
                }

                str_hash(e->dir_hash_algo, hash, name);

                pid = e->pid;

                pthread_rwlock_unlock(&irmd.reg_lock);

                if (ipcp_query(pid, hash, len) == 0) {
                        free(hash);
                        return e;
                }

                free(hash);

                pthread_rwlock_rdlock(&irmd.reg_lock);
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return NULL;
}

static pid_t create_ipcp(const char *   name,
                         enum ipcp_type type)
{
        struct pid_el *     ppid;
        struct ipcp_entry * entry;
        struct list_head *  p;
        pid_t               pid;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_name(name);
        if (entry != NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("IPCP by that name already exists.");
                return -EPERM;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        ppid = malloc(sizeof(*ppid));
        if (ppid == NULL)
                goto fail_ppid;

        entry = ipcp_entry_create(name, type);
        if (entry == NULL) {
                log_err("Failed to create IPCP entry.");
                goto fail_ipcp_entry;
        }

        pid = ipcp_create(name, type);
        if (pid == -1) {
                log_err("Failed to create IPCP.");
                goto fail_ipcp;
        }

        entry->pid = pid;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        list_for_each(p, &irmd.ipcps) {
                if (list_entry(p, struct ipcp_entry, next)->type > type)
                        break;
        }

        list_add_tail(&entry->next, p);
        ++irmd.n_ipcps;

        ppid->pid = entry->pid;
        list_add(&ppid->next, &irmd.spawned_pids);

        pthread_rwlock_unlock(&irmd.reg_lock);

        /* IRMd maintenance will clean up if booting fails. */
        if (ipcp_entry_wait_boot(entry)) {
                log_err("IPCP %d failed to boot.", pid);
                return -1;
        }

        log_info("Created IPCP %d.", pid);

        return pid;

 fail_ipcp:
        ipcp_entry_destroy(entry);
 fail_ipcp_entry:
        free(ppid);
 fail_ppid:
        return -1;
}

static int create_ipcp_r(pid_t pid,
                         int   result)
{
        struct list_head * p;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        list_for_each(p, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (e->pid == pid) {
                        ipcp_entry_set_state(e, result ? IPCP_NULL : IPCP_LIVE);
                        break;
                }
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;
}

static void clear_spawned_process(pid_t pid)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &(irmd.spawned_pids)) {
                struct pid_el * a = list_entry(p, struct pid_el, next);
                if (a->pid == pid) {
                        list_del(&a->next);
                        free(a);
                }
        }
}

static int destroy_ipcp(pid_t pid)
{
        struct list_head * p;
        struct list_head * h;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        list_for_each_safe(p, h, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                if (e->pid == pid) {
                        clear_spawned_process(pid);
                        if (ipcp_destroy(pid))
                                log_err("Could not destroy IPCP.");
                        list_del(&e->next);
                        ipcp_entry_destroy(e);
                        --irmd.n_ipcps;
                        log_info("Destroyed IPCP %d.", pid);
                }
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;
}

static int bootstrap_ipcp(pid_t               pid,
                          ipcp_config_msg_t * conf)
{
        struct ipcp_entry * entry;
        struct layer_info   info;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_pid(pid);
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

        if (ipcp_bootstrap(entry->pid, conf, &info)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Could not bootstrap IPCP.");
                return -1;
        }

        entry->layer = strdup(info.layer_name);
        if (entry->layer == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_warn("Failed to set name of layer.");
                return -ENOMEM;
        }

        entry->dir_hash_algo = info.dir_hash_algo;

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Bootstrapped IPCP %d in layer %s.",
                 pid, conf->layer_info->layer_name);

        return 0;
}

static int enroll_ipcp(pid_t  pid,
                       char * dst)
{
        struct ipcp_entry * entry = NULL;
        struct layer_info   info;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_pid(pid);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -1;
        }

        if (entry->layer != NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("IPCP in wrong state");
                return -1;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (ipcp_enroll(pid, dst, &info) < 0) {
                log_err("Could not enroll IPCP %d.", pid);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_pid(pid);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -1;
        }

        entry->layer = strdup(info.layer_name);
        if (entry->layer == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Failed to strdup layer_name.");
                return -ENOMEM;
        }

        entry->dir_hash_algo = info.dir_hash_algo;

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Enrolled IPCP %d in layer %s.",
                 pid, info.layer_name);

        return 0;
}

static int connect_ipcp(pid_t        pid,
                        const char * dst,
                        const char * component,
                        qosspec_t    qs)
{
        struct ipcp_entry * entry = NULL;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_pid(pid);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -EIPCP;
        }

        if (entry->type != IPCP_UNICAST && entry->type != IPCP_BROADCAST) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Cannot establish connections for this IPCP type.");
                return -EIPCP;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_dbg("Connecting %s to %s.", component, dst);

        if (ipcp_connect(pid, dst, component, qs)) {
                log_err("Could not connect IPCP.");
                return -EPERM;
        }

        log_info("Established %s connection between IPCP %d and %s.",
                 component, pid, dst);

        return 0;
}

static int disconnect_ipcp(pid_t        pid,
                           const char * dst,
                           const char * component)
{
        struct ipcp_entry * entry = NULL;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        entry = get_ipcp_entry_by_pid(pid);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -EIPCP;
        }

        if (entry->type != IPCP_UNICAST) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Cannot tear down connections for this IPCP type.");
                return -EIPCP;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (ipcp_disconnect(pid, dst, component)) {
                log_err("Could not disconnect IPCP.");
                return -EPERM;
        }

        log_info("%s connection between IPCP %d and %s torn down.",
                 component, pid, dst);

        return 0;
}

static int bind_program(char *   prog,
                        char *   name,
                        uint16_t flags,
                        int      argc,
                        char **  argv)
{
        char *              progs;
        char *              progn;
        char **             argv_dup = NULL;
        int                 i;
        char *              name_dup = NULL;
        struct prog_entry * e        = NULL;
        struct reg_entry *  re       = NULL;

        if (prog == NULL || name == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        e = prog_table_get(&irmd.prog_table, path_strip(prog));
        if (e == NULL) {
                progs = strdup(path_strip(prog));
                if (progs == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        return -ENOMEM;
                }

                progn = strdup(name);
                if (progn == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        free(progs);
                        return -ENOMEM;
                }

                if ((flags & BIND_AUTO) && argc) {
                /* We need to duplicate argv and set argv[0] to prog. */
                        argv_dup = malloc((argc + 2) * sizeof(*argv_dup));
                        argv_dup[0] = strdup(prog);
                        for (i = 1; i <= argc; ++i) {
                                argv_dup[i] = strdup(argv[i - 1]);
                                if (argv_dup[i] == NULL) {
                                        pthread_rwlock_unlock(&irmd.reg_lock);
                                        argvfree(argv_dup);
                                        log_err("Failed to bind program "
                                                "%s to %s.",
                                                prog, name);
                                        free(progs);
                                        free(progn);
                                        return -ENOMEM;
                                }
                        }
                        argv_dup[argc + 1] = NULL;
                }
                e = prog_entry_create(progn, progs, flags, argv_dup);
                if (e == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        free(progs);
                        free(progn);
                        argvfree(argv_dup);
                        return -ENOMEM;
                }
                prog_table_add(&irmd.prog_table, e);
        }

        name_dup = strdup(name);
        if (name_dup == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -ENOMEM;
        }

        if (prog_entry_add_name(e, name_dup)) {
                log_err("Failed adding name.");
                pthread_rwlock_unlock(&irmd.reg_lock);
                free(name_dup);
                return -ENOMEM;
        }

        re = registry_get_entry(&irmd.registry, name);
        if (re != NULL && reg_entry_add_prog(re, e) < 0)
                log_err("Failed adding program %s for name %s.", prog, name);

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Bound program %s to name %s.", prog, name);

        return 0;
}

static int bind_process(pid_t  pid,
                        char * name)
{
        char * name_dup        = NULL;
        struct proc_entry * e  = NULL;
        struct reg_entry *  re = NULL;
        struct timespec     now;
        struct timespec     dl = {0, 10 * MILLION};

        if (name == NULL)
                return -EINVAL;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        ts_add(&dl, &now, &dl);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        while (!kill(pid, 0)) {
                e = proc_table_get(&irmd.proc_table, pid);
                if (e != NULL || ts_diff_ms(&now, &dl) > 0)
                        break;
                clock_gettime(PTHREAD_COND_CLOCK, &now);
                sched_yield();
        }

        if (e == NULL) {
                log_err("Process %d does not %s.", pid,
                        kill(pid, 0) ? "exist" : "respond");
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -1;
        }

        name_dup = strdup(name);
        if (name_dup == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -ENOMEM;
        }

        if (proc_entry_add_name(e, name_dup)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Failed to add name %s to process %d.", name, pid);
                free(name_dup);
                return -1;
        }

        re = registry_get_entry(&irmd.registry, name);
        if (re != NULL && reg_entry_add_pid(re, pid) < 0)
                log_err("Failed adding process %d for name %s.", pid, name);

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Bound process %d to name %s.", pid, name);

        return 0;
}

static int unbind_program(char * prog,
                          char * name)
{
        struct reg_entry * e;

        if (prog == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (name == NULL)
                prog_table_del(&irmd.prog_table, prog);
        else {
                struct prog_entry * en = prog_table_get(&irmd.prog_table, prog);
                if (en == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        return -EINVAL;
                }

                prog_entry_del_name(en, name);

                e = registry_get_entry(&irmd.registry, name);
                if (e != NULL)
                        reg_entry_del_prog(e, prog);
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (name == NULL)
                log_info("Program %s unbound.", prog);
        else
                log_info("All names matching %s unbound for %s.", name, prog);

        return 0;
}

static int unbind_process(pid_t        pid,
                          const char * name)
{
        struct reg_entry * e;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (name == NULL)
                proc_table_del(&irmd.proc_table, pid);
        else {
                struct proc_entry * en = proc_table_get(&irmd.proc_table, pid);
                if (en != NULL)
                        proc_entry_del_name(en, name);

                e = registry_get_entry(&irmd.registry, name);
                if (e != NULL)
                        reg_entry_del_pid(e, pid);
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (name == NULL)
                log_info("Process %d unbound.", pid);
        else
                log_info("All names matching %s unbound for %d.", name, pid);

        return 0;
}

static ssize_t list_ipcps(ipcp_info_msg_t *** ipcps,
                          size_t *            n_ipcps)
{
        struct list_head * p;
        int                i = 0;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        *n_ipcps = irmd.n_ipcps;
        if (*n_ipcps == 0) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                return 0;
        }

        *ipcps = malloc(irmd.n_ipcps * sizeof(**ipcps));
        if (*ipcps == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                *n_ipcps = 0;
                return -ENOMEM;
        }

        list_for_each(p, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                (*ipcps)[i] = malloc(sizeof(***ipcps));
                if ((*ipcps)[i] == NULL) {
                        --i;
                        goto fail;
                }

                ipcp_info_msg__init((*ipcps)[i]);
                (*ipcps)[i]->name = strdup(e->name);
                if ((*ipcps)[i]->name == NULL)
                        goto fail;

                (*ipcps)[i]->layer = strdup(
                        e->layer != NULL ? e->layer : "Not enrolled");
                if ((*ipcps)[i]->layer == NULL)
                        goto fail;

                (*ipcps)[i]->pid    = e->pid;
                (*ipcps)[i++]->type = e->type;
       }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;

 fail:
        pthread_rwlock_unlock(&irmd.reg_lock);
        while (i >= 0) {
                free((*ipcps)[i]->layer);
                free((*ipcps)[i]->name);
                free(*ipcps[i--]);
        }
        free(*ipcps);
        *n_ipcps = 0;
        return -ENOMEM;
}

static int name_create(const char *     name,
                       enum pol_balance pol)
{
        struct reg_entry * re;
        struct list_head * p;

        assert(name);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (registry_has_name(&irmd.registry, name)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Registry entry for %s already exists.", name);
                return -ENAME;
        }

        re = registry_add_name(&irmd.registry, name);
        if (re == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Failed creating registry entry for %s.", name);
                return -ENOMEM;
        }
        ++irmd.n_names;
        reg_entry_set_policy(re, pol);

        /* check the tables for existing bindings */
        list_for_each(p, &irmd.proc_table) {
                struct list_head * q;
                struct proc_entry * e;
                e = list_entry(p, struct proc_entry, next);
                list_for_each(q, &e->names) {
                        struct str_el * s;
                        s = list_entry(q, struct str_el, next);
                        if (!strcmp(s->str, name))
                                reg_entry_add_pid(re, e->pid);
                }
        }

        list_for_each(p, &irmd.prog_table) {
                struct list_head * q;
                struct prog_entry * e;
                e = list_entry(p, struct prog_entry, next);
                list_for_each(q, &e->names) {
                        struct str_el * s;
                        s = list_entry(q, struct str_el, next);
                        if (!strcmp(s->str, name))
                                reg_entry_add_prog(re, e);
                }
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Created new name: %s.", name);

        return 0;
}

static int name_destroy(const char * name)
{
        assert(name);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (!registry_has_name(&irmd.registry, name)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_warn("Registry entry for %s does not exist.", name);
                return -ENAME;
        }

        registry_del_name(&irmd.registry, name);
        --irmd.n_names;

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Destroyed name: %s.", name);

        return 0;
}

static ssize_t list_names(name_info_msg_t *** names,
                          size_t *            n_names)
{
        struct list_head * p;
        int                i = 0;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        *n_names = irmd.n_names;
        if (*n_names == 0) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                return 0;
        }

        *names = malloc(irmd.n_names * sizeof(**names));
        if (*names == NULL) {
                *n_names = 0;
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -ENOMEM;
        }

        list_for_each(p, &irmd.registry) {
                struct reg_entry * e = list_entry(p, struct reg_entry, next);

                (*names)[i] = malloc(sizeof(***names));
                if ((*names)[i] == NULL) {
                        --i;
                        goto fail;
                }

                name_info_msg__init((*names)[i]);
                (*names)[i]->name = strdup(e->name);
                if ((*names)[i]->name == NULL)
                        goto fail;

                (*names)[i++]->pol_lb = e->pol_lb;
       }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;

 fail:
        pthread_rwlock_unlock(&irmd.reg_lock);
        while (i >= 0) {
                free((*names)[i]->name);
                free(*names[i--]);
        }
        free(*names);
        *n_names = 0;
        return -ENOMEM;
}

static int name_reg(const char * name,
                    pid_t        pid)
{
        size_t              len;
        struct ipcp_entry * ipcp;
        uint8_t *           hash;
        int                 err;

        assert(name);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (!registry_has_name(&irmd.registry, name)) {
                err = -ENAME;
                goto fail;
        }

        ipcp = get_ipcp_entry_by_pid(pid);
        if (ipcp == NULL) {
                err = -EIPCP;
                goto fail;
        }

        if (ipcp->layer == NULL) {
                err = -EPERM;
                goto fail;
        }

        len = IPCP_HASH_LEN(ipcp);

        hash = malloc(len);
        if (hash == NULL) {
                err = -ENOMEM;
                goto fail;
        }

        str_hash(ipcp->dir_hash_algo, hash, name);
        pthread_rwlock_unlock(&irmd.reg_lock);

        if (ipcp_reg(pid, hash, len)) {
                log_err("Could not register " HASH_FMT " with IPCP %d.",
                        HASH_VAL(hash), pid);
                free(hash);
                return -1;
        }

        log_info("Registered %s with IPCP %d as " HASH_FMT ".",
                 name, pid, HASH_VAL(hash));

        free(hash);

        return 0;

fail:
        pthread_rwlock_unlock(&irmd.reg_lock);
        return err;
}

static int name_unreg(const char * name,
                      pid_t        pid)
{
        struct ipcp_entry * ipcp;
        int                 err;
        uint8_t *           hash;
        size_t              len;

        assert(name);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        ipcp = get_ipcp_entry_by_pid(pid);
        if (ipcp == NULL) {
                err = -EIPCP;
                goto fail;
        }

        if (ipcp->layer == NULL) {
                err = -EPERM;
                goto fail;
        }

        len = IPCP_HASH_LEN(ipcp);

        hash = malloc(len);
        if  (hash == NULL) {
                err = -ENOMEM;
                goto fail;
        }

        str_hash(ipcp->dir_hash_algo, hash, name);

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (ipcp_unreg(pid, hash, len)) {
                log_err("Could not unregister %s with IPCP %d.", name, pid);
                free(hash);
                return -1;
        }

        log_info("Unregistered %s from %d.", name, pid);

        free(hash);

        return 0;

 fail:
        pthread_rwlock_unlock(&irmd.reg_lock);
        return err;
}

static int proc_announce(pid_t  pid,
                         char * prog)
{
        struct proc_entry * e;
        struct prog_entry * a;
        char *              prog_dup;

        assert(prog);

        prog_dup = strdup(prog);
        if (prog_dup == NULL)
                return -ENOMEM;

        e = proc_entry_create(pid, prog_dup);
        if (e == NULL) {
                free(prog_dup);
                return -ENOMEM;
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        proc_table_add(&irmd.proc_table, e);

        /* Copy listen names from program if it exists. */
        a = prog_table_get(&irmd.prog_table, e->prog);
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
                        log_dbg("Process %d inherits name %s from program %s.",
                                pid, n->str, e->prog);
                }
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;
}

static int flow_accept(pid_t              pid,
                       struct timespec *  timeo,
                       struct irm_flow ** fl,
                       const void *       data,
                       size_t             len)
{
        struct irm_flow  *  f  = NULL;
        struct proc_entry * e  = NULL;
        struct reg_entry *  re = NULL;
        struct list_head *  p  = NULL;

        pid_t pid_n1;
        pid_t pid_n;
        int   flow_id;
        int   ret;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        e = proc_table_get(&irmd.proc_table, pid);
        if (e == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Unknown process %d calling accept.", pid);
                return -EINVAL;
        }

        log_dbg("New instance (%d) of %s added.", pid, e->prog);
        log_dbg("This process accepts flows for:");

        list_for_each(p, &e->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                log_dbg("        %s", s->str);
                re = registry_get_entry(&irmd.registry, s->str);
                if (re != NULL)
                        reg_entry_add_pid(re, pid);
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        ret = proc_entry_sleep(e, timeo);
        if (ret == -ETIMEDOUT)
                return -ETIMEDOUT;

        if (ret == -1)
                return -EPIPE;

        if (irmd_get_state() != IRMD_RUNNING)
                return -EIRMD;

        pthread_rwlock_rdlock(&irmd.flows_lock);

        f = get_irm_flow_n(pid);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_warn("Port_id was not created yet.");
                return -EPERM;
        }

        pid_n   = f->n_pid;
        pid_n1  = f->n_1_pid;
        flow_id = f->flow_id;

        pthread_rwlock_unlock(&irmd.flows_lock);
        pthread_rwlock_rdlock(&irmd.reg_lock);

        e = proc_table_get(&irmd.proc_table, pid);
        if (e == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                pthread_rwlock_wrlock(&irmd.flows_lock);
                list_del(&f->next);
                bmp_release(irmd.flow_ids, f->flow_id);
                pthread_rwlock_unlock(&irmd.flows_lock);
                ipcp_flow_alloc_resp(pid_n1, flow_id, pid_n, -1, NULL, 0);
                clear_irm_flow(f);
                irm_flow_set_state(f, FLOW_NULL);
                irm_flow_destroy(f);
                log_dbg("Process gone while accepting flow.");
                return -EPERM;
        }

        pthread_mutex_lock(&e->lock);

        re = e->re;

        pthread_mutex_unlock(&e->lock);

        if (reg_entry_get_state(re) != REG_NAME_FLOW_ARRIVED) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                pthread_rwlock_wrlock(&irmd.flows_lock);
                list_del(&f->next);
                bmp_release(irmd.flow_ids, f->flow_id);
                pthread_rwlock_unlock(&irmd.flows_lock);
                ipcp_flow_alloc_resp(pid_n1, flow_id, pid_n, -1, NULL, 0);
                clear_irm_flow(f);
                irm_flow_set_state(f, FLOW_NULL);
                irm_flow_destroy(f);
                log_err("Entry in wrong state.");
                return -EPERM;
        }

        registry_del_process(&irmd.registry, pid);

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (f->qs.cypher_s == 0) { /* no crypto requested, don't send pubkey */
                data = NULL;
                len = 0;
        }

        if (ipcp_flow_alloc_resp(pid_n1, flow_id, pid_n, 0, data, len)) {
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

        log_info("Flow on flow_id %d allocated.", f->flow_id);

        *fl = f;

        return 0;
}

static int flow_alloc(pid_t              pid,
                      const char *       dst,
                      qosspec_t          qs,
                      struct timespec *  timeo,
                      struct irm_flow ** e,
                      bool               join,
                      const void *       data,
                      size_t             len)
{
        struct irm_flow *   f;
        struct ipcp_entry * ipcp;
        int                 flow_id;
        int                 state;
        uint8_t *           hash;

        ipcp = join ? get_ipcp_entry_by_layer(dst)
                    : get_ipcp_by_dst_name(dst, pid);
        if (ipcp == NULL) {
                log_info("Destination %s unreachable.", dst);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd.flows_lock);
        flow_id = bmp_allocate(irmd.flow_ids);
        if (!bmp_is_id_valid(irmd.flow_ids, flow_id)) {
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_err("Could not allocate flow_id.");
                return -EBADF;
        }

        f = irm_flow_create(pid, ipcp->pid, flow_id, qs);
        if (f == NULL) {
                bmp_release(irmd.flow_ids, flow_id);
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_err("Could not allocate flow_id.");
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

        if (join) {
                if (ipcp_flow_join(ipcp->pid, flow_id, pid, hash,
                                   IPCP_HASH_LEN(ipcp), qs)) {
                        /* sanitizer cleans this */
                        log_info("Flow_join failed.");
                        free(hash);
                        return -EAGAIN;
                }
        } else {
                if (ipcp_flow_alloc(ipcp->pid, flow_id, pid, hash,
                                    IPCP_HASH_LEN(ipcp), qs, data, len)) {
                        /* sanitizer cleans this */
                        log_info("Flow_allocation failed.");
                        free(hash);
                        return -EAGAIN;
                }
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

        log_info("Flow on flow_id %d allocated.", flow_id);

        return 0;
}

static int flow_dealloc(pid_t pid,
                        int   flow_id,
                        time_t timeo)
{
        pid_t n_1_pid = -1;
        int   ret = 0;

        struct irm_flow * f = NULL;

        pthread_rwlock_wrlock(&irmd.flows_lock);

        f = get_irm_flow(flow_id);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_dbg("Deallocate unknown port %d by %d.", flow_id, pid);
                return 0;
        }

        if (pid == f->n_pid) {
                f->n_pid = -1;
                n_1_pid = f->n_1_pid;
        } else if (pid == f->n_1_pid) {
                f->n_1_pid = -1;
        } else {
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_dbg("Dealloc called by wrong process.");
                return -EPERM;
        }

        if (irm_flow_get_state(f) == FLOW_DEALLOC_PENDING) {
                list_del(&f->next);
                if ((kill(f->n_pid, 0) < 0 && f->n_1_pid == -1) ||
                    (kill(f->n_1_pid, 0) < 0 && f->n_pid == -1))
                        irm_flow_set_state(f, FLOW_NULL);
                clear_irm_flow(f);
                irm_flow_destroy(f);
                bmp_release(irmd.flow_ids, flow_id);
                log_info("Completed deallocation of flow_id %d by process %d.",
                         flow_id, pid);
        } else {
                irm_flow_set_state(f, FLOW_DEALLOC_PENDING);
                log_dbg("Partial deallocation of flow_id %d by process %d.",
                        flow_id, pid);
        }

        pthread_rwlock_unlock(&irmd.flows_lock);

        if (n_1_pid != -1)
                ret = ipcp_flow_dealloc(n_1_pid, flow_id, timeo);

        return ret;
}

static pid_t auto_execute(char ** argv)
{
        pid_t       pid;
        struct stat s;

        if (stat(argv[0], &s) != 0) {
                log_warn("Program %s does not exist.", argv[0]);
                return -1;
        }

        if (!(s.st_mode & S_IXUSR)) {
                log_warn("Program %s is not executable.", argv[0]);
                return -1;
        }

        if (posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL)) {
                log_err("Failed to spawn new process");
                return -1;
        }

        log_info("Instantiated %s as process %d.", argv[0], pid);

        return pid;
}

static struct irm_flow * flow_req_arr(pid_t           pid,
                                      const uint8_t * hash,
                                      qosspec_t       qs,
                                      const void *    data,
                                      size_t          len)
{
        struct reg_entry *  re = NULL;
        struct prog_entry * a  = NULL;
        struct proc_entry * e  = NULL;
        struct irm_flow *   f  = NULL;

        struct pid_el *     c_pid;
        struct ipcp_entry * ipcp;
        pid_t               h_pid   = -1;
        int                 flow_id = -1;

        struct timespec wt = {IRMD_REQ_ARR_TIMEOUT / 1000,
                              (IRMD_REQ_ARR_TIMEOUT % 1000) * MILLION};

        log_dbg("Flow req arrived from IPCP %d for " HASH_FMT ".",
                pid, HASH_VAL(hash));

        pthread_rwlock_rdlock(&irmd.reg_lock);

        ipcp = get_ipcp_entry_by_pid(pid);
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

        /* Give the process a bit of slop time to call accept */
        if (reg_entry_leave_state(re, REG_NAME_IDLE, &wt) == -1) {
                log_err("No processes for " HASH_FMT ".", HASH_VAL(hash));
                return NULL;
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        switch (reg_entry_get_state(re)) {
        case REG_NAME_IDLE:
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No processes for " HASH_FMT ".", HASH_VAL(hash));
                return NULL;
        case REG_NAME_AUTO_ACCEPT:
                c_pid = malloc(sizeof(*c_pid));
                if (c_pid == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        return NULL;
                }

                reg_entry_set_state(re, REG_NAME_AUTO_EXEC);
                a = prog_table_get(&irmd.prog_table,
                                   reg_entry_get_prog(re));

                if (a == NULL || (c_pid->pid = auto_execute(a->argv)) < 0) {
                        reg_entry_set_state(re, REG_NAME_AUTO_ACCEPT);
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        log_err("Could not start program for reg_entry %s.",
                                re->name);
                        free(c_pid);
                        return NULL;
                }

                list_add(&c_pid->next, &irmd.spawned_pids);

                pthread_rwlock_unlock(&irmd.reg_lock);

                if (reg_entry_leave_state(re, REG_NAME_AUTO_EXEC, NULL))
                        return NULL;

                pthread_rwlock_wrlock(&irmd.reg_lock);
                /* FALLTHRU */
        case REG_NAME_FLOW_ACCEPT:
                h_pid = reg_entry_get_pid(re);
                if (h_pid == -1) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        log_err("Invalid process id returned.");
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

        flow_id = bmp_allocate(irmd.flow_ids);
        if (!bmp_is_id_valid(irmd.flow_ids, flow_id)) {
                pthread_rwlock_unlock(&irmd.flows_lock);
                return NULL;
        }

        f = irm_flow_create(h_pid, pid, flow_id, qs);
        if (f == NULL) {
                bmp_release(irmd.flow_ids, flow_id);
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_err("Could not allocate flow_id.");
                return NULL;
        }

        if (len != 0) {
                assert(data);
                f->data = malloc(len);
                if (f->data == NULL) {
                        bmp_release(irmd.flow_ids, flow_id);
                        pthread_rwlock_unlock(&irmd.flows_lock);
                        log_err("Could not piggyback data.");
                        return NULL;
                }

                f->len = len;

                memcpy(f->data, data, len);
        }

        list_add(&f->next, &irmd.irm_flows);

        pthread_rwlock_unlock(&irmd.flows_lock);
        pthread_rwlock_rdlock(&irmd.reg_lock);

        reg_entry_set_state(re, REG_NAME_FLOW_ARRIVED);

        e = proc_table_get(&irmd.proc_table, h_pid);
        if (e == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                pthread_rwlock_wrlock(&irmd.flows_lock);
                clear_irm_flow(f);
                bmp_release(irmd.flow_ids, f->flow_id);
                list_del(&f->next);
                pthread_rwlock_unlock(&irmd.flows_lock);
                log_err("Could not get process table entry for %d.", h_pid);
                free(f->data);
                f->len = 0;
                irm_flow_destroy(f);
                return NULL;
        }

        proc_entry_wake(e, re);

        pthread_rwlock_unlock(&irmd.reg_lock);

        reg_entry_leave_state(re, REG_NAME_FLOW_ARRIVED, NULL);

        return f;
}

static int flow_alloc_reply(int          flow_id,
                            int          response,
                            const void * data,
                            size_t       len)
{
        struct irm_flow * f;

        pthread_rwlock_rdlock(&irmd.flows_lock);

        f = get_irm_flow(flow_id);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd.flows_lock);
                return -1;
        }

        if (!response)
                irm_flow_set_state(f, FLOW_ALLOCATED);
        else
                irm_flow_set_state(f, FLOW_NULL);

        f->data = malloc(len);
        if (f->data == NULL) {
                pthread_rwlock_unlock(&irmd.flows_lock);
                return -1;
        }
        memcpy(f->data, data, len);
        f->len = len;

        pthread_rwlock_unlock(&irmd.flows_lock);

        return 0;
}

static void irm_fini(void)
{
        struct list_head * p;
        struct list_head * h;

        if (irmd_get_state() != IRMD_NULL)
                log_warn("Unsafe destroy.");

        pthread_rwlock_wrlock(&irmd.reg_lock);

        /* Clear the lists. */
        list_for_each_safe(p, h, &irmd.ipcps) {
                struct ipcp_entry * e = list_entry(p, struct ipcp_entry, next);
                list_del(&e->next);
                ipcp_entry_destroy(e);
        }

        list_for_each(p, &irmd.spawned_pids) {
                struct pid_el * e = list_entry(p, struct pid_el, next);
                if (kill(e->pid, SIGTERM))
                        log_dbg("Could not send kill signal to %d.", e->pid);
        }

        list_for_each_safe(p, h, &irmd.spawned_pids) {
                struct pid_el * e = list_entry(p, struct pid_el, next);
                int status;
                if (waitpid(e->pid, &status, 0) < 0)
                        log_dbg("Error waiting for %d to exit.", e->pid);
                list_del(&e->next);
                registry_del_process(&irmd.registry, e->pid);
                free(e);
        }

        list_for_each_safe(p, h, &irmd.prog_table) {
                struct prog_entry * e = list_entry(p, struct prog_entry, next);
                list_del(&e->next);
                prog_entry_destroy(e);
        }

        list_for_each_safe(p, h, &irmd.proc_table) {
                struct proc_entry * e = list_entry(p, struct proc_entry, next);
                list_del(&e->next);
                e->state = PROC_INIT; /* sanitizer already joined */
                proc_entry_destroy(e);
        }

        registry_destroy(&irmd.registry);

        pthread_rwlock_unlock(&irmd.reg_lock);

        close(irmd.sockfd);

        if (unlink(IRM_SOCK_PATH))
                log_dbg("Failed to unlink %s.", IRM_SOCK_PATH);

        pthread_rwlock_wrlock(&irmd.flows_lock);

        if (irmd.flow_ids != NULL)
                bmp_destroy(irmd.flow_ids);

        list_for_each_safe(p, h, &irmd.irm_flows) {
                struct irm_flow * f = list_entry(p, struct irm_flow, next);
                list_del(&f->next);
                irm_flow_destroy(f);
        }

        pthread_rwlock_unlock(&irmd.flows_lock);


        if (irmd.rdrb != NULL)
                shm_rdrbuff_destroy(irmd.rdrb);

        if (irmd.lf != NULL)
                lockfile_destroy(irmd.lf);

        pthread_mutex_destroy(&irmd.cmd_lock);
        pthread_cond_destroy(&irmd.cmd_cond);
        pthread_rwlock_destroy(&irmd.flows_lock);
        pthread_rwlock_destroy(&irmd.reg_lock);
        pthread_rwlock_destroy(&irmd.state_lock);

#ifdef HAVE_FUSE
        if (rmdir(FUSE_PREFIX))
                log_dbg("Failed to remove " FUSE_PREFIX);
#endif
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

                if (irmd_get_state() != IRMD_RUNNING)
                        return (void *) 0;

                pthread_rwlock_wrlock(&irmd.reg_lock);

                list_for_each_safe(p, h, &irmd.spawned_pids) {
                        struct pid_el * e = list_entry(p, struct pid_el, next);
                        waitpid(e->pid, &s, WNOHANG);
                        if (kill(e->pid, 0) >= 0)
                                continue;
                        log_dbg("Child process %d died, error %d.", e->pid, s);
                        list_del(&e->next);
                        free(e);
                }

                list_for_each_safe(p, h, &irmd.proc_table) {
                        struct proc_entry * e =
                                list_entry(p, struct proc_entry, next);
                        if (kill(e->pid, 0) >= 0)
                                continue;
                        log_dbg("Dead process removed: %d.", e->pid);
                        list_del(&e->next);
                        proc_entry_destroy(e);
                }

                list_for_each_safe(p, h, &irmd.ipcps) {
                        struct ipcp_entry * e =
                                list_entry(p, struct ipcp_entry, next);
                        if (kill(e->pid, 0) >= 0)
                                continue;
                        log_dbg("Dead IPCP removed: %d.", e->pid);
                        list_del(&e->next);
                        ipcp_entry_destroy(e);
                }

                list_for_each_safe(p, h, &irmd.registry) {
                        struct list_head * p2;
                        struct list_head * h2;
                        struct reg_entry * e =
                                list_entry(p, struct reg_entry, next);
                        list_for_each_safe(p2, h2, &e->reg_pids) {
                                struct pid_el * a =
                                        list_entry(p2, struct pid_el, next);
                                if (kill(a->pid, 0) >= 0)
                                        continue;
                                log_dbg("Dead process removed from: %d %s.",
                                        a->pid, e->name);
                                reg_entry_del_pid_el(e, a);
                        }
                }

                pthread_rwlock_unlock(&irmd.reg_lock);
                pthread_rwlock_wrlock(&irmd.flows_lock);

                list_for_each_safe(p, h, &irmd.irm_flows) {
                        int ipcpi;
                        int flow_id;
                        struct irm_flow * f =
                                list_entry(p, struct irm_flow, next);

                        if (irm_flow_get_state(f) == FLOW_ALLOC_PENDING
                            && ts_diff_ms(&f->t0, &now) > IRMD_FLOW_TIMEOUT) {
                                log_dbg("Pending flow_id %d timed out.",
                                         f->flow_id);
                                f->n_pid = -1;
                                irm_flow_set_state(f, FLOW_DEALLOC_PENDING);
                                continue;
                        }

                        if (kill(f->n_pid, 0) < 0) {
                                log_dbg("Process %d gone, deallocating "
                                        "flow %d.",
                                         f->n_pid, f->flow_id);
                                f->n_pid = -1;
                                irm_flow_set_state(f, FLOW_DEALLOC_PENDING);
                                ipcpi   = f->n_1_pid;
                                flow_id = f->flow_id;
                                pthread_rwlock_unlock(&irmd.flows_lock);
                                ipcp_flow_dealloc(ipcpi, flow_id, DEALLOC_TIME);
                                pthread_rwlock_wrlock(&irmd.flows_lock);
                                continue;
                        }

                        if (kill(f->n_1_pid, 0) < 0) {
                                struct shm_flow_set * set;
                                log_err("IPCP %d gone, flow %d removed.",
                                        f->n_1_pid, f->flow_id);
                                set = shm_flow_set_open(f->n_pid);
                                if (set != NULL)
                                        shm_flow_set_destroy(set);
                                f->n_1_pid = -1;
                                irm_flow_set_state(f, FLOW_DEALLOC_PENDING);
                        }
                }

                pthread_rwlock_unlock(&irmd.flows_lock);

                nanosleep(&timeout, NULL);
        }
}

static void close_ptr(void * o)
{
        close(*((int *) o));
}

static void * acceptloop(void * o)
{
        int            csockfd;
        struct timeval tv = {(SOCKET_TIMEOUT / 1000),
                             (SOCKET_TIMEOUT % 1000) * 1000};

        (void) o;

        while (irmd_get_state() == IRMD_RUNNING) {
                struct cmd * cmd;

                csockfd = accept(irmd.sockfd, 0, 0);
                if (csockfd < 0)
                        continue;

                if (setsockopt(csockfd, SOL_SOCKET, SO_RCVTIMEO,
                               (void *) &tv, sizeof(tv)))
                        log_warn("Failed to set timeout on socket.");

                cmd = malloc(sizeof(*cmd));
                if (cmd == NULL) {
                        log_err("Out of memory.");
                        close(csockfd);
                        break;
                }

                pthread_cleanup_push(close_ptr, &csockfd);
                pthread_cleanup_push(free, cmd);

                cmd->len = read(csockfd, cmd->cbuf, SOCK_BUF_SIZE);

                pthread_cleanup_pop(false);
                pthread_cleanup_pop(false);

                if (cmd->len <= 0) {
                        log_err("Failed to read from socket.");
                        close(csockfd);
                        free(cmd);
                        continue;
                }

                cmd->fd  = csockfd;

                pthread_mutex_lock(&irmd.cmd_lock);

                list_add(&cmd->next, &irmd.cmds);

                pthread_cond_signal(&irmd.cmd_cond);

                pthread_mutex_unlock(&irmd.cmd_lock);
        }

        return (void *) 0;
}

static void free_msg(void * o)
{
        irm_msg__free_unpacked((irm_msg_t *) o, NULL);
}

static void * mainloop(void * o)
{
        int             sfd;
        irm_msg_t *     msg;
        buffer_t        buffer;

        (void) o;

        while (true) {
                irm_msg_t       * ret_msg;
                struct irm_flow * e       = NULL;
                struct timespec * timeo   = NULL;
                struct timespec   ts      = {0, 0};
                struct cmd *      cmd;
                int               result;

                ret_msg = malloc(sizeof(*ret_msg));
                if (ret_msg == NULL)
                        return (void *) -1;

                irm_msg__init(ret_msg);

                ret_msg->code = IRM_MSG_CODE__IRM_REPLY;

                pthread_mutex_lock(&irmd.cmd_lock);

                pthread_cleanup_push(free_msg, ret_msg);
                pthread_cleanup_push((void *)(void *) pthread_mutex_unlock,
                                     &irmd.cmd_lock);

                while (list_is_empty(&irmd.cmds))
                        pthread_cond_wait(&irmd.cmd_cond, &irmd.cmd_lock);

                cmd = list_last_entry(&irmd.cmds, struct cmd, next);
                list_del(&cmd->next);

                pthread_cleanup_pop(true);
                pthread_cleanup_pop(false);

                msg = irm_msg__unpack(NULL, cmd->len, cmd->cbuf);
                sfd = cmd->fd;

                free(cmd);

                if (msg == NULL) {
                        close(sfd);
                        irm_msg__free_unpacked(msg, NULL);
                        continue;
                }

                tpm_dec(irmd.tpm);

                if (msg->has_timeo_sec) {
                        assert(msg->has_timeo_nsec);

                        ts.tv_sec  = msg->timeo_sec;
                        ts.tv_nsec = msg->timeo_nsec;
                        timeo = &ts;
                }

                pthread_cleanup_push(close_ptr, &sfd);
                pthread_cleanup_push(free_msg, msg);
                pthread_cleanup_push(free_msg, ret_msg);

                switch (msg->code) {
                case IRM_MSG_CODE__IRM_CREATE_IPCP:
                        result = create_ipcp(msg->name, msg->ipcp_type);
                        break;
                case IRM_MSG_CODE__IPCP_CREATE_R:
                        result = create_ipcp_r(msg->pid, msg->result);
                        break;
                case IRM_MSG_CODE__IRM_DESTROY_IPCP:
                        result = destroy_ipcp(msg->pid);
                        break;
                case IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP:
                        result = bootstrap_ipcp(msg->pid, msg->conf);
                        break;
                case IRM_MSG_CODE__IRM_ENROLL_IPCP:
                        result = enroll_ipcp(msg->pid, msg->dst);
                        break;
                case IRM_MSG_CODE__IRM_CONNECT_IPCP:
                        result = connect_ipcp(msg->pid, msg->dst, msg->comp,
                                              msg_to_spec(msg->qosspec));
                        break;
                case IRM_MSG_CODE__IRM_DISCONNECT_IPCP:
                        result = disconnect_ipcp(msg->pid, msg->dst, msg->comp);
                        break;
                case IRM_MSG_CODE__IRM_BIND_PROGRAM:
                        result = bind_program(msg->prog,
                                              msg->name,
                                              msg->opts,
                                              msg->n_args,
                                              msg->args);
                        break;
                case IRM_MSG_CODE__IRM_UNBIND_PROGRAM:
                        result = unbind_program(msg->prog, msg->name);
                        break;
                case IRM_MSG_CODE__IRM_PROC_ANNOUNCE:
                        result = proc_announce(msg->pid, msg->prog);
                        break;
                case IRM_MSG_CODE__IRM_BIND_PROCESS:
                        result = bind_process(msg->pid, msg->name);
                        break;
                case IRM_MSG_CODE__IRM_UNBIND_PROCESS:
                        result = unbind_process(msg->pid, msg->name);
                        break;
                case IRM_MSG_CODE__IRM_LIST_IPCPS:
                        result = list_ipcps(&ret_msg->ipcps, &ret_msg->n_ipcps);
                        break;
                case IRM_MSG_CODE__IRM_CREATE_NAME:
                        result = name_create(msg->names[0]->name,
                                             msg->names[0]->pol_lb);
                        break;
                case IRM_MSG_CODE__IRM_DESTROY_NAME:
                        result = name_destroy(msg->name);
                        break;
                case IRM_MSG_CODE__IRM_LIST_NAMES:
                        result = list_names(&ret_msg->names, &ret_msg->n_names);
                        break;
                case IRM_MSG_CODE__IRM_REG_NAME:
                        result = name_reg(msg->name, msg->pid);
                        break;
                case IRM_MSG_CODE__IRM_UNREG_NAME:
                        result = name_unreg(msg->name, msg->pid);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ACCEPT:
                        assert(msg->pk.len > 0 ? msg->pk.data != NULL
                               : msg->pk.data == NULL);
                        result = flow_accept(msg->pid, timeo, &e,
                                             msg->pk.data, msg->pk.len);
                        if (result == 0) {
                                qosspec_msg_t qs_msg;
                                ret_msg->has_flow_id = true;
                                ret_msg->flow_id     = e->flow_id;
                                ret_msg->has_pid     = true;
                                ret_msg->pid         = e->n_1_pid;
                                qs_msg = spec_to_msg(&e->qs);
                                ret_msg->qosspec     = &qs_msg;
                                ret_msg->has_pk      = true;
                                ret_msg->pk.data     = e->data;
                                ret_msg->pk.len      = e->len;
                                e->len = 0; /* Data is free'd with ret_msg */
                        }
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ALLOC:
                        assert(msg->pk.len > 0 ? msg->pk.data != NULL
                                               : msg->pk.data == NULL);
                        result = flow_alloc(msg->pid, msg->dst,
                                            msg_to_spec(msg->qosspec),
                                            timeo, &e, false, msg->pk.data,
                                            msg->pk.len);
                        if (result == 0) {
                                ret_msg->has_flow_id = true;
                                ret_msg->flow_id     = e->flow_id;
                                ret_msg->has_pid     = true;
                                ret_msg->pid         = e->n_1_pid;
                                ret_msg->has_pk      = true;
                                ret_msg->pk.data     = e->data;
                                ret_msg->pk.len      = e->len;
                                e->len = 0; /* Data is free'd with ret_msg */
                        }
                        break;
                case IRM_MSG_CODE__IRM_FLOW_JOIN:
                        assert(msg->pk.len == 0 && msg->pk.data == NULL);
                        result = flow_alloc(msg->pid, msg->dst,
                                            msg_to_spec(msg->qosspec),
                                            timeo, &e, true, NULL, 0);
                        if (result == 0) {
                                ret_msg->has_flow_id = true;
                                ret_msg->flow_id     = e->flow_id;
                                ret_msg->has_pid     = true;
                                ret_msg->pid         = e->n_1_pid;
                        }
                        break;
                case IRM_MSG_CODE__IRM_FLOW_DEALLOC:
                        result = flow_dealloc(msg->pid,
                                              msg->flow_id,
                                              msg->timeo_sec);
                        break;
                case IRM_MSG_CODE__IPCP_FLOW_REQ_ARR:
                        assert(msg->pk.len > 0 ? msg->pk.data != NULL
                                               : msg->pk.data == NULL);
                        e = flow_req_arr(msg->pid,
                                         msg->hash.data,
                                         msg_to_spec(msg->qosspec),
                                         msg->pk.data,
                                         msg->pk.len);
                        result = (e == NULL ? -1 : 0);
                        if (result == 0) {
                                ret_msg->has_flow_id = true;
                                ret_msg->flow_id     = e->flow_id;
                                ret_msg->has_pid     = true;
                                ret_msg->pid         = e->n_pid;
                        }
                        break;
                case IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY:
                        assert(msg->pk.len > 0 ? msg->pk.data != NULL
                                               : msg->pk.data == NULL);
                        result = flow_alloc_reply(msg->flow_id,
                                                  msg->response,
                                                  msg->pk.data,
                                                  msg->pk.len);
                        break;
                default:
                        log_err("Don't know that message code.");
                        result = -1;
                        break;
                }

                pthread_cleanup_pop(false);
                pthread_cleanup_pop(true);
                pthread_cleanup_pop(false);

                if (result == -EPIPE)
                        goto fail;

                ret_msg->has_result = true;
                ret_msg->result     = result;

                buffer.len = irm_msg__get_packed_size(ret_msg);
                if (buffer.len == 0) {
                        log_err("Failed to calculate length of reply message.");
                        goto fail;
                }

                buffer.data = malloc(buffer.len);
                if (buffer.data == NULL) {
                        log_err("Failed to malloc buffer.");
                        goto fail;
                }

                irm_msg__pack(ret_msg, buffer.data);

                /* Can't free the qosspec. */
                ret_msg->qosspec = NULL;
                irm_msg__free_unpacked(ret_msg, NULL);

                pthread_cleanup_push(close_ptr, &sfd);

                if (write(sfd, buffer.data, buffer.len) == -1)
                        if (result != -EIRMD)
                                log_warn("Failed to send reply message.");

                free(buffer.data);

                pthread_cleanup_pop(true);

                tpm_inc(irmd.tpm);

                continue;
 fail:
                irm_msg__free_unpacked(ret_msg, NULL);
                close(sfd);
                tpm_inc(irmd.tpm);
                continue;
        }

        return (void *) 0;
}

static int irm_init(void)
{
        struct stat        st;
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

        pthread_condattr_destroy(&cattr);

        list_head_init(&irmd.ipcps);
        list_head_init(&irmd.proc_table);
        list_head_init(&irmd.prog_table);
        list_head_init(&irmd.spawned_pids);
        list_head_init(&irmd.registry);
        list_head_init(&irmd.irm_flows);
        list_head_init(&irmd.cmds);

        irmd.flow_ids = bmp_create(SYS_MAX_FLOWS, 0);
        if (irmd.flow_ids == NULL) {
                log_err("Failed to create flow_ids bitmap.");
                goto fail_flow_ids;
        }

        if ((irmd.lf = lockfile_create()) == NULL) {
                if ((irmd.lf = lockfile_open()) == NULL) {
                        log_err("Lockfile error.");
                        goto fail_lockfile;
                }

                if (kill(lockfile_owner(irmd.lf), 0) < 0) {
                        log_info("IRMd didn't properly shut down last time.");
                        shm_rdrbuff_purge();
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

        if (irmd.lf == NULL) {
                log_err("Failed to create lockfile.");
                goto fail_lockfile;
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

        if (chmod(IRM_SOCK_PATH, 0666)) {
                log_err("Failed to chmod socket.");
                goto fail_sock_path;
        }

        if ((irmd.rdrb = shm_rdrbuff_create()) == NULL) {
                log_err("Failed to create rdrbuff.");
                goto fail_rdrbuff;
        }
#ifdef HAVE_FUSE
        if (stat(FUSE_PREFIX, &st) != -1)
                log_warn(FUSE_PREFIX " already exists...");
        else
                mkdir(FUSE_PREFIX, 0777);
#endif

#ifdef HAVE_LIBGCRYPT
        if (!gcry_check_version(GCRYPT_VERSION)) {
                log_err("Error checking libgcrypt version.");
                goto fail_gcry_version;
        }

        if (!gcry_control(GCRYCTL_ANY_INITIALIZATION_P)) {
                log_err("Libgcrypt was not initialized.");
                goto fail_gcry_version;
        }

        gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
#endif
        irmd_set_state(IRMD_RUNNING);

        log_info("Ouroboros IPC Resource Manager daemon started...");

        return 0;

#ifdef HAVE_LIBGCRYPT
 fail_gcry_version:
#ifdef HAVE_FUSE
        rmdir(FUSE_PREFIX);
#endif
        shm_rdrbuff_destroy(irmd.rdrb);
#endif
 fail_rdrbuff:
        close(irmd.sockfd);
 fail_sock_path:
        unlink(IRM_SOCK_PATH);
 fail_stat:
        lockfile_destroy(irmd.lf);
 fail_lockfile:
        bmp_destroy(irmd.flow_ids);
 fail_flow_ids:
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
        printf("Usage: irmd \n"
               "         [--stdout  (Log to stdout instead of system log)]\n"
               "         [--version (Print version number and exit)]\n"
               "\n");
}

int main(int     argc,
         char ** argv)
{
        sigset_t  sigset;
        bool      use_stdout = false;
        int       sig;

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGTERM);
        sigaddset(&sigset, SIGPIPE);

        argc--;
        argv++;
        while (argc > 0) {
                if (strcmp(*argv, "--stdout") == 0) {
                        use_stdout = true;
                        argc--;
                        argv++;
                } else if (strcmp(*argv, "--version") == 0) {
                        printf("Ouroboros version %d.%d.%d\n",
                               OUROBOROS_VERSION_MAJOR,
                               OUROBOROS_VERSION_MINOR,
                               OUROBOROS_VERSION_PATCH);
                        exit(EXIT_SUCCESS);
                } else {
                        usage();
                        exit(EXIT_FAILURE);
                }
        }

        if (geteuid() != 0) {
                printf("IPC Resource Manager must be run as root.\n");
                exit(EXIT_FAILURE);
        }

        log_init(!use_stdout);

        if (irm_init() < 0)
                goto fail_irm_init;

        irmd.tpm = tpm_create(IRMD_MIN_THREADS, IRMD_ADD_THREADS,
                              mainloop, NULL);
        if (irmd.tpm == NULL) {
                irmd_set_state(IRMD_NULL);
                goto fail_tpm_create;
        }

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (tpm_start(irmd.tpm)) {
                irmd_set_state(IRMD_NULL);
                goto fail_tpm_start;
        }

        if (pthread_create(&irmd.irm_sanitize, NULL, irm_sanitize, NULL)) {
                irmd_set_state(IRMD_NULL);
                goto fail_irm_sanitize;
        }

        if (pthread_create(&irmd.acceptor, NULL, acceptloop, NULL)) {
                irmd_set_state(IRMD_NULL);
                goto fail_acceptor;
        }

        while (irmd_get_state() != IRMD_NULL) {
                if (sigwait(&sigset, &sig) != 0) {
                        log_warn("Bad signal.");
                        continue;
                }

                switch(sig) {
                case SIGINT:
                case SIGQUIT:
                case SIGTERM:
                case SIGHUP:
                        log_info("IRMd shutting down...");
                        irmd_set_state(IRMD_NULL);
                        break;
                case SIGPIPE:
                        log_dbg("Ignored SIGPIPE.");
                        break;
                default:
                        break;
                }
        }

        pthread_cancel(irmd.acceptor);

        pthread_join(irmd.acceptor, NULL);
        pthread_join(irmd.irm_sanitize, NULL);

        tpm_stop(irmd.tpm);

        tpm_destroy(irmd.tpm);

        irm_fini();

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        log_info("Bye.");

        log_fini();

        exit(EXIT_SUCCESS);

 fail_acceptor:
        pthread_join(irmd.irm_sanitize, NULL);
 fail_irm_sanitize:
        tpm_stop(irmd.tpm);
 fail_tpm_start:
        tpm_destroy(irmd.tpm);
 fail_tpm_create:
        irm_fini();
 fail_irm_init:
        log_fini();
        exit(EXIT_FAILURE);
}
