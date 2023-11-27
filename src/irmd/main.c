/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * The IPC Resource Manager
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
#include <ouroboros/pthread.h>

#include "irmd.h"
#include "ipcp.h"
#include "reg/flow.h"
#include "reg/ipcp.h"
#include "reg/name.h"
#include "reg/proc.h"
#include "reg/prog.h"
#include "configfile.h"
#include "utils.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <spawn.h>

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#define IRMD_CLEANUP_TIMER ((IRMD_FLOW_TIMEOUT / 20) * MILLION) /* ns */
#define SHM_SAN_HOLDOFF    1000 /* ms */
#define IPCP_HASH_LEN(p)   hash_len((p)->dir_hash_algo)
#define BIND_TIMEOUT       10   /* ms */
#define DEALLOC_TIME       300  /*  s */

#define registry_has_name(name) \
        (registry_get_name(name) != NULL)

enum irm_state {
        IRMD_NULL = 0,
        IRMD_RUNNING
};

struct cmd {
        struct list_head next;

        uint8_t          cbuf[SOCK_BUF_SIZE];
        size_t           len;
        int              fd;
};

struct {
        bool                 log_stdout;   /* log to stdout              */

        struct list_head     names;        /* registered names known     */
        size_t               n_names;      /* number of names            */

        struct list_head     ipcps;        /* list of ipcps in system    */
        size_t               n_ipcps;      /* number of ipcps            */

        struct list_head     procs;        /* processes                  */
        struct list_head     progs;        /* programs known             */
        struct list_head     spawned_pids; /* child processes            */

        struct bmp *         flow_ids;     /* flow_ids for flows         */
        struct list_head     flows;        /* flow information           */

        pthread_rwlock_t     reg_lock;     /* lock for registration info */

#ifdef HAVE_TOML
        char *               cfg_file;     /* configuration file path    */
#endif
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

static void clear_reg_flow(struct reg_flow * f) {
        ssize_t idx;

        assert(f);

        if (f->data.len != 0) {
                free(f->data.data);
                f->data.len = 0;
        }

        while ((idx = shm_rbuff_read(f->n_rb)) >= 0)
                shm_rdrbuff_remove(irmd.rdrb, idx);

        while ((idx = shm_rbuff_read(f->n_1_rb)) >= 0)
                shm_rdrbuff_remove(irmd.rdrb, idx);
}

static struct reg_flow * registry_get_flow(int flow_id)
{
        struct list_head * p;

        list_for_each(p, &irmd.flows) {
                struct reg_flow * f = list_entry(p, struct reg_flow, next);
                if (f->flow_id == flow_id)
                        return f;
        }

        return NULL;
}

static struct reg_flow * registry_get_pending_flow_for_pid(pid_t n_pid)
{
        struct list_head * p;

        list_for_each(p, &irmd.flows) {
                struct reg_flow * e = list_entry(p, struct reg_flow, next);
                enum flow_state state = reg_flow_get_state(e);
                if (e->n_pid == n_pid && state == FLOW_ALLOC_REQ_PENDING)
                        return e;
        }

        return NULL;
}

static int registry_add_ipcp(struct reg_ipcp * ipcp)
{
        struct list_head * p;

        assert(ipcp);

        list_for_each(p, &irmd.ipcps) {
                if (list_entry(p, struct reg_ipcp, next)->type > ipcp->type)
                        break;
        }

        list_add_tail(&ipcp->next, p);
        ++irmd.n_ipcps;

        return 0;
}

static struct reg_ipcp * registry_get_ipcp_by_pid(pid_t pid)
{
        struct list_head * p;

        list_for_each(p, &irmd.ipcps) {
                struct reg_ipcp * e = list_entry(p, struct reg_ipcp, next);
                if (e->pid == pid)
                        return e;
        }

        return NULL;
}

static void registry_del_ipcp(pid_t pid)
{
        struct reg_ipcp * ipcp;

        ipcp = registry_get_ipcp_by_pid(pid);
        if (ipcp == NULL)
                return;

        list_del(&ipcp->next);
        reg_ipcp_destroy(ipcp);
        --irmd.n_ipcps;
}

static struct reg_ipcp * registry_get_ipcp_by_name(const char * name)
{
        struct list_head * p;

        list_for_each(p, &irmd.ipcps) {
                struct reg_ipcp * e = list_entry(p, struct reg_ipcp, next);
                if (strcmp(name, e->name) == 0)
                        return e;
        }

        return NULL;
}

static struct reg_ipcp * registry_get_ipcp_by_layer(const char * layer)
{
        struct list_head * p;

        list_for_each(p, &irmd.ipcps) {
                struct reg_ipcp * e = list_entry(p, struct reg_ipcp, next);
                if (strcmp(layer, e->layer) == 0)
                        return e;
        }

        return NULL;
}

static struct reg_ipcp * registry_get_ipcp_by_dst_name(const char * name,
                                                       pid_t        src)
{
        struct list_head * p;
        struct list_head * h;
        uint8_t *          hash;
        pid_t              pid;
        size_t             len;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        list_for_each_safe(p, h, &irmd.ipcps) {
                struct reg_ipcp * e = list_entry(p, struct reg_ipcp, next);
                if (e->layer == NULL || e->pid == src || e->type == IPCP_BROADCAST)
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

int get_layer_for_ipcp(pid_t  pid,
                       char * buf)
{
        struct reg_ipcp * ipcp;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        ipcp = registry_get_ipcp_by_pid(pid);
        if (ipcp == NULL || ipcp->layer == NULL)
                goto fail;

        strcpy(buf, ipcp->layer);

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;

 fail:
        pthread_rwlock_unlock(&irmd.reg_lock);
        return -1;
}

static struct reg_name * registry_get_name(const char * name)
{
        struct list_head * p;

        list_for_each(p, &irmd.names) {
                struct reg_name * e = list_entry(p, struct reg_name, next);
                if (!strcmp(name, e->name))
                        return e;
        }

        return NULL;
}

static struct reg_name * registry_get_name_by_hash(enum hash_algo     algo,
                                                   const uint8_t *    hash,
                                                   size_t             len)
{
        struct list_head * p;
        uint8_t * thash;

        thash = malloc(len);
        if (thash == NULL)
                return NULL;

        list_for_each(p, &irmd.names) {
                struct reg_name * n = list_entry(p, struct reg_name, next);
                str_hash(algo, thash, n->name);
                if (memcmp(thash, hash, len) == 0) {
                        free(thash);
                        return n;
                }
        }

        free(thash);

        return NULL;
}

static int registry_add_name(struct reg_name * n)
{

        assert(n);

        list_add(&n->next, &irmd.names);

        ++irmd.n_names;

        return 0;
}

static void registry_del_name(const char * name)
{
        struct reg_name * n;

        n = registry_get_name(name);
        if (n == NULL)
                return;

        list_del(&n->next);
        reg_name_destroy(n);
        --irmd.n_names;
}

static void registry_names_del_proc(pid_t pid)
{
        struct list_head * p;

        assert(pid > 0);

        list_for_each(p, &irmd.names) {
                struct reg_name * n = list_entry(p, struct reg_name, next);
                reg_name_del_pid(n, pid);
        }

        return;
}

static void registry_destroy_names(void)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &irmd.names) {
                struct reg_name * n = list_entry(p, struct reg_name, next);
                list_del(&n->next);
                reg_name_set_state(n, NAME_NULL);
                reg_name_destroy(n);
        }
}

static int registry_add_prog(struct reg_prog * p)
{
        assert(p);

        list_add(&p->next, &irmd.progs);

        return 0;
}

static void registry_del_prog(const char * prog)
{
        struct list_head * p;
        struct list_head * h;

        assert(prog);

        list_for_each_safe(p, h, &irmd.progs) {
                struct reg_prog * e = list_entry(p, struct reg_prog, next);
                if (!strcmp(prog, e->prog)) {
                        list_del(&e->next);
                        reg_prog_destroy(e);
                }
        }
}

static struct reg_prog * registry_get_prog(const char * prog)
{
        struct list_head * p;

        assert(prog);

        list_for_each(p, &irmd.progs) {
                struct reg_prog * e = list_entry(p, struct reg_prog, next);
                if (!strcmp(e->prog, prog))
                        return e;
        }

        return NULL;
}

static int registry_add_proc(struct reg_proc * p)
{
        assert(p);

        list_add(&p->next, &irmd.procs);

        return 0;
}

static void registry_del_proc(pid_t pid)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &irmd.procs) {
                struct reg_proc * e = list_entry(p, struct reg_proc, next);
                if (pid == e->pid) {
                        list_del(&e->next);
                        reg_proc_destroy(e);
                }
        }
}

static struct reg_proc * registry_get_proc(pid_t pid)
{
        struct list_head * p;

        list_for_each(p, &irmd.procs) {
                struct reg_proc * e = list_entry(p, struct reg_proc, next);
                if (pid == e->pid)
                        return e;
        }

        return NULL;
}

pid_t create_ipcp(const char *   name,
                  enum ipcp_type type)
{
        struct pid_el *    ppid;
        struct reg_ipcp *  ipcp;
        pid_t              pid;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        ipcp = registry_get_ipcp_by_name(name);
        if (ipcp != NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("IPCP by that name already exists.");
                return -EPERM;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        ppid = malloc(sizeof(*ppid));
        if (ppid == NULL)
                goto fail_ppid;

        ipcp = reg_ipcp_create(name, type);
        if (ipcp == NULL) {
                log_err("Failed to create IPCP entry.");
                goto fail_reg_ipcp;
        }

        pid = ipcp_create(name, type);
        if (pid == -1) {
                log_err("Failed to create IPCP.");
                goto fail_ipcp;
        }

        ipcp->pid = pid;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        registry_add_ipcp(ipcp);

        ppid->pid = ipcp->pid;
        list_add(&ppid->next, &irmd.spawned_pids);

        pthread_rwlock_unlock(&irmd.reg_lock);

        /* IRMd maintenance will clean up if booting fails. */
        if (reg_ipcp_wait_boot(ipcp)) {
                log_err("IPCP %d failed to boot.", pid);
                return -1;
        }

        log_info("Created IPCP %d.", pid);

        return pid;

 fail_ipcp:
        reg_ipcp_destroy(ipcp);
 fail_reg_ipcp:
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
                struct reg_ipcp * e = list_entry(p, struct reg_ipcp, next);
                if (e->pid == pid) {
                        reg_ipcp_set_state(e, result ? IPCP_NULL : IPCP_LIVE);
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
        pthread_rwlock_wrlock(&irmd.reg_lock);

        registry_del_ipcp(pid);

        clear_spawned_process(pid);

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (ipcp_destroy(pid))
                log_err("Could not destroy IPCP.");

        return 0;
}

int bootstrap_ipcp(pid_t                pid,
                   struct ipcp_config * conf)
{
        struct reg_ipcp * entry;
        struct layer_info   info;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        entry = registry_get_ipcp_by_pid(pid);
        if (entry == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -1;
        }

        if (entry->type != conf->type) {
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
                 pid, conf->layer_info.layer_name);

        return 0;
}

int enroll_ipcp(pid_t        pid,
                const char * dst)
{
        struct reg_ipcp * ipcp;
        struct layer_info info;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        ipcp = registry_get_ipcp_by_pid(pid);
        if (ipcp == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -1;
        }

        if (ipcp->layer != NULL) {
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

        ipcp = registry_get_ipcp_by_pid(pid);
        if (ipcp == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -1;
        }

        ipcp->layer = strdup(info.layer_name);
        if (ipcp->layer == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Failed to strdup layer_name.");
                return -ENOMEM;
        }

        ipcp->dir_hash_algo = info.dir_hash_algo;

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Enrolled IPCP %d in layer %s.",
                 pid, info.layer_name);

        return 0;
}

int connect_ipcp(pid_t        pid,
                 const char * dst,
                 const char * component,
                 qosspec_t    qs)
{
        struct reg_ipcp * ipcp;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        ipcp = registry_get_ipcp_by_pid(pid);
        if (ipcp == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -EIPCP;
        }

        if (ipcp->type != IPCP_UNICAST && ipcp->type != IPCP_BROADCAST) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Cannot establish connections for this IPCP type.");
                return -EIPCP;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_dbg("Connecting %s to %s.", component, dst);

        if (ipcp_connect(pid, dst, component, qs)) {
                log_err("Could not connect IPCP %d to %s.", pid, dst);
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
        struct reg_ipcp * ipcp;

        pthread_rwlock_rdlock(&irmd.reg_lock);

        ipcp = registry_get_ipcp_by_pid(pid);
        if (ipcp == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No such IPCP.");
                return -EIPCP;
        }

        if (ipcp->type != IPCP_UNICAST && ipcp->type != IPCP_BROADCAST) {
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

int bind_program(const char *  prog,
                 const char *  name,
                 uint16_t      flags,
                 int           argc,
                 char **       argv)
{
        struct reg_prog * p;
        struct reg_name * n;

        if (prog == NULL || name == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        p = registry_get_prog(path_strip(prog));
        if (p == NULL) {
                p = reg_prog_create(prog, flags, argc, argv);
                if (p == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        return -ENOMEM;
                }

                registry_add_prog(p);
        }

        if (reg_prog_add_name(p, name)) {
                log_err("Failed adding name.");
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -ENOMEM;
        }

        n = registry_get_name(name);
        if (n != NULL && reg_name_add_prog(n, p) < 0)
                log_err("Failed adding program %s for name %s.", prog, name);

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Bound program %s to name %s.", prog, name);

        return 0;
}

int bind_process(pid_t        pid,
                 const char * name)
{
        struct reg_proc * pc = NULL;
        struct reg_name * rn;
        struct timespec   now;
        struct timespec   dl = {0, 10 * MILLION};

        if (name == NULL)
                return -EINVAL;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        ts_add(&dl, &now, &dl);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        while (!kill(pid, 0)) {
                pc = registry_get_proc(pid);
                if (pc != NULL || ts_diff_ms(&now, &dl) > 0)
                        break;
                clock_gettime(PTHREAD_COND_CLOCK, &now);
                sched_yield();
        }

        if (pc == NULL) {
                log_err("Process %d does not %s.", pid,
                        kill(pid, 0) ? "exist" : "respond");
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -1;
        }

        if (reg_proc_add_name(pc, name)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Failed to add name %s to process %d.", name, pid);
                return -1;
        }

        rn = registry_get_name(name);
        if (rn != NULL && reg_name_add_pid(rn, pid) < 0)
                log_err("Failed adding process %d for name %s.", pid, name);

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Bound process %d to name %s.", pid, name);

        return 0;
}

static int unbind_program(const char * prog,
                          const char * name)
{
        if (prog == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (name == NULL)
                registry_del_prog(prog);
        else {
                struct reg_name * rn;
                struct reg_prog * pg;

                pg = registry_get_prog(prog);
                if (pg == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        return -EINVAL;
                }

                reg_prog_del_name(pg, name);

                rn = registry_get_name(name);
                if (rn != NULL)
                        reg_name_del_prog(rn, prog);
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
        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (name == NULL)
                registry_del_proc(pid);
        else {
                struct reg_name * n;
                struct reg_proc * p;

                p = registry_get_proc(pid);
                if (p != NULL)
                        reg_proc_del_name(p, name);

                n = registry_get_name(name);
                if (n != NULL)
                        reg_name_del_pid(n, pid);
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (name == NULL)
                log_info("Process %d unbound.", pid);
        else
                log_info("All names matching %s unbound for %d.", name, pid);

        return 0;
}

static int get_ipcp_info(ipcp_list_msg_t ** msg,
                         struct reg_ipcp *  ipcp)
{
        *msg = malloc(sizeof(**msg));
        if (*msg == NULL)
                goto fail;

        ipcp_list_msg__init(*msg);

        (*msg)->name = strdup(ipcp->name);
        if ((*msg)->name == NULL)
                goto fail_name;

        (*msg)->layer = strdup(
                ipcp->layer != NULL ? ipcp->layer : "Not enrolled");
        if ((*msg)->layer == NULL)
                goto fail_layer;

        (*msg)->pid  = ipcp->pid;
        (*msg)->type = ipcp->type;

        return 0;

 fail_layer:
        free((*msg)->name);
 fail_name:
        free(*msg);
        *msg = NULL;
 fail:
        return -1;
}

static ssize_t list_ipcps(ipcp_list_msg_t *** ipcps,
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
                struct reg_ipcp * e = list_entry(p, struct reg_ipcp, next);
                if (get_ipcp_info(&((*ipcps)[i]), e) < 0)
                        goto fail;
                ++i;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;

 fail:
        pthread_rwlock_unlock(&irmd.reg_lock);
        while (i > 0)
                ipcp_list_msg__free_unpacked((*ipcps)[--i], NULL);

        free(*ipcps);
        *n_ipcps = 0;
        return -ENOMEM;
}

int name_create(const char *     name,
                enum pol_balance lb)
{
        struct reg_name *  n;
        struct list_head * p;

        assert(name);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (registry_has_name(name)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_warn("Name %s already exists.", name);
                return 0;
        }

        n = reg_name_create(name, lb);
        if (n == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_dbg("Could not create name.");
                return -ENOMEM;
        }

        if (registry_add_name(n) < 0) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Failed to add name %s.", name);
                return -ENOMEM;
        }

        /* check the tables for existing bindings */
        list_for_each(p, &irmd.procs) {
                struct list_head * q;
                struct reg_proc * e;
                e = list_entry(p, struct reg_proc, next);
                list_for_each(q, &e->names) {
                        struct str_el * s;
                        s = list_entry(q, struct str_el, next);
                        if (!strcmp(s->str, name))
                                reg_name_add_pid(n, e->pid);
                }
        }

        list_for_each(p, &irmd.progs) {
                struct list_head * q;
                struct reg_prog * e;
                e = list_entry(p, struct reg_prog, next);
                list_for_each(q, &e->names) {
                        struct str_el * s;
                        s = list_entry(q, struct str_el, next);
                        if (!strcmp(s->str, name))
                                reg_name_add_prog(n, e);
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

        if (!registry_has_name(name)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_warn("Registry entry for %s does not exist.", name);
                return -ENAME;
        }

        registry_del_name(name);

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Destroyed name: %s.", name);

        return 0;
}

static int get_name_info(name_info_msg_t ** msg,
                         struct reg_name *  n)
{
        *msg = malloc(sizeof(**msg));
        if (*msg == NULL)
                goto fail;

        name_info_msg__init(*msg);

        (*msg)->name = strdup(n->name);
        if ((*msg)->name == NULL)
                goto fail_name;

        (*msg)->pol_lb = n->pol_lb;

        return 0;

 fail_name:
        free(*msg);
        *msg = NULL;
 fail:
        return -1;
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

        list_for_each(p, &irmd.names) {
                struct reg_name * n = list_entry(p, struct reg_name, next);
                if (get_name_info(&((*names)[i]), n) < 0)
                        goto fail;
                ++i;
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;

 fail:
        pthread_rwlock_unlock(&irmd.reg_lock);
        while (i > 0)
                name_info_msg__free_unpacked((*names)[--i], NULL);

        free(*names);
        *n_names = 0;
        return -ENOMEM;
}

int name_reg(const char * name,
             pid_t        pid)
{
        size_t            len;
        struct reg_ipcp * ipcp;
        uint8_t *         hash;
        int               err;

        assert(name);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (!registry_has_name(name)) {
                err = -ENAME;
                goto fail;
        }

        ipcp = registry_get_ipcp_by_pid(pid);
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
                log_err("Could not register " HASH_FMT32 " with IPCP %d.",
                        HASH_VAL32(hash), pid);
                free(hash);
                return -1;
        }

        log_info("Registered %s with IPCP %d as " HASH_FMT32 ".",
                 name, pid, HASH_VAL32(hash));

        free(hash);

        return 0;

fail:
        pthread_rwlock_unlock(&irmd.reg_lock);
        return err;
}

static int name_unreg(const char * name,
                      pid_t        pid)
{
        struct reg_ipcp * ipcp;
        int               err;
        uint8_t *         hash;
        size_t            len;

        assert(name);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        ipcp = registry_get_ipcp_by_pid(pid);
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

static int proc_announce(pid_t        pid,
                         const char * prog)
{
        struct reg_proc * rpc;
        struct reg_prog * rpg;

        assert(prog);

        rpc = reg_proc_create(pid, prog);
        if (rpc == NULL)
                return -ENOMEM;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        registry_add_proc(rpc);

        /* Copy listen names from program if it exists. */
        rpg = registry_get_prog(rpc->prog);
        if (rpg != NULL) {
                struct list_head * p;
                list_for_each(p, &rpg->names) {
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

                        list_add(&n->next, &rpc->names);
                        log_dbg("Process %d inherits name %s from program %s.",
                                pid, n->str, rpc->prog);
                }
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;
}

static int flow_accept(pid_t             pid,
                       struct timespec * dl,
                       struct reg_flow * f_out,
                       buffer_t *        data)
{
        struct reg_flow *  f;
        struct reg_proc *  rp;
        struct reg_name *  n;
        struct list_head * p;
        pid_t              pid_n;
        pid_t              pid_n_1;
        int                flow_id;
        int                ret;
        buffer_t           tmp = {NULL, 0};

        pthread_rwlock_wrlock(&irmd.reg_lock);

        rp = registry_get_proc(pid);
        if (rp == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Unknown process %d calling accept.", pid);
                return -EINVAL;
        }

        log_dbg("New instance (%d) of %s added.", pid, rp->prog);
        log_dbg("This process accepts flows for:");

        list_for_each(p, &rp->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                log_dbg("        %s", s->str);
                n = registry_get_name(s->str);
                if (n != NULL)
                        reg_name_add_pid(n, pid);
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

        ret = reg_proc_sleep(rp, dl);
        if (ret == -ETIMEDOUT)
                return -ETIMEDOUT;

        if (ret == -1)
                return -EPIPE;

        if (irmd_get_state() != IRMD_RUNNING)
                return -EIRMD;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        f = registry_get_pending_flow_for_pid(pid);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_warn("Port_id was not created yet.");
                return -EPERM;
        }

        pid_n   = f->n_pid;
        pid_n_1 = f->n_1_pid;
        flow_id = f->flow_id;

        rp = registry_get_proc(pid);
        if (rp == NULL) {
                list_del(&f->next);
                bmp_release(irmd.flow_ids, f->flow_id);
                pthread_rwlock_unlock(&irmd.reg_lock);
                ipcp_flow_alloc_resp(pid_n_1, flow_id, pid_n, -1, tmp);
                clear_reg_flow(f);
                reg_flow_set_state(f, FLOW_NULL);
                reg_flow_destroy(f);
                log_dbg("Process gone while accepting flow.");
                return -EPERM;
        }

        pthread_mutex_lock(&rp->lock);

        n = rp->name;

        pthread_mutex_unlock(&rp->lock);

        if (reg_name_get_state(n) != NAME_FLOW_ARRIVED) {
                list_del(&f->next);
                bmp_release(irmd.flow_ids, f->flow_id);
                pthread_rwlock_unlock(&irmd.reg_lock);
                ipcp_flow_alloc_resp(pid_n_1, flow_id, pid_n, -1, tmp);
                clear_reg_flow(f);
                reg_flow_set_state(f, FLOW_NULL);
                reg_flow_destroy(f);
                log_err("Entry in wrong state.");
                return -EPERM;
        }

        registry_names_del_proc(pid);

        f_out->flow_id = f->flow_id;
        f_out->n_pid   = f->n_pid;
        f_out->n_1_pid = f->n_1_pid;
        f_out->qs      = f->qs;
        f_out->mpl     = f->mpl;

        if (f->qs.cypher_s != 0) /* crypto requested, send pubkey */
                tmp = *data;

        *data = f->data; /* pass owner */
        clrbuf (f->data);

        pthread_rwlock_unlock(&irmd.reg_lock);

        if (ipcp_flow_alloc_resp(pid_n_1, flow_id, pid_n, 0, tmp)) {
                pthread_rwlock_wrlock(&irmd.reg_lock);
                list_del(&f->next);
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_dbg("Failed to respond to alloc. Port_id invalidated.");
                clear_reg_flow(f);
                reg_flow_set_state(f, FLOW_NULL);
                reg_flow_destroy(f);
                return -EPERM;
        }

        reg_flow_set_state(f, FLOW_ALLOCATED);

        log_info("Flow on flow_id %d allocated.", f->flow_id);

        return 0;
}

static int flow_join(pid_t              pid,
                     const char *       dst,
                     qosspec_t          qs,
                     struct timespec *  dl,
                     struct reg_flow *  f_out)
{
        struct reg_flow *   f;
        struct reg_ipcp * ipcp;
        int                 flow_id;
        int                 state;
        uint8_t *           hash;

        log_info("Allocating flow for %d to %s.", pid, dst);

        ipcp = registry_get_ipcp_by_layer(dst);
        if (ipcp == NULL) {
                log_info("Layer %s unreachable.", dst);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        flow_id = bmp_allocate(irmd.flow_ids);
        if (!bmp_is_id_valid(irmd.flow_ids, flow_id)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Could not allocate flow_id.");
                return -EBADF;
        }

        f = reg_flow_create(pid, ipcp->pid, flow_id, qs);
        if (f == NULL) {
                bmp_release(irmd.flow_ids, flow_id);
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Could not allocate flow_id.");
                return -ENOMEM;
        }

        list_add(&f->next, &irmd.flows);

        pthread_rwlock_unlock(&irmd.reg_lock);

        assert(reg_flow_get_state(f) == FLOW_ALLOC_PENDING);

        hash = malloc(IPCP_HASH_LEN(ipcp));
        if  (hash == NULL)
                /* sanitizer cleans this */
                return -ENOMEM;

        str_hash(ipcp->dir_hash_algo, hash, dst);

        if (ipcp_flow_join(ipcp->pid, flow_id, pid, hash,
                                IPCP_HASH_LEN(ipcp), qs)) {
                reg_flow_set_state(f, FLOW_NULL);
                /* sanitizer cleans this */
                log_info("Flow_join failed.");
                free(hash);
                return -EAGAIN;
        }

        free(hash);

        state = reg_flow_wait_state(f, FLOW_ALLOCATED, dl);
        if (state != FLOW_ALLOCATED) {
                if (state == -ETIMEDOUT) {
                        log_dbg("Flow allocation timed out");
                        return -ETIMEDOUT;
                }

                log_info("Pending flow to %s torn down.", dst);
                return -EPIPE;
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        assert(reg_flow_get_state(f) == FLOW_ALLOCATED);

        f_out->flow_id = f->flow_id;
        f_out->n_pid   = f->n_pid;
        f_out->n_1_pid = f->n_1_pid;
        f_out->mpl     = f->mpl;

        assert(f->data.data == NULL);
        assert(f->data.len  == 0);

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Flow on flow_id %d allocated.", flow_id);

        return 0;
}

static int flow_alloc(pid_t              pid,
                      const char *       dst,
                      qosspec_t          qs,
                      struct timespec *  dl,
                      struct reg_flow *  f_out,
                      buffer_t *         data)
{
        struct reg_flow * f;
        struct reg_ipcp * ipcp;
        int               flow_id;
        int               state;
        uint8_t *         hash;

        log_info("Allocating flow for %d to %s.", pid, dst);

        ipcp = registry_get_ipcp_by_dst_name(dst, pid);
        if (ipcp == NULL) {
                log_info("Destination %s unreachable.", dst);
                return -1;
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        flow_id = bmp_allocate(irmd.flow_ids);
        if (!bmp_is_id_valid(irmd.flow_ids, flow_id)) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Could not allocate flow_id.");
                return -EBADF;
        }

        f = reg_flow_create(pid, ipcp->pid, flow_id, qs);
        if (f == NULL) {
                bmp_release(irmd.flow_ids, flow_id);
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Could not allocate flow_id.");
                return -ENOMEM;
        }

        list_add(&f->next, &irmd.flows);

        pthread_rwlock_unlock(&irmd.reg_lock);

        assert(reg_flow_get_state(f) == FLOW_ALLOC_PENDING);

        hash = malloc(IPCP_HASH_LEN(ipcp));
        if  (hash == NULL)
                /* sanitizer cleans this */
                return -ENOMEM;

        str_hash(ipcp->dir_hash_algo, hash, dst);

        if (ipcp_flow_alloc(ipcp->pid, flow_id, pid, hash,
                            IPCP_HASH_LEN(ipcp), qs, *data)) {
                reg_flow_set_state(f, FLOW_NULL);
                /* sanitizer cleans this */
                log_warn("Flow_allocation %d failed.", flow_id);
                free(hash);
                return -EAGAIN;
        }

        free(hash);

        state = reg_flow_wait_state(f, FLOW_ALLOCATED, dl);
        if (state != FLOW_ALLOCATED) {
                if (state == -ETIMEDOUT) {
                        log_err("Flow allocation timed out");
                        return -ETIMEDOUT;
                }

                log_warn("Pending flow to %s torn down.", dst);
                return -EPIPE;
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        assert(reg_flow_get_state(f) == FLOW_ALLOCATED);

        f_out->flow_id = f->flow_id;
        f_out->n_pid   = f->n_pid;
        f_out->n_1_pid = f->n_1_pid;
        f_out->mpl     = f->mpl;
        *data          = f->data; /* pass owner */
        clrbuf(f->data);

        pthread_rwlock_unlock(&irmd.reg_lock);

        log_info("Flow on flow_id %d allocated.", flow_id);

        return 0;
}

static int flow_dealloc(pid_t  pid,
                        int    flow_id,
                        time_t timeo)
{
        pid_t n_1_pid = -1;
        int   ret = 0;

        struct reg_flow * f = NULL;

        log_dbg("Deallocating flow %d for process %d.",
                flow_id, pid);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        f = registry_get_flow(flow_id);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_dbg("Deallocate unknown port %d by %d.", flow_id, pid);
                return 0;
        }

        if (pid == f->n_pid) {
                f->n_pid = -1;
                n_1_pid = f->n_1_pid;
        } else if (pid == f->n_1_pid) {
                f->n_1_pid = -1;
        } else {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_dbg("Dealloc called by wrong process.");
                return -EPERM;
        }

        if (reg_flow_get_state(f) == FLOW_DEALLOC_PENDING) {
                list_del(&f->next);
                if ((kill(f->n_pid, 0) < 0 && f->n_1_pid == -1) ||
                    (kill(f->n_1_pid, 0) < 0 && f->n_pid == -1))
                        reg_flow_set_state(f, FLOW_NULL);
                clear_reg_flow(f);
                reg_flow_destroy(f);
                bmp_release(irmd.flow_ids, flow_id);
                log_info("Completed deallocation of flow_id %d by process %d.",
                         flow_id, pid);
        } else {
                reg_flow_set_state(f, FLOW_DEALLOC_PENDING);
                log_dbg("Partial deallocation of flow_id %d by process %d.",
                        flow_id, pid);
        }

        pthread_rwlock_unlock(&irmd.reg_lock);

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

static int flow_req_arr(pid_t             pid,
                        struct reg_flow * f_out,
                        const uint8_t *   hash,
                        time_t            mpl,
                        qosspec_t         qs,
                        buffer_t          data)
{
        struct reg_name * n;
        struct reg_prog * rpg;
        struct reg_proc * rpc;
        struct reg_flow * f;
        struct reg_ipcp * ipcp;

        struct pid_el *   c_pid;
        pid_t             h_pid;
        int               flow_id;

        struct timespec   wt = {IRMD_REQ_ARR_TIMEOUT / 1000,
                                (IRMD_REQ_ARR_TIMEOUT % 1000) * MILLION};

        log_dbg("Flow req arrived from IPCP %d for " HASH_FMT32 ".",
                pid, HASH_VAL32(hash));

        pthread_rwlock_rdlock(&irmd.reg_lock);

        ipcp = registry_get_ipcp_by_pid(pid);
        if (ipcp == NULL) {
                log_err("IPCP died.");
                return -EIPCP;
        }

        n = registry_get_name_by_hash(ipcp->dir_hash_algo,
                                      hash, IPCP_HASH_LEN(ipcp));
        if (n == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Unknown hash: " HASH_FMT32 ".", HASH_VAL32(hash));
                return -1;
        }

        log_info("Flow request arrived for %s.", n->name);

        pthread_rwlock_unlock(&irmd.reg_lock);

        /* Give the process a bit of slop time to call accept */
        if (reg_name_leave_state(n, NAME_IDLE, &wt) == -1) {
                log_err("No processes for " HASH_FMT32 ".", HASH_VAL32(hash));
                return -1;
        }

        pthread_rwlock_wrlock(&irmd.reg_lock);

        switch (reg_name_get_state(n)) {
        case NAME_IDLE:
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("No processes for " HASH_FMT32 ".", HASH_VAL32(hash));
                return -1;
        case NAME_AUTO_ACCEPT:
                c_pid = malloc(sizeof(*c_pid));
                if (c_pid == NULL) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        return -1;
                }

                reg_name_set_state(n, NAME_AUTO_EXEC);
                rpg = registry_get_prog(reg_name_get_prog(n));
                if (rpg == NULL
                    || (c_pid->pid = auto_execute(rpg->argv)) < 0) {
                        reg_name_set_state(n, NAME_AUTO_ACCEPT);
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        log_err("Could not start program for reg_entry %s.",
                                n->name);
                        free(c_pid);
                        return -1;
                }

                list_add(&c_pid->next, &irmd.spawned_pids);

                pthread_rwlock_unlock(&irmd.reg_lock);

                if (reg_name_leave_state(n, NAME_AUTO_EXEC, NULL))
                        return -1;

                pthread_rwlock_wrlock(&irmd.reg_lock);
                /* FALLTHRU */
        case NAME_FLOW_ACCEPT:
                h_pid = reg_name_get_pid(n);
                if (h_pid == -1) {
                        pthread_rwlock_unlock(&irmd.reg_lock);
                        log_err("Invalid process id returned.");
                        return -1;
                }

                break;
        default:
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("IRMd in wrong state.");
                return -1;
        }

        flow_id = bmp_allocate(irmd.flow_ids);
        if (!bmp_is_id_valid(irmd.flow_ids, flow_id)) {
                log_err("Out of flow ids.");
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -1;
        }

        f = reg_flow_create(h_pid, pid, flow_id, qs);
        if (f == NULL) {
                bmp_release(irmd.flow_ids, flow_id);
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Could not allocate flow_id.");
                return -1;
        }

        f->state = FLOW_ALLOC_REQ_PENDING;
        f->mpl   = mpl;
        f->data  = data;

        list_add(&f->next, &irmd.flows);

        reg_name_set_state(n, NAME_FLOW_ARRIVED);

        rpc = registry_get_proc(h_pid);
        if (rpc == NULL) {
                clear_reg_flow(f);
                bmp_release(irmd.flow_ids, f->flow_id);
                list_del(&f->next);
                pthread_rwlock_unlock(&irmd.reg_lock);
                log_err("Could not get process table entry for %d.", h_pid);
                freebuf(f->data);
                reg_flow_destroy(f);
                return -1;
        }

        reg_proc_wake(rpc, n);

        pthread_rwlock_unlock(&irmd.reg_lock);

        reg_name_leave_state(n, NAME_FLOW_ARRIVED, NULL);

        f_out->flow_id = flow_id;
        f_out->n_pid   = h_pid;

        return 0;
}

static int flow_alloc_reply(int      flow_id,
                            int      response,
                            time_t   mpl,
                            buffer_t data)
{
        struct reg_flow * f;

        pthread_rwlock_wrlock(&irmd.reg_lock);

        f = registry_get_flow(flow_id);
        if (f == NULL) {
                pthread_rwlock_unlock(&irmd.reg_lock);
                return -1;
        }

        f->mpl = mpl;

        if (!response)
                reg_flow_set_state(f, FLOW_ALLOCATED);
        else
                reg_flow_set_state(f, FLOW_NULL);

        f->data = data;

        pthread_rwlock_unlock(&irmd.reg_lock);

        return 0;
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
                pthread_cleanup_push(__cleanup_rwlock_unlock, &irmd.reg_lock);

                list_for_each_safe(p, h, &irmd.spawned_pids) {
                        struct pid_el * e = list_entry(p, struct pid_el, next);
                        waitpid(e->pid, &s, WNOHANG);
                        if (kill(e->pid, 0) >= 0)
                                continue;
                        log_dbg("Child process %d died, error %d.", e->pid, s);
                        list_del(&e->next);
                        free(e);
                }

                list_for_each_safe(p, h, &irmd.procs) {
                        struct reg_proc * e =
                                list_entry(p, struct reg_proc, next);
                        if (kill(e->pid, 0) >= 0)
                                continue;
                        log_dbg("Dead process removed: %d.", e->pid);
                        list_del(&e->next);
                        reg_proc_destroy(e);
                }

                list_for_each_safe(p, h, &irmd.ipcps) {
                        struct reg_ipcp * e =
                                list_entry(p, struct reg_ipcp, next);
                        if (kill(e->pid, 0) >= 0)
                                continue;
                        log_dbg("Dead IPCP removed: %d.", e->pid);
                        list_del(&e->next);
                        reg_ipcp_destroy(e);
                }

                list_for_each_safe(p, h, &irmd.names) {
                        struct list_head * p2;
                        struct list_head * h2;
                        struct reg_name * e =
                                list_entry(p, struct reg_name, next);
                        list_for_each_safe(p2, h2, &e->reg_pids) {
                                struct pid_el * a =
                                        list_entry(p2, struct pid_el, next);
                                if (kill(a->pid, 0) >= 0)
                                        continue;
                                log_dbg("Dead process removed from: %d %s.",
                                        a->pid, e->name);
                                reg_name_del_pid_el(e, a);
                        }
                }

                pthread_cleanup_pop(true);

                pthread_rwlock_wrlock(&irmd.reg_lock);
                pthread_cleanup_push(__cleanup_rwlock_unlock, &irmd.reg_lock);

                list_for_each_safe(p, h, &irmd.flows) {
                        int ipcpi;
                        int flow_id;
                        struct reg_flow * f =
                                list_entry(p, struct reg_flow, next);

                        if (reg_flow_get_state(f) == FLOW_ALLOC_PENDING
                            && ts_diff_ms(&f->t0, &now) > IRMD_FLOW_TIMEOUT) {
                                log_dbg("Pending flow_id %d timed out.",
                                         f->flow_id);
                                f->n_pid = -1;
                                reg_flow_set_state(f, FLOW_DEALLOC_PENDING);
                                continue;
                        }

                        if (kill(f->n_pid, 0) < 0) {
                                log_dbg("Process %d gone, deallocating "
                                        "flow %d.",
                                         f->n_pid, f->flow_id);
                                f->n_pid = -1;
                                reg_flow_set_state(f, FLOW_DEALLOC_PENDING);
                                ipcpi   = f->n_1_pid;
                                flow_id = f->flow_id;
                                ipcp_flow_dealloc(ipcpi, flow_id, DEALLOC_TIME);
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
                                reg_flow_set_state(f, FLOW_DEALLOC_PENDING);
                        }
                }

                pthread_cleanup_pop(true);

                nanosleep(&timeout, NULL);
        }
}

__attribute__((no_sanitize_address))
static void * acceptloop(void * o)
{
        int            csockfd;

        (void) o;

        while (irmd_get_state() == IRMD_RUNNING) {
                struct cmd * cmd;

                csockfd = accept(irmd.sockfd, 0, 0);
                if (csockfd < 0)
                        continue;

                cmd = malloc(sizeof(*cmd));
                if (cmd == NULL) {
                        log_err("Out of memory.");
                        close(csockfd);
                        break;
                }

                pthread_cleanup_push(__cleanup_close_ptr, &csockfd);
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

static irm_msg_t * do_command_msg(irm_msg_t * msg)
{
        struct ipcp_config conf;
        irm_msg_t *        ret_msg;
        buffer_t           data;
        struct reg_flow    f;
        struct qos_spec    qs;
        struct timespec *  dl  = NULL;
        struct timespec    ts  = {0, 0};
        int                res;

        memset(&f, 0, sizeof(f));

        ret_msg = malloc(sizeof(*ret_msg));
        if (ret_msg == NULL) {
                log_err("Failed to malloc return msg.");
                return NULL;
        }

        irm_msg__init(ret_msg);

        ret_msg->code = IRM_MSG_CODE__IRM_REPLY;

        if (msg->has_timeo_sec) {
                struct timespec now;
                clock_gettime(PTHREAD_COND_CLOCK, &now);
                assert(msg->has_timeo_nsec);

                ts.tv_sec  = msg->timeo_sec;
                ts.tv_nsec = msg->timeo_nsec;

                ts_add(&ts, &now, &ts);

                dl = &ts;
        }

        pthread_cleanup_push(free_msg, ret_msg);

        switch (msg->code) {
        case IRM_MSG_CODE__IRM_CREATE_IPCP:
                res = create_ipcp(msg->name, msg->ipcp_type);
                break;
        case IRM_MSG_CODE__IPCP_CREATE_R:
                res = create_ipcp_r(msg->pid, msg->result);
                break;
        case IRM_MSG_CODE__IRM_DESTROY_IPCP:
                res = destroy_ipcp(msg->pid);
                break;
        case IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP:
                conf = ipcp_config_msg_to_s(msg->conf);
                res = bootstrap_ipcp(msg->pid, &conf);
                break;
        case IRM_MSG_CODE__IRM_ENROLL_IPCP:
                res = enroll_ipcp(msg->pid, msg->dst);
                break;
        case IRM_MSG_CODE__IRM_CONNECT_IPCP:
                qs = qos_spec_msg_to_s(msg->qosspec);
                res = connect_ipcp(msg->pid, msg->dst, msg->comp, qs);
                break;
        case IRM_MSG_CODE__IRM_DISCONNECT_IPCP:
                res = disconnect_ipcp(msg->pid, msg->dst, msg->comp);
                break;
        case IRM_MSG_CODE__IRM_BIND_PROGRAM:
                res = bind_program(msg->prog, msg->name, msg->opts,
                                   msg->n_args, msg->args);
                break;
        case IRM_MSG_CODE__IRM_UNBIND_PROGRAM:
                res = unbind_program(msg->prog, msg->name);
                break;
        case IRM_MSG_CODE__IRM_PROC_ANNOUNCE:
                res = proc_announce(msg->pid, msg->prog);
                break;
        case IRM_MSG_CODE__IRM_BIND_PROCESS:
                res = bind_process(msg->pid, msg->name);
                break;
        case IRM_MSG_CODE__IRM_UNBIND_PROCESS:
                res = unbind_process(msg->pid, msg->name);
                break;
        case IRM_MSG_CODE__IRM_LIST_IPCPS:
                res = list_ipcps(&ret_msg->ipcps, &ret_msg->n_ipcps);
                break;
        case IRM_MSG_CODE__IRM_CREATE_NAME:
                res = name_create(msg->names[0]->name,
                                  msg->names[0]->pol_lb);
                break;
        case IRM_MSG_CODE__IRM_DESTROY_NAME:
                res = name_destroy(msg->name);
                break;
        case IRM_MSG_CODE__IRM_LIST_NAMES:
                res = list_names(&ret_msg->names, &ret_msg->n_names);
                break;
        case IRM_MSG_CODE__IRM_REG_NAME:
                res = name_reg(msg->name, msg->pid);
                break;
        case IRM_MSG_CODE__IRM_UNREG_NAME:
                res = name_unreg(msg->name, msg->pid);
                break;
        case IRM_MSG_CODE__IRM_FLOW_ACCEPT:
                data.len  = msg->pk.len;
                data.data = msg->pk.data;
                assert(data.len > 0 ? data.data != NULL : data.data == NULL);
                res = flow_accept(msg->pid, dl, &f, &data);
                if (res == 0) {
                        qosspec_msg_t * qs_msg;
                        qs_msg = qos_spec_s_to_msg(&f.qs);
                        ret_msg->has_flow_id = true;
                        ret_msg->flow_id     = f.flow_id;
                        ret_msg->has_pid     = true;
                        ret_msg->pid         = f.n_1_pid;
                        ret_msg->qosspec     = qs_msg;
                        ret_msg->has_mpl     = true;
                        ret_msg->mpl         = f.mpl;
                        ret_msg->has_pk      = true;
                        ret_msg->pk.data     = data.data;
                        ret_msg->pk.len      = data.len;
                }
                break;
        case IRM_MSG_CODE__IRM_FLOW_ALLOC:
                data.len  = msg->pk.len;
                data.data = msg->pk.data;
                qs = qos_spec_msg_to_s(msg->qosspec);
                assert(data.len > 0 ? data.data != NULL : data.data == NULL);
                res = flow_alloc(msg->pid, msg->dst, qs, dl, &f, &data);
                if (res == 0) {
                        ret_msg->has_flow_id = true;
                        ret_msg->flow_id     = f.flow_id;
                        ret_msg->has_pid     = true;
                        ret_msg->pid         = f.n_1_pid;
                        ret_msg->has_mpl     = true;
                        ret_msg->mpl         = f.mpl;
                        ret_msg->has_pk      = true;
                        ret_msg->pk.data     = data.data;
                        ret_msg->pk.len      = data.len;
                }
                break;
        case IRM_MSG_CODE__IRM_FLOW_JOIN:
                assert(msg->pk.len == 0 && msg->pk.data == NULL);
                qs = qos_spec_msg_to_s(msg->qosspec);
                res = flow_join(msg->pid, msg->dst, qs, dl, &f);
                if (res == 0) {
                        ret_msg->has_flow_id = true;
                        ret_msg->flow_id     = f.flow_id;
                        ret_msg->has_pid     = true;
                        ret_msg->pid         = f.n_1_pid;
                        ret_msg->has_mpl     = true;
                        ret_msg->mpl         = f.mpl;
                }
                break;
        case IRM_MSG_CODE__IRM_FLOW_DEALLOC:
                res = flow_dealloc(msg->pid, msg->flow_id, msg->timeo_sec);
                break;
        case IRM_MSG_CODE__IPCP_FLOW_REQ_ARR:
                data.len  = msg->pk.len;
                data.data = msg->pk.data;
                msg->has_pk  = false; /* pass data */
                msg->pk.data = NULL;
                msg->pk.len  = 0;
                assert(data.len > 0 ? data.data != NULL : data.data == NULL);
                qs = qos_spec_msg_to_s(msg->qosspec);
                res = flow_req_arr(msg->pid, &f, msg->hash.data,
                                   msg->mpl, qs, data);
                if (res == 0) {
                        ret_msg->has_flow_id = true;
                        ret_msg->flow_id     = f.flow_id;
                        ret_msg->has_pid     = true;
                        ret_msg->pid         = f.n_pid;
                }
                break;
        case IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY:
                data.len  = msg->pk.len;
                data.data = msg->pk.data;
                msg->has_pk  = false; /* pass data */
                msg->pk.data = NULL;
                msg->pk.len  = 0;
                assert(data.len > 0 ? data.data != NULL : data.data == NULL);
                res = flow_alloc_reply(msg->flow_id, msg->response,
                                       msg->mpl, data);
                break;
        default:
                log_err("Don't know that message code.");
                res = -1;
                break;
        }

        pthread_cleanup_pop(false);

        ret_msg->has_result = true;
        ret_msg->result     = res;

        return ret_msg;
}

static void * mainloop(void * o)
{
        int             sfd;
        irm_msg_t *     msg;
        buffer_t        buffer;

        (void) o;

        while (true) {
                irm_msg_t *  ret_msg;
                struct cmd * cmd;

                pthread_mutex_lock(&irmd.cmd_lock);

                pthread_cleanup_push(__cleanup_mutex_unlock, &irmd.cmd_lock);

                while (list_is_empty(&irmd.cmds))
                        pthread_cond_wait(&irmd.cmd_cond, &irmd.cmd_lock);

                cmd = list_last_entry(&irmd.cmds, struct cmd, next);
                list_del(&cmd->next);

                pthread_cleanup_pop(true);

                msg = irm_msg__unpack(NULL, cmd->len, cmd->cbuf);
                sfd = cmd->fd;

                free(cmd);

                if (msg == NULL) {
                        close(sfd);
                        continue;
                }

                tpm_dec(irmd.tpm);

                pthread_cleanup_push(__cleanup_close_ptr, &sfd);
                pthread_cleanup_push(free_msg, msg);

                ret_msg = do_command_msg(msg);

                pthread_cleanup_pop(true);
                pthread_cleanup_pop(false);

                if (ret_msg == NULL) {
                        log_err("Failed to create return message.");
                        goto fail_msg;
                }

                if (ret_msg->result == -EPIPE || ret_msg->result == -EIRMD) {
                        log_err("Failed to execute command: %d.", ret_msg->result);
                        goto fail;
                }

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

                irm_msg__free_unpacked(ret_msg, NULL);

                pthread_cleanup_push(__cleanup_close_ptr, &sfd);

                if (write(sfd, buffer.data, buffer.len) == -1)
                        log_warn("Failed to send reply message.");

                free(buffer.data);

                pthread_cleanup_pop(true);

                tpm_inc(irmd.tpm);

                continue;
 fail:
                irm_msg__free_unpacked(ret_msg, NULL);
 fail_msg:
                close(sfd);
                tpm_inc(irmd.tpm);
                continue;
        }

        return (void *) 0;
}

static void irm_fini(void)
{
        struct list_head * p;
        struct list_head * h;

        if (irmd_get_state() != IRMD_NULL)
                log_warn("Unsafe destroy.");

        tpm_destroy(irmd.tpm);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        /* Clear the lists. */
        list_for_each_safe(p, h, &irmd.ipcps) {
                struct reg_ipcp * e = list_entry(p, struct reg_ipcp, next);
                list_del(&e->next);
                reg_ipcp_destroy(e);
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
                registry_names_del_proc(e->pid);
                free(e);
        }

        list_for_each_safe(p, h, &irmd.progs) {
                struct reg_prog * e = list_entry(p, struct reg_prog, next);
                list_del(&e->next);
                reg_prog_destroy(e);
        }

        list_for_each_safe(p, h, &irmd.procs) {
                struct reg_proc * e = list_entry(p, struct reg_proc, next);
                list_del(&e->next);
                e->state = PROC_INIT; /* sanitizer already joined */
                reg_proc_destroy(e);
        }

        registry_destroy_names();

        pthread_rwlock_unlock(&irmd.reg_lock);

        close(irmd.sockfd);

        if (unlink(IRM_SOCK_PATH))
                log_dbg("Failed to unlink %s.", IRM_SOCK_PATH);

        pthread_rwlock_wrlock(&irmd.reg_lock);

        if (irmd.flow_ids != NULL)
                bmp_destroy(irmd.flow_ids);

        list_for_each_safe(p, h, &irmd.flows) {
                struct reg_flow * f = list_entry(p, struct reg_flow, next);
                list_del(&f->next);
                reg_flow_destroy(f);
        }

        pthread_rwlock_unlock(&irmd.reg_lock);


        if (irmd.rdrb != NULL)
                shm_rdrbuff_destroy(irmd.rdrb);

        if (irmd.lf != NULL)
                lockfile_destroy(irmd.lf);

        pthread_mutex_destroy(&irmd.cmd_lock);
        pthread_cond_destroy(&irmd.cmd_cond);
        pthread_rwlock_destroy(&irmd.reg_lock);
        pthread_rwlock_destroy(&irmd.state_lock);

#ifdef HAVE_FUSE
        sleep(1);
        if (rmdir(FUSE_PREFIX))
                log_warn("Failed to remove " FUSE_PREFIX);
#endif
}

static int ouroboros_reset(void)
{
        shm_rdrbuff_purge();
        lockfile_destroy(irmd.lf);

        return 0;
}

static int irm_init(void)
{
        struct stat        st;
        pthread_condattr_t cattr;
#ifdef HAVE_FUSE
        mode_t             mask;
#endif
        memset(&st, 0, sizeof(st));

        log_init(!irmd.log_stdout);

        irmd.lf = lockfile_create();
        if (irmd.lf == NULL) {
                irmd.lf = lockfile_open();
                if (irmd.lf == NULL) {
                        log_err("Lockfile error.");
                        goto fail_lockfile;
                }

                if (kill(lockfile_owner(irmd.lf), 0) < 0) {
                        log_warn("IRMd didn't properly shut down last time.");
                        if (ouroboros_reset() < 0) {
                                log_err("Failed to clean stale resources.");
                                lockfile_close(irmd.lf);
                                goto fail_lockfile;
                        }

                        log_warn("Stale resources cleaned.");
                        irmd.lf = lockfile_create();
                } else {
                        log_warn("IRMd already running (%d), exiting.",
                                 lockfile_owner(irmd.lf));
                        lockfile_close(irmd.lf);
                        goto fail_lockfile;
                }
        }

        if (irmd.lf == NULL) {
                log_err("Failed to create lockfile.");
                goto fail_lockfile;
        }

        if (pthread_rwlock_init(&irmd.state_lock, NULL)) {
                log_err("Failed to initialize rwlock.");
                goto fail_state_lock;
        }

        if (pthread_rwlock_init(&irmd.reg_lock, NULL)) {
                log_err("Failed to initialize rwlock.");
                goto fail_reg_lock;
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
        list_head_init(&irmd.procs);
        list_head_init(&irmd.progs);
        list_head_init(&irmd.spawned_pids);
        list_head_init(&irmd.names);
        list_head_init(&irmd.flows);
        list_head_init(&irmd.cmds);

        irmd.flow_ids = bmp_create(SYS_MAX_FLOWS, 0);
        if (irmd.flow_ids == NULL) {
                log_err("Failed to create flow_ids bitmap.");
                goto fail_flow_ids;
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

        irmd.tpm = tpm_create(IRMD_MIN_THREADS, IRMD_ADD_THREADS,
                              mainloop, NULL);
        if (irmd.tpm == NULL) {
                log_err("Failed to greate thread pool.");
                goto fail_tpm_create;
        }
#ifdef HAVE_FUSE
        mask = umask(0);

        if (stat(FUSE_PREFIX, &st) != -1)
                log_warn(FUSE_PREFIX " already exists...");
        else
                mkdir(FUSE_PREFIX, 0777);

        umask(mask);
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

        return 0;

#ifdef HAVE_LIBGCRYPT
 fail_gcry_version:
 #ifdef HAVE_FUSE
        rmdir(FUSE_PREFIX);
 #endif
        tpm_destroy(irmd.tpm);
#endif
 fail_tpm_create:
        shm_rdrbuff_destroy(irmd.rdrb);
 fail_rdrbuff:
        close(irmd.sockfd);
 fail_sock_path:
        unlink(IRM_SOCK_PATH);
 fail_stat:
        bmp_destroy(irmd.flow_ids);
 fail_flow_ids:
        pthread_cond_destroy(&irmd.cmd_cond);
 fail_cmd_cond:
        pthread_mutex_destroy(&irmd.cmd_lock);
 fail_cmd_lock:
        pthread_rwlock_destroy(&irmd.reg_lock);
 fail_reg_lock:
        pthread_rwlock_destroy(&irmd.state_lock);
 fail_state_lock:
        lockfile_destroy(irmd.lf);
 fail_lockfile:
        log_fini();
        return -1;
}

static void usage(void)
{
        printf("Usage: irmd \n"
#ifdef OUROBOROS_CONFIG_INI
               "         [--config <path> (Path to configuration file)]\n"
#endif
               "         [--stdout  (Log to stdout instead of system log)]\n"
               "         [--version (Print version number and exit)]\n"
               "\n");
}

static int irm_start(void)
{
        if (tpm_start(irmd.tpm))
                goto fail_tpm_start;

        irmd_set_state(IRMD_RUNNING);

        if (pthread_create(&irmd.irm_sanitize, NULL, irm_sanitize, NULL))
                goto fail_irm_sanitize;

        if (pthread_create(&irmd.acceptor, NULL, acceptloop, NULL))
                goto fail_acceptor;

        log_info("Ouroboros IPC Resource Manager daemon started...");

        return 0;

 fail_acceptor:
        pthread_cancel(irmd.irm_sanitize);
        pthread_join(irmd.irm_sanitize, NULL);
 fail_irm_sanitize:
        irmd_set_state(IRMD_NULL);
        tpm_stop(irmd.tpm);
 fail_tpm_start:
        return -1;

}

static void irm_sigwait(sigset_t sigset)
{
        int sig;

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
}

static void irm_stop(void)
{
        pthread_cancel(irmd.acceptor);

        pthread_join(irmd.acceptor, NULL);
        pthread_join(irmd.irm_sanitize, NULL);

        tpm_stop(irmd.tpm);
}

static void irm_argparse(int     argc,
                         char ** argv)
{
#ifdef HAVE_TOML
        irmd.cfg_file = NULL;
#endif
        argc--;
        argv++;
        while (argc > 0) {
                if (strcmp(*argv, "--stdout") == 0) {
                        irmd.log_stdout = true;
                        argc--;
                        argv++;
                } else if (strcmp(*argv, "--version") == 0) {
                        printf("Ouroboros version %d.%d.%d\n",
                               OUROBOROS_VERSION_MAJOR,
                               OUROBOROS_VERSION_MINOR,
                               OUROBOROS_VERSION_PATCH);
                        exit(EXIT_SUCCESS);
#ifdef HAVE_TOML
                } else if (strcmp (*argv, "--config") == 0) {
                        irmd.cfg_file = *(argv + 1);
                        argc -= 2;
                        argv += 2;
#endif
                } else {
                        usage();
                        exit(EXIT_FAILURE);
                }
        }
}

int main(int     argc,
         char ** argv)
{
        sigset_t sigset;
        int      ret = EXIT_SUCCESS;

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGTERM);
        sigaddset(&sigset, SIGPIPE);

        irm_argparse(argc, argv);

        if (irmd.log_stdout)
                printf(O7S_ASCII_ART);

        if (geteuid() != 0) {
                printf("IPC Resource Manager must be run as root.\n");
                exit(EXIT_FAILURE);
        }

        if (irm_init() < 0)
                goto fail_irm_init;

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (irm_start() < 0)
                goto fail_irm_start;

#ifdef HAVE_TOML
        if (irm_configure(irmd.cfg_file) < 0) {
                irmd_set_state(IRMD_NULL);
                ret = EXIT_FAILURE;
        }
#endif
        irm_sigwait(sigset);

        irm_stop();

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        irm_fini();

        log_info("Bye.");

        log_fini();

        exit(ret);

 fail_irm_start:
        irm_fini();
 fail_irm_init:
        exit(EXIT_FAILURE);
}
