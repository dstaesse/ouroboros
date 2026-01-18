/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
The IPC Resource Manager - Registry
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

#define OUROBOROS_PREFIX "reg"

#include <ouroboros/bitmap.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/logs.h>
#include <ouroboros/protobuf.h>
#include <ouroboros/pthread.h>

#include "reg.h"
#include "flow.h"
#include "ipcp.h"
#include "name.h"
#include "proc.h"
#include "prog.h"

#include <assert.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

#define ID_OFFT 1 /* reserve some flow_ids */

struct {
        struct bmp *         flow_ids;  /* flow_ids for flows         */

        struct list_head     flows;     /* flow information           */
        size_t               n_flows;   /* number of flows            */

        struct list_head     ipcps;     /* list of ipcps in system    */
        size_t               n_ipcps;   /* number of ipcps            */

        struct list_head     names;     /* registered names known     */
        size_t               n_names;   /* number of names            */

        struct list_head     procs;     /* processes                  */
        size_t               n_procs;   /* number of processes        */

        struct list_head     progs;     /* programs known             */
        size_t               n_progs;   /* number of programs         */

        struct list_head     spawned;   /* child processes            */
        size_t               n_spawned; /* number of child processes  */

        pthread_mutex_t      mtx;       /* registry lock              */
        pthread_cond_t       cond;      /* condvar for reg changes    */
} reg;

struct pid_entry {
        struct list_head next;
        pid_t            pid;
};

static struct reg_flow * __reg_get_flow(int flow_id)
{
        struct list_head * p;

        assert(flow_id >= ID_OFFT);

        list_for_each(p, &reg.flows) {
                struct reg_flow * entry;
                entry = list_entry(p, struct reg_flow, next);
                if (entry->info.id == flow_id)
                        return entry;
        }

        return NULL;
}

static struct reg_flow * __reg_get_accept_flow(pid_t pid)
{
        struct list_head * p;

        list_for_each(p, &reg.flows) {
                struct reg_flow * entry;
                entry = list_entry(p, struct reg_flow, next);
                if (entry->info.state != FLOW_ACCEPT_PENDING)
                        continue;
                if (entry->info.n_pid == pid)
                        return entry;
        }

        return NULL;
}

static struct list_head * __reg_after_flow(int flow_id)
{
        struct list_head * p;

        assert(flow_id >= ID_OFFT);

        list_for_each(p, &reg.flows) {
                struct reg_flow * entry;
                entry = list_entry(p, struct reg_flow, next);
                if (entry->info.id > flow_id)
                        break;
        }

        return p;
}

static struct reg_ipcp * __reg_get_ipcp(pid_t pid)
{
        struct list_head * p;

        assert(pid > 0);

        list_for_each(p, &reg.ipcps) {
                struct reg_ipcp * entry;
                entry = list_entry(p, struct reg_ipcp, next);
                if (entry->info.pid == pid)
                        return entry;
        }

        return NULL;
}

static struct reg_ipcp * __reg_get_ipcp_by_layer(const char * layer)
{
        struct list_head * p;

        list_for_each(p, &reg.ipcps) {
                struct reg_ipcp * entry;
                entry = list_entry(p, struct reg_ipcp, next);
                if (strcmp(entry->layer.name, layer) == 0)
                        return entry;
        }

        return NULL;
}


static struct list_head * __reg_after_ipcp(const struct ipcp_info * info)
{
        struct list_head * p;

        assert(info != NULL);

        list_for_each(p, &reg.ipcps) {
                struct reg_ipcp * entry;
                entry = list_entry(p, struct reg_ipcp, next);
                if (entry->info.type < info->type)
                        continue;

                if (entry->info.type > info->type)
                        break;

                if (entry->info.pid > info->pid)
                        break;
        }

        return p;
}

static struct reg_name * __reg_get_name(const char * name)
{
        struct list_head * p;

        assert(name != NULL);

        list_for_each(p, &reg.names) {
                struct reg_name * entry;
                entry = list_entry(p, struct reg_name, next);
                if (strcmp(entry->info.name, name) == 0)
                        return entry;
        }

        return NULL;
}

static int __reg_get_pending_flow_id(const char * name)
{
        struct reg_name * entry;
        struct reg_flow * flow;
        pid_t             pid;

        assert(name != NULL);
        assert(strlen(name) > 0);
        assert(strlen(name) < NAME_SIZE + 1);

        entry =__reg_get_name(name);
        if (entry == NULL)
                return -ENAME;

        pid = reg_name_get_active(entry);
        if (pid < 0)
                return -EAGAIN;

        flow = __reg_get_accept_flow(pid);
        if (flow == NULL) /* compiler barks, this can't be NULL */
                return -EAGAIN;

        strcpy(flow->name, name);

        return flow->info.id;
}

static struct list_head * __reg_after_name(const char * name)
{
        struct list_head * p;

        assert(name != NULL);

        list_for_each(p, &reg.names) {
                struct reg_name * entry;
                entry = list_entry(p, struct reg_name, next);
                if (strcmp(entry->info.name, name) > 0)
                        break;
        }

        return p;
}

static struct reg_proc * __reg_get_proc(pid_t pid)
{
        struct list_head * p;

        list_for_each(p, &reg.procs) {
                struct reg_proc * entry;
                entry = list_entry(p, struct reg_proc, next);
                if (entry->info.pid == pid)
                        return entry;
        }

        return NULL;
}

static struct list_head * __reg_after_proc(pid_t pid)
{
        struct list_head * p;

        list_for_each(p, &reg.procs) {
                struct reg_proc * entry;
                entry = list_entry(p, struct reg_proc, next);
                if (entry->info.pid > pid)
                        break;
        }

        return p;
}

static void __reg_kill_all_proc(int signal)
{
        struct list_head * p;

        list_for_each(p, &reg.procs) {
                struct reg_proc * entry;
                entry = list_entry(p, struct reg_proc, next);
                kill(entry->info.pid, signal);
        }
}

static pid_t __reg_get_dead_proc(void)
{
        struct list_head * p;

        list_for_each(p, &reg.procs) {
                struct reg_proc * entry;
                entry = list_entry(p, struct reg_proc, next);
                if (kill(entry->info.pid, 0) < 0)
                        return entry->info.pid;
        }

        return -1;
}

static void __reg_cancel_flows_for_proc(pid_t pid)
{
        struct list_head * p;
        bool   changed = false;

        list_for_each(p, &reg.flows) {
                struct reg_flow * entry;
                entry = list_entry(p, struct reg_flow, next);
                if (entry->info.n_pid != pid)
                        continue;

                switch (entry->info.state) {
                case FLOW_ALLOC_PENDING:
                        /* FALLTHRU */
                case FLOW_ACCEPT_PENDING:
                        entry->info.state = FLOW_DEALLOCATED;
                        changed = true;
                        break;
                default:
                        continue;
                }
        }

        if (changed)
                pthread_cond_broadcast(&reg.cond);
}

static struct pid_entry * __reg_get_spawned(pid_t pid)
{
        struct list_head * p;

        list_for_each(p, &reg.spawned) {
                struct pid_entry * entry;
                entry = list_entry(p, struct pid_entry, next);
                if (entry->pid == pid)
                        return entry;
        }

        return NULL;
}

static struct list_head * __reg_after_spawned(pid_t pid)
{
        struct list_head * p;

        list_for_each(p, &reg.spawned) {
                struct pid_entry * entry;
                entry = list_entry(p, struct pid_entry, next);
                if (entry->pid > pid)
                        break;
        }

        return p;
}

static void __reg_kill_all_spawned(int signal)
{
        struct list_head * p;

        list_for_each(p, &reg.spawned) {
                struct pid_entry * entry;
                entry = list_entry(p, struct pid_entry, next);
                kill(entry->pid, signal);
        }
}

static pid_t __reg_first_spawned(void)
{
        if (list_is_empty(&reg.spawned))
                return -1;

        return list_first_entry(&reg.spawned, struct pid_entry, next)->pid;
}

static struct reg_prog * __reg_get_prog(const char * name)
{
        struct list_head * p;

        list_for_each(p, &reg.progs) {
                struct reg_prog * entry;
                entry = list_entry(p, struct reg_prog, next);
                if (strcmp(entry->info.name, name) == 0)
                        return entry;
        }

        return NULL;
}

static char ** __reg_get_exec(const char * name)
{
        struct list_head * p;

        list_for_each(p, &reg.names) {
                struct reg_name * entry;
                entry = list_entry(p, struct reg_name, next);
                if (strcmp(entry->info.name, name) == 0)
                        return reg_name_get_exec(entry);
        }

        return NULL;
}

static struct list_head * __reg_after_prog(const char * name)
{
        struct list_head * p;

        list_for_each(p, &reg.progs) {
                struct reg_prog * entry;
                entry = list_entry(p, struct reg_prog, next);
                if (strcmp(entry->info.name, name) > 0)
                        break;
        }

        return p;
}

static void __reg_del_name_from_procs(const char * name)
{
        struct list_head * p;

        list_for_each(p, &reg.procs) {
                struct reg_proc * proc;
                proc = list_entry(p, struct reg_proc, next);
                reg_proc_del_name(proc, name);
        }
}

static void __reg_del_name_from_progs(const char * name)
{
        struct list_head * p;

        list_for_each(p, &reg.progs) {
                struct reg_prog * prog;
                prog = list_entry(p, struct reg_prog, next);
                reg_prog_del_name(prog, name);
        }
}

static void __reg_proc_update_names(struct reg_proc * proc)
{
        struct list_head * p;
        struct reg_prog * prog;

        assert(list_is_empty(&proc->names));

        prog = __reg_get_prog(proc->info.prog);
        if (prog == NULL)
                return;

        list_for_each(p, &reg.names) {
                struct reg_name * name;
                name = list_entry(p, struct reg_name, next);
                assert(!reg_name_has_proc(name, proc->info.pid));
                if (reg_prog_has_name(prog, name->info.name)) {
                        reg_proc_add_name(proc, name->info.name);
                        reg_name_add_proc(name, proc->info.pid);
                }
        }
}

static void __reg_del_proc_from_names(pid_t pid)
{
        struct list_head * p;

        list_for_each(p, &reg.names) {
                struct reg_name * name;
                name = list_entry(p, struct reg_name, next);
                reg_name_del_proc(name, pid);
        }
}

static void __reg_del_prog_from_names(const char * prog)
{
        struct list_head * p;

        list_for_each(p, &reg.names) {
                struct reg_name * name;
                name = list_entry(p, struct reg_name, next);
                reg_name_del_prog(name, prog);
        }
}

static int __reg_add_active_proc(pid_t pid)
{
        struct list_head * p;
        size_t             n_names = 0;
        size_t             failed = 0;

        assert(pid > 0);

        list_for_each(p, &reg.names) {
                struct reg_name * name;
                name = list_entry(p, struct reg_name, next);
                if (reg_name_has_proc(name, pid)) {
                        if (reg_name_add_active(name, pid) < 0)
                                failed++;
                        n_names++;
                }
        }

        if (n_names > 0 && failed == n_names)
                return -1;

        return 0; /* some were marked */
}

static void __reg_del_active_proc(pid_t pid)
{
        struct list_head * p;

        assert(pid > 0);

        list_for_each(p, &reg.names) {
                struct reg_name * name;
                name = list_entry(p, struct reg_name, next);
                reg_name_del_active(name, pid);
        }
}

int reg_init(void)
{
        pthread_condattr_t cattr;

        if (pthread_mutex_init(&reg.mtx, NULL) != 0) {
                log_err("Failed to initialize mutex.");
                goto fail_mtx;
        }

        if (pthread_condattr_init(&cattr) != 0) {
                log_err("Failed to initialize condattr.");
                goto fail_cattr;
        }

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&reg.cond, &cattr) != 0) {
                log_err("Failed to initialize condvar.");
                goto fail_cond;
        }

        reg.flow_ids = bmp_create(SYS_MAX_FLOWS -ID_OFFT, ID_OFFT);
        if (reg.flow_ids == NULL) {
                log_err("Failed to create flow_ids bitmap.");
                goto fail_flow_ids;
        }

        pthread_condattr_destroy(&cattr);

        list_head_init(&reg.flows);
        list_head_init(&reg.ipcps);
        list_head_init(&reg.names);
        list_head_init(&reg.procs);
        list_head_init(&reg.progs);
        list_head_init(&reg.spawned);

        return 0;

 fail_flow_ids:
        pthread_cond_destroy(&reg.cond);
 fail_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(&reg.mtx);
 fail_mtx:
        return -1;
}

void reg_clear(void)
{
        struct list_head * p;
        struct list_head * h;

        pthread_mutex_lock(&reg.mtx);

        list_for_each_safe(p, h, &reg.spawned) {
                struct pid_entry * entry;
                entry = list_entry(p, struct pid_entry, next);
                list_del(&entry->next);
                free(entry);
                reg.n_spawned--;
        }

        list_for_each_safe(p, h, &reg.progs) {
                struct reg_prog * entry;
                entry = list_entry(p, struct reg_prog, next);
                list_del(&entry->next);
                __reg_del_prog_from_names(entry->info.path);
                reg_prog_destroy(entry);
                reg.n_progs--;
        }

        list_for_each_safe(p, h, &reg.procs) {
                struct reg_proc * entry;
                entry = list_entry(p, struct reg_proc, next);
                list_del(&entry->next);
                __reg_del_proc_from_names(entry->info.pid);
                reg_proc_destroy(entry);
                reg.n_procs--;
        }

        list_for_each_safe(p, h, &reg.flows) {
                struct reg_flow * entry;
                entry = list_entry(p, struct reg_flow, next);
                list_del(&entry->next);
                reg_flow_destroy(entry);
                reg.n_flows--;
        }

        list_for_each_safe(p, h, &reg.names) {
                struct reg_name * entry;
                entry = list_entry(p, struct reg_name, next);
                list_del(&entry->next);
                reg_name_destroy(entry);
                reg.n_names--;
        }

        list_for_each_safe(p, h, &reg.ipcps) {
                struct reg_ipcp * entry;
                entry = list_entry(p, struct reg_ipcp, next);
                list_del(&entry->next);
                reg_ipcp_destroy(entry);
                reg.n_ipcps--;
        }

        pthread_mutex_unlock(&reg.mtx);
}

void reg_fini(void)
{
        assert(list_is_empty(&reg.spawned));
        assert(list_is_empty(&reg.progs));
        assert(list_is_empty(&reg.procs));
        assert(list_is_empty(&reg.names));
        assert(list_is_empty(&reg.ipcps));
        assert(list_is_empty(&reg.flows));

        assert(reg.n_spawned == 0);
        assert(reg.n_progs == 0);
        assert(reg.n_procs == 0);
        assert(reg.n_names == 0);
        assert(reg.n_ipcps == 0);
        assert(reg.n_flows == 0);

        bmp_destroy(reg.flow_ids);

        if (pthread_cond_destroy(&reg.cond) != 0)
                log_warn("Failed to destroy condvar.");

        if (pthread_mutex_destroy(&reg.mtx) != 0)
                log_warn("Failed to destroy mutex.");
}

int reg_create_flow(struct flow_info * info)
{
        struct reg_flow *  f;

        assert(info != NULL);
        assert(info->id == 0);
        assert(info->n_pid != 0);
        assert(info->state == FLOW_INIT);

        pthread_mutex_lock(&reg.mtx);

        info->id = bmp_allocate(reg.flow_ids);
        if (!bmp_is_id_valid(reg.flow_ids, info->id)) {
                log_err("Failed to allocate flow id.");
                goto fail_id;
        }

        f = reg_flow_create(info);
        if (f == NULL) {
                log_err("Failed to create flow %d.", info->id);
                goto fail_flow;
        }

        list_add(&f->next, __reg_after_flow(info->id));

        reg.n_flows++;

        pthread_mutex_unlock(&reg.mtx);

        return 0;

 fail_flow:
        bmp_release(reg.flow_ids, info->id);
        info->id = 0;
 fail_id:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

int  reg_destroy_flow(int flow_id)
{
        struct reg_flow * f;

        pthread_mutex_lock(&reg.mtx);

        f = __reg_get_flow(flow_id);
        if (f == NULL) {
                log_err("Flow %d does not exist.", flow_id);
                goto no_flow;
        }

        list_del(&f->next);

        reg.n_flows--;

        bmp_release(reg.flow_ids, flow_id);

        pthread_mutex_unlock(&reg.mtx);

        pthread_cond_broadcast(&reg.cond);

        reg_flow_destroy(f);

        return 0;

 no_flow:
        pthread_mutex_unlock(&reg.mtx);
        return -1;

}

bool reg_has_flow(int flow_id)
{
        bool ret;

        pthread_mutex_lock(&reg.mtx);

        ret = __reg_get_flow(flow_id) != NULL;

        pthread_mutex_unlock(&reg.mtx);

        return ret;
}

int reg_create_ipcp(const struct ipcp_info * info)
{
        struct reg_ipcp *  ipcp;
        struct pid_entry * entry;

        assert(info != NULL);
        assert(info->pid != 0);
        assert(info->state == IPCP_INIT);

        pthread_mutex_lock(&reg.mtx);

        if (__reg_get_ipcp(info->pid) != NULL) {
                log_err("IPCP %d already exists.", info->pid);
                goto fail_ipcp;
        }

        ipcp = reg_ipcp_create(info);
        if (ipcp == NULL) {
                log_err("Failed to create ipcp %s.", info->name);
                goto fail_ipcp;
        }

        entry = malloc(sizeof(*entry));
        if (entry == NULL) {
                log_err("Failed to create spawn entry.\n");
                goto fail_spawn;
        }

        entry->pid = info->pid;

        list_add_tail(&ipcp->next, __reg_after_ipcp(info));
        list_add(&entry->next, __reg_after_spawned(info->pid));

        reg.n_ipcps++;
        reg.n_spawned++;

        pthread_mutex_unlock(&reg.mtx);

        return 0;

 fail_spawn:
        reg_ipcp_destroy(ipcp);
 fail_ipcp:
        pthread_mutex_unlock(&reg.mtx);
        return -1;

}

int reg_update_ipcp(struct ipcp_info * info)
{
        struct reg_ipcp * ipcp;

        pthread_mutex_lock(&reg.mtx);

        ipcp = __reg_get_ipcp(info->pid);
        if (ipcp == NULL) {
                log_err("IPCP %d does not exist.", info->pid);
                goto no_ipcp;

        }

        reg_ipcp_update(ipcp, info);

        pthread_mutex_unlock(&reg.mtx);

        reg_ipcp_destroy(ipcp);

        return 0;

 no_ipcp:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

bool reg_has_ipcp(pid_t pid)
{
        bool ret;

        pthread_mutex_lock(&reg.mtx);

        ret = __reg_get_ipcp(pid) != NULL;

        pthread_mutex_unlock(&reg.mtx);

        return ret;
}

static int __get_ipcp_info(ipcp_list_msg_t ** msg,
                           struct reg_ipcp * ipcp)
{
        *msg = malloc(sizeof(**msg));
        if (*msg == NULL)
                goto fail;

        ipcp_list_msg__init(*msg);

        (*msg)->name = strdup(ipcp->info.name);
        if ((*msg)->name == NULL)
                goto fail_msg;

        (*msg)->layer = strdup(ipcp->layer.name);
        if ((*msg)->layer == NULL)
                goto fail_msg;

        (*msg)->pid       = ipcp->info.pid;
        (*msg)->type      = ipcp->info.type;
        (*msg)->hash_algo = ipcp->layer.dir_hash_algo;

        return 0;

 fail_msg:
        ipcp_list_msg__free_unpacked(*msg, NULL);
        *msg = NULL;
 fail:
        return -1;
}

int reg_list_ipcps(ipcp_list_msg_t *** ipcps)
{
        struct list_head * p;
        int                i = 0;

        pthread_mutex_lock(&reg.mtx);

        if (reg.n_ipcps == 0)
                goto finish;

        *ipcps = malloc(reg.n_ipcps * sizeof(**ipcps));
        if (*ipcps == NULL) {
                log_err("Failed to malloc ipcps.");
                goto fail_malloc;
        }

        list_for_each(p, &reg.ipcps) {
                struct reg_ipcp * entry;
                entry = list_entry(p, struct reg_ipcp, next);
                if (__get_ipcp_info(&(*ipcps)[i], entry) < 0)
                        goto fail;

                i++;
        }
 finish:
        pthread_mutex_unlock(&reg.mtx);

        return i;

 fail:
        while (i-- > 0)
                ipcp_list_msg__free_unpacked((*ipcps)[i], NULL);
        free(*ipcps);
 fail_malloc:
        pthread_mutex_unlock(&reg.mtx);
        *ipcps = NULL;
        return -ENOMEM;
}

int reg_create_name(const struct name_info * info)
{
        struct reg_name *  n;

        assert(info != NULL);

        pthread_mutex_lock(&reg.mtx);

        if (__reg_get_name(info->name) != NULL) {
                log_dbg("Name %s already exists.", info->name);
                goto exists;
        }

        n = reg_name_create(info);
        if (n == NULL) {
                log_err("Failed to create name %s.", info->name);
                goto fail_name;
        }

        list_add(&n->next, __reg_after_name(info->name));

        reg.n_names++;

        pthread_mutex_unlock(&reg.mtx);
        return 0;
 exists:
        pthread_mutex_unlock(&reg.mtx);
        return -EEXIST;

 fail_name:
        pthread_mutex_unlock(&reg.mtx);
        return -1;

}

int  reg_destroy_name(const char * name)
{
        struct reg_name * n;

        pthread_mutex_lock(&reg.mtx);

        n = __reg_get_name(name);
        if (n == NULL) {
                log_err("Name %s does not exist.", name);
                goto no_name;
        }

        __reg_del_name_from_procs(name);
        __reg_del_name_from_progs(name);

        list_del(&n->next);

        reg.n_names--;

        pthread_mutex_unlock(&reg.mtx);

        reg_name_destroy(n);

        return 0;

 no_name:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

bool reg_has_name(const char * name)
{
        bool ret;

        pthread_mutex_lock(&reg.mtx);

        ret = __reg_get_name(name) != NULL;

        pthread_mutex_unlock(&reg.mtx);

        return ret;
}

int reg_get_name_info(const char *       name,
                      struct name_info * info)
{
        struct reg_name * n;

        assert(name != NULL);
        assert(info != NULL);

        pthread_mutex_lock(&reg.mtx);

        n = __reg_get_name(name);
        if (n == NULL) {
                log_err("Name %s does not exist.", name);
                goto no_name;
        }

        *info = n->info;

        pthread_mutex_unlock(&reg.mtx);

        return 0;

 no_name:
        pthread_mutex_unlock(&reg.mtx);
        return -ENOENT;

}

int reg_get_name_for_hash(char *          buf,
                          enum hash_algo  algo,
                          const uint8_t * hash)
{
        struct list_head * p;
        uint8_t *          thash;
        size_t             len;
        char *             name = NULL;

        len = hash_len(algo);

        thash = malloc(len);
        if (thash == NULL)
                return -ENOMEM;

        pthread_mutex_lock(&reg.mtx);

        list_for_each(p, &reg.names) {
                struct reg_name * n = list_entry(p, struct reg_name, next);
                str_hash(algo, thash, n->info.name);
                if (memcmp(thash, hash, len) == 0) {
                        name = n->info.name;
                        break;
                }
        }

        if (name != NULL)
                strcpy(buf, name);

        pthread_mutex_unlock(&reg.mtx);

        free(thash);

        return name == NULL ? -ENOENT : 0;
}

int reg_get_name_for_flow_id(char * buf,
                             int    flow_id)
{
        struct reg_flow * f;

        pthread_mutex_lock(&reg.mtx);

        f = __reg_get_flow(flow_id);
        if (f != NULL)
                strcpy(buf, f->name);

        pthread_mutex_unlock(&reg.mtx);

        return f == NULL ? -ENOENT : 0;
}

int reg_list_names(name_info_msg_t *** names)
{
        struct list_head * p;
        int                i = 0;

        pthread_mutex_lock(&reg.mtx);

        if (reg.n_names == 0)
                goto finish;

        *names = malloc(reg.n_names * sizeof(**names));
        if (*names == NULL) {
                log_err("Failed to malloc names.");
                goto fail_malloc;
        }

        list_for_each(p, &reg.names) {
                struct reg_name * entry;
                entry = list_entry(p, struct reg_name, next);
                (*names)[i] = name_info_s_to_msg(&entry->info);
                if ((*names)[i] == NULL) {
                        log_err("Failed to create name list info.");
                        goto fail;
                }
                /* wipe security info to avoid huge messages */
                free((*names)[i]->scrt);
                (*names)[i]->scrt = NULL;
                free((*names)[i]->skey);
                (*names)[i]->skey = NULL;
                free((*names)[i]->ccrt);
                (*names)[i]->ccrt = NULL;
                free((*names)[i]->ckey);
                (*names)[i]->ckey = NULL;

                i++;
        }
 finish:
        pthread_mutex_unlock(&reg.mtx);

        return i;

 fail:
        while (i-- > 0)
                name_info_msg__free_unpacked((*names)[i], NULL);
        free(*names);
 fail_malloc:
        pthread_mutex_unlock(&reg.mtx);
        *names = NULL;
        return -ENOMEM;
}

int reg_create_proc(const struct proc_info * info)
{
        struct reg_proc * proc;

        assert(info != NULL);

        pthread_mutex_lock(&reg.mtx);

        if (__reg_get_proc(info->pid) != NULL) {
                log_err("Process %d already exists.", info->pid);
                goto fail_proc;
        }

        proc = reg_proc_create(info);
        if (proc == NULL) {
                log_err("Failed to create process %d.", info->pid);
                goto fail_proc;
        }

        __reg_proc_update_names(proc);

        list_add(&proc->next, __reg_after_proc(info->pid));

        reg.n_procs++;

        pthread_cond_broadcast(&reg.cond);

        pthread_mutex_unlock(&reg.mtx);

        return 0;

 fail_proc:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

int reg_destroy_proc(pid_t pid)
{
        struct reg_proc *  proc;
        struct pid_entry * spawn;
        struct reg_ipcp *  ipcp;

        pthread_mutex_lock(&reg.mtx);

        proc = __reg_get_proc(pid);
        if (proc != NULL) {
                list_del(&proc->next);
                reg.n_procs--;
                reg_proc_destroy(proc);
                __reg_del_proc_from_names(pid);
                __reg_cancel_flows_for_proc(pid);
        }

        spawn = __reg_get_spawned(pid);
        if (spawn != NULL) {
                list_del(&spawn->next);
                reg.n_spawned--;
                free(spawn);
        }

        ipcp = __reg_get_ipcp(pid);
        if (ipcp != NULL) {
                list_del(&ipcp->next);
                reg.n_ipcps--;
                reg_ipcp_destroy(ipcp);
        }

        pthread_mutex_unlock(&reg.mtx);

        return 0;
}

bool reg_has_proc(pid_t pid)
{
        bool ret;

        pthread_mutex_lock(&reg.mtx);

        ret = __reg_get_proc(pid) != NULL;

        pthread_mutex_unlock(&reg.mtx);

        return ret;
}

void reg_kill_all_proc(int signal)
{
        pthread_mutex_lock(&reg.mtx);

        __reg_kill_all_proc(signal);

        pthread_mutex_unlock(&reg.mtx);
}

pid_t reg_get_dead_proc(void)
{
        pid_t ret;

        pthread_mutex_lock(&reg.mtx);

        ret = __reg_get_dead_proc();

        pthread_mutex_unlock(&reg.mtx);

        return ret;
}

int reg_create_spawned(pid_t pid)
{
        struct pid_entry * entry;

        pthread_mutex_lock(&reg.mtx);

        if (__reg_get_spawned(pid) != NULL) {
                log_err("Spawned process %d already exists.", pid);
                goto fail_proc;
        }

        entry = malloc(sizeof(*entry));
        if (entry == NULL) {
                log_err("Failed to create pid_entry %d.", pid);
                goto fail_proc;
        }

        entry->pid = pid;

        list_add(&entry->next, __reg_after_spawned(pid));

        reg.n_spawned++;

        pthread_mutex_unlock(&reg.mtx);

        return 0;
 fail_proc:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

bool reg_has_spawned(pid_t pid)
{
        bool ret;

        pthread_mutex_lock(&reg.mtx);

        ret = __reg_get_spawned(pid) != NULL;

        pthread_mutex_unlock(&reg.mtx);

        return ret;
}

void reg_kill_all_spawned(int signal)
{
        pthread_mutex_lock(&reg.mtx);

        __reg_kill_all_spawned(signal);

        pthread_mutex_unlock(&reg.mtx);
}

pid_t reg_first_spawned(void)
{
        pid_t pid;

        pthread_mutex_lock(&reg.mtx);

        pid = __reg_first_spawned();

        pthread_mutex_unlock(&reg.mtx);

        return pid;
}

int reg_bind_proc(const char *  name,
                  pid_t         pid)
{
        struct reg_name * n;
        struct reg_proc * p;

        assert(name != NULL);
        assert(pid > 0);

        pthread_mutex_lock(&reg.mtx);

        n = __reg_get_name(name);
        if (n == NULL) {
                log_err("Could not find name %s.", name);
                goto fail;
        }

        p = __reg_get_proc(pid);
        if (p == NULL) {
                log_err("Could not find process %d.", pid);
                goto fail;
        }

        if (reg_name_has_proc(n, pid)) {
                log_err("Process %d already bound to name %s.", pid, name);
                goto fail;
        }

        if (reg_proc_has_name(p, name)) {
                log_err("Name %s already bound to process %d.", name, pid);
        }

        if (reg_name_add_proc(n, pid) < 0) {
                log_err("Failed to add process %d to name %s.", pid, name);
                goto fail;
        }

        if (reg_proc_add_name(p, name) < 0) {
                log_err("Failed to add name %s to process %d.", name, pid);
                goto fail_proc;
        }

        if (__reg_get_accept_flow(pid) != NULL) {
                if (reg_name_add_active(n, pid) < 0) {
                        log_warn("Failed to update name %s with active %d",
                                 name, pid);
                }
        }

        pthread_mutex_unlock(&reg.mtx);

        return 0;

 fail_proc:
        reg_name_del_proc(n, pid);
 fail:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

int reg_unbind_proc(const char *  name,
                    pid_t         pid)
{
        struct reg_name * n;
        struct reg_proc * p;

        assert(name != NULL);
        assert(pid > 0);

        pthread_mutex_lock(&reg.mtx);

        n = __reg_get_name(name);
        if (n == NULL) {
                log_err("Could not find name %s.", name);
                goto fail;
        }

        p = __reg_get_proc(pid);
        if (p == NULL) {
                log_err("Could not find process %d.", pid);
                goto fail;
        }

        if (!reg_name_has_proc(n, pid)) {
                log_err("Process %d not bound to name %s.", pid, name);
                goto fail;
        }

        if (!reg_proc_has_name(p, name)) {
                log_err("Name %s not bound to process %d.", name, pid);
                goto fail;
        }

        reg_name_del_proc(n, pid);

        reg_proc_del_name(p, name);

        pthread_mutex_unlock(&reg.mtx);

        return 0;

 fail:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

int reg_create_prog(const struct prog_info * info)
{
        struct reg_prog * prog;

        assert(info != NULL);

        pthread_mutex_lock(&reg.mtx);

        if (__reg_get_prog(info->name) != NULL) {
                log_dbg("Program %s already exists.", info->name);
                goto exists;
        }

        prog = reg_prog_create(info);
        if (prog == NULL) {
                log_err("Failed to create program %s.", info->name);
                goto fail_prog;
        }

        list_add(&prog->next, __reg_after_prog(info->name));

        reg.n_progs++;
 exists:
        pthread_mutex_unlock(&reg.mtx);

        return 0;

 fail_prog:
        pthread_mutex_unlock(&reg.mtx);
        return -1;

}

int  reg_destroy_prog(const char * name)
{
        struct reg_prog * prog;

        pthread_mutex_lock(&reg.mtx);

        prog = __reg_get_prog(name);
        if (prog == NULL) {
                log_err("Program %s does not exist.", name);
                goto no_prog;
        }

         log_err("Removing %s from names.", prog->info.path);

        __reg_del_prog_from_names(prog->info.path);

        list_del(&prog->next);

        reg.n_progs--;

        pthread_mutex_unlock(&reg.mtx);

        reg_prog_destroy(prog);

        return 0;

 no_prog:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

bool reg_has_prog(const char * name)
{
        bool ret;

        assert(name != NULL);

        pthread_mutex_lock(&reg.mtx);

        ret = __reg_get_prog(name) != NULL;

        pthread_mutex_unlock(&reg.mtx);

        return ret;
}

int reg_get_exec(const char * name,
                 char ***     prog)
{
        char ** exec;
        int     ret = 0;

        assert(name != NULL);
        assert(prog != NULL);

        pthread_mutex_lock(&reg.mtx);

        exec = __reg_get_exec(name);
        if (exec == NULL) {
                ret = -EPERM;
                goto finish;
        }

        *prog = argvdup(exec);
        if (*prog == NULL) {
                log_err("Failed to argvdup exec.");
                ret = -ENOMEM;
                goto finish;
        }

 finish:
        pthread_mutex_unlock(&reg.mtx);

        return ret;
}

int reg_bind_prog(const char * name,
                  char **      exec,
                  uint8_t      flags)
{
        struct reg_name * n;
        struct reg_prog * p;

        assert(name != NULL);
        assert(exec != NULL);
        assert(exec[0] != NULL);

        pthread_mutex_lock(&reg.mtx);

        n = __reg_get_name(name);
        if (n == NULL) {
                log_err("Could not find name %s.", name);
                goto fail;
        }

        p = __reg_get_prog(path_strip(exec[0]));
        if (p == NULL) {
                log_err("Could not find program %s.", exec[0]);
                goto fail;
        }

        if (reg_name_has_prog(n, exec[0])) {
                log_err("Program %s already bound to %s.", exec[0], name);
                goto fail;
        }

        if (reg_prog_has_name(p, name)) {
                log_err("Name %s already bound to program %s.", name, exec[0]);
                goto fail;
        }


        if (flags & BIND_AUTO && reg_name_add_prog(n, exec) < 0) {
                log_err("Failed to set autostart %s for %s.", exec[0], name);
                goto fail;
        }

        if (reg_prog_add_name(p, name) < 0) {
                log_err("Failed to add %s to program %s.", name, exec[0]);
                goto fail_prog;
        }

        pthread_mutex_unlock(&reg.mtx);

        return 0;

 fail_prog:
        reg_name_del_prog(n, exec[0]);
 fail:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

int reg_unbind_prog(const char * name,
                    const char * prog)
{
        struct reg_name * n;
        struct reg_prog * p;

        assert(name != NULL);
        assert(prog != NULL);

        pthread_mutex_lock(&reg.mtx);

        n = __reg_get_name(name);
        if (n == NULL) {
                log_err("Could not find name %s.", name);
                goto fail;
        }

        p = __reg_get_prog(prog);
        if (p == NULL) {
                log_err("Could not find program %s.", prog);
                goto fail;
        }

        if (!reg_prog_has_name(p, name)) {
                log_err("Name %s not bound to program %s.", name, prog);
                goto fail;
        }

        reg_name_del_prog(n, prog);

        reg_prog_del_name(p, name);

        pthread_mutex_unlock(&reg.mtx);

        return 0;

 fail:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

int reg_set_layer_for_ipcp(struct ipcp_info *        info,
                           const struct layer_info * layer)
{
        struct reg_ipcp * ipcp;

        assert(info != NULL);
        assert(info->state == IPCP_BOOT);

        pthread_mutex_lock(&reg.mtx);

        ipcp = __reg_get_ipcp(info->pid);
        if (ipcp == NULL) {
                log_err("IPCP %d not found.", info->pid);
                goto fail_ipcp;
        }

        reg_ipcp_set_layer(ipcp, layer);

        ipcp->info.state = info->state;

        pthread_mutex_unlock(&reg.mtx);

        return 0;
 fail_ipcp:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

int reg_get_ipcp(struct ipcp_info *  info,
                 struct layer_info * layer)
{
        struct reg_ipcp * ipcp;

        assert(info != NULL);

        pthread_mutex_lock(&reg.mtx);

        ipcp = __reg_get_ipcp(info->pid);
        if (ipcp == NULL) {
                log_err("IPCP %d not found.", info->pid);
                goto fail_ipcp;
        }

        *info  = ipcp->info;
        if (layer != NULL)
                *layer = ipcp->layer;

        pthread_mutex_unlock(&reg.mtx);

        return 0;
 fail_ipcp:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

int reg_get_ipcp_by_layer(struct ipcp_info *  info,
                          struct layer_info * layer)
{
        struct reg_ipcp * ipcp;

        assert(info != NULL);
        assert(layer != NULL);

        pthread_mutex_lock(&reg.mtx);

        ipcp = __reg_get_ipcp_by_layer(layer->name);
        if (ipcp == NULL) {
                log_err("No IPCP for %s not found.", layer->name);
                goto fail_ipcp;
        }

        *info  = ipcp->info;
        *layer = ipcp->layer;

        pthread_mutex_unlock(&reg.mtx);

        return 0;
 fail_ipcp:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

int reg_prepare_flow_alloc(struct flow_info * info)
{
        struct reg_flow * flow;
        int               ret;

        assert(info != NULL);

        pthread_mutex_lock(&reg.mtx);

        flow = __reg_get_flow(info->id);

        assert(flow != NULL);
        assert(flow->info.state == FLOW_INIT);

        info->state = FLOW_ALLOC_PENDING;

        ret = reg_flow_update(flow, info);

        pthread_mutex_unlock(&reg.mtx);

        return ret;
}

int reg_wait_flow_allocated(struct flow_info *      info,
                            buffer_t *              pbuf,
                            const struct timespec * abstime)
{
        struct reg_flow * flow;
        int               ret  = -1;
        bool              stop = false;

        assert(info != NULL);
        assert(info->id >= ID_OFFT);

        pthread_mutex_lock(&reg.mtx);

        flow = __reg_get_flow(info->id);

        assert(flow != NULL);
        assert(info->id == flow->info.id);
        assert(info->n_pid == flow->info.n_pid);

        assert(info->state == FLOW_ALLOC_PENDING);

        pthread_cleanup_push(__cleanup_mutex_unlock, &reg.mtx);

        while (!stop) {
                switch(flow->info.state) {
                case FLOW_ALLOC_PENDING:
                        ret = -__timedwait(&reg.cond, &reg.mtx, abstime);
                        break;
                case FLOW_ALLOCATED:
                        ret  = 0;
                        stop = true;
                        break;
                case FLOW_DEALLOCATED:
                        ret  = flow->response;
                        stop = true;
                        break;
                default:
                        assert(false);
                }

                flow = __reg_get_flow(flow->info.id);
                if (flow == NULL) {
                        info->state = FLOW_DEALLOCATED;
                        ret = -1;
                        break;
                }

                if (ret == -ETIMEDOUT) {
                        info->state = FLOW_DEALLOCATED;
                        reg_flow_update(flow, info);
                        break;
                }
        }

        if (flow != NULL) {
                reg_flow_get_data(flow, pbuf);
                *info = flow->info;
        }

        pthread_cleanup_pop(true); /* __cleanup_mutex_unlock */

        return ret;
}

int reg_respond_alloc(struct flow_info * info,
                      buffer_t *         pbuf,
                      int                response)
{
        struct reg_flow * flow;

        assert(info != NULL);
        assert(info->state == FLOW_ALLOCATED ||
               info->state == FLOW_DEALLOCATED);
        assert(pbuf != NULL);
        assert(!(info->state == FLOW_DEALLOCATED && pbuf->data != NULL));

        pthread_mutex_lock(&reg.mtx);

        flow = __reg_get_flow(info->id);
        if (flow == NULL) {
                log_warn("Flow %d already destroyed.", info->id);
                goto fail_flow;
        }

        if (flow->info.state == FLOW_DEALLOCATED) {
                log_warn("Flow %d already deallocated.", info->id);
                goto fail_flow;
        }

        assert(flow->info.state == FLOW_ALLOC_PENDING);
        assert(flow->data.len == 0);
        assert(flow->data.data == NULL);

        info->n_pid   = flow->info.n_pid;
        info->n_1_pid = flow->info.n_pid;

        if (reg_flow_update(flow, info) < 0) {
                log_err("Failed to create flow structs.");
                goto fail_flow;
        }

        flow->response = response;

        if (info->state == FLOW_ALLOCATED)
                reg_flow_set_data(flow, pbuf);

        pthread_cond_broadcast(&reg.cond);

        pthread_mutex_unlock(&reg.mtx);

        return 0;

 fail_flow:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

int reg_prepare_flow_accept(struct flow_info * info)
{
        struct reg_flow * flow;
        int               ret;

        assert(info != NULL);

        pthread_mutex_lock(&reg.mtx);

        flow = __reg_get_flow(info->id);

        assert(flow != NULL);
        assert(info->n_pid != 0);

        info->state = FLOW_ACCEPT_PENDING;

        ret = reg_flow_update(flow, info);

        pthread_cond_broadcast(&reg.cond);

        pthread_mutex_unlock(&reg.mtx);

        return ret;
}

void __cleanup_wait_accept(void * o)
{
        struct reg_flow * flow;

        flow = (struct reg_flow *) o;

        __reg_del_active_proc(flow->info.n_pid);
}

int reg_wait_flow_accepted(struct flow_info *      info,
                           buffer_t *              pbuf,
                           const struct timespec * abstime)
{
        struct reg_flow * flow;
        int               ret  = -1;
        bool              stop = false;

        assert(info != NULL);
        assert(info->id >= ID_OFFT);

        pthread_mutex_lock(&reg.mtx);

        flow = __reg_get_flow(info->id);

        assert(flow != NULL);
        assert(info->id == flow->info.id);
        assert(info->n_pid == flow->info.n_pid);

        if (__reg_add_active_proc(info->n_pid) < 0) {
                log_err("Failed to mark pid %d active.", info->n_pid);
                goto fail;
        }

        pthread_cond_broadcast(&reg.cond);

        pthread_cleanup_push(__cleanup_mutex_unlock, &reg.mtx);
        pthread_cleanup_push(__cleanup_wait_accept, flow);

        while (!stop) {
                switch(flow->info.state) {
                case FLOW_ACCEPT_PENDING:
                        ret = -__timedwait(&reg.cond, &reg.mtx, abstime);
                        break;
                case FLOW_ALLOCATED:
                        ret  = 0;
                        stop = true;
                        break;
                case FLOW_DEALLOCATED:
                        ret = -1;
                        stop = true;
                        break;
                default:
                        assert(false);
                }

                flow = __reg_get_flow(flow->info.id);
                if (flow == NULL) {
                        info->state = FLOW_DEALLOCATED;
                        ret = -1;
                        break;
                }

                if (ret == -ETIMEDOUT) {
                        info->state = FLOW_DEALLOCATED;
                        reg_flow_update(flow, info);
                        break;
                }
        }

        pthread_cleanup_pop(true); /* __cleanup_wait_accept */

        if (flow != NULL) {
                reg_flow_get_data(flow, pbuf);
                *info = flow->info;
        }

        pthread_cleanup_pop(true); /* __cleanup_mutex_unlock */

        return ret;
 fail:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

int reg_wait_flow_accepting(const char *            name,
                            const struct timespec * abstime)
{
        int ret;

        assert(name != NULL);
        assert(abstime != NULL);

        pthread_mutex_lock(&reg.mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, &reg.mtx);

        while (true) {
                ret = __reg_get_pending_flow_id(name);
                if (ret != -EAGAIN)
                        break;

                ret = -__timedwait(&reg.cond, &reg.mtx, abstime);
                if (ret == -ETIMEDOUT)
                        break;
        }

        pthread_cleanup_pop(true);

        return ret;
}

int reg_respond_accept(struct flow_info * info,
                       buffer_t *         pbuf)
{
        struct reg_flow * flow;

        assert(info != NULL);
        assert(info->state == FLOW_ALLOCATED);
        assert(pbuf != NULL);

        pthread_mutex_lock(&reg.mtx);

        flow = __reg_get_flow(info->id);
        if (flow == NULL) {
                log_err("Flow not found for request: %d", info->id);
                goto fail_flow;
        }

        assert(flow->info.state == FLOW_ACCEPT_PENDING);

        info->n_pid = flow->info.n_pid;

        reg_flow_set_data(flow, pbuf);
        clrbuf(pbuf);

        if (reg_flow_update(flow, info) < 0) {
                log_err("Failed to create flow structs.");
                goto fail_flow;
        }

        pthread_cond_broadcast(&reg.cond);

        pthread_mutex_unlock(&reg.mtx);

        return 0;

 fail_flow:
        pthread_mutex_unlock(&reg.mtx);
        return -1;
}

void reg_dealloc_flow(struct flow_info * info)
{
        struct reg_flow * flow;

        assert(info != NULL);
        assert(info->id != 0);
        assert(info->n_pid != 0);

        pthread_mutex_lock(&reg.mtx);

        flow = __reg_get_flow(info->id);

        assert(flow != NULL);
        assert(flow->data.data == NULL);
        assert(flow->data.len == 0);
        assert(flow->info.state == FLOW_ALLOCATED);

        flow->info.state = FLOW_DEALLOC_PENDING;
        info->state = FLOW_DEALLOC_PENDING;
        info->n_1_pid = flow->info.n_1_pid;

        memset(flow->name, 0, sizeof(flow->name));

        reg_flow_update(flow, info);

        pthread_mutex_unlock(&reg.mtx);
}

void reg_dealloc_flow_resp(struct flow_info * info)
{
        struct reg_flow * flow;

        assert(info != NULL);
        assert(info->id != 0);
        assert(info->n_1_pid != 0);

        pthread_mutex_lock(&reg.mtx);

        flow = __reg_get_flow(info->id);

        assert(flow != NULL);
        assert(flow->data.data == NULL);
        assert(flow->data.len == 0);

        assert(flow->info.state == FLOW_DEALLOC_PENDING);
        flow->info.state = FLOW_DEALLOCATED;
        info->state = FLOW_DEALLOCATED;

        reg_flow_update(flow, info);

        pthread_mutex_unlock(&reg.mtx);
}

int reg_wait_proc(pid_t                   pid,
                  const struct timespec * abstime)
{
        struct reg_proc * proc = NULL;
        int               ret;

        assert(pid > 0);
        assert(abstime != NULL);

        pthread_mutex_lock(&reg.mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, &reg.mtx);

        while (true) {
                proc = __reg_get_proc(pid);
                if (proc != NULL) {
                        ret = 0;
                        break;
                }

                ret = -__timedwait(&reg.cond, &reg.mtx, abstime);
                if (ret == -ETIMEDOUT)
                        break;
        }

        pthread_cleanup_pop(true);

        return ret;
}

int reg_wait_ipcp_boot(struct ipcp_info *      info,
                       const struct timespec * abstime)
{
        struct reg_ipcp * ipcp;
        int               ret;
        bool              stop = false;

        assert(info->state == IPCP_INIT);

        pthread_mutex_lock(&reg.mtx);

        ipcp = __reg_get_ipcp(info->pid);

        if (ipcp->info.state == IPCP_INIT)
                reg_ipcp_update(ipcp, info);

        pthread_cleanup_push(__cleanup_mutex_unlock, &reg.mtx);

        while (!stop) {
                if (ipcp == NULL)
                        break;

                switch(ipcp->info.state) {
                case IPCP_NULL:
                        ret = -1;
                        stop = true;
                        break;
                case IPCP_BOOT:
                        /* FALLTHRU*/
                case IPCP_OPERATIONAL:
                        ret  = 0;
                        stop = true;
                        break;
                case IPCP_INIT:
                        ret = -__timedwait(&reg.cond, &reg.mtx, abstime);
                        break;
                default:
                        assert(false);
                        break; /* Shut up static analyzer. */
                }

                ipcp = __reg_get_ipcp(info->pid);

                if (ret == -ETIMEDOUT)
                        break;
        }

        if (ipcp != NULL)
               *info = ipcp->info;

        pthread_cleanup_pop(true);

        return ipcp == NULL? -EIPCP : ret;
}

int reg_respond_ipcp(const struct ipcp_info * info)
{
        struct reg_ipcp * ipcp;

        assert(info != NULL);

        pthread_mutex_lock(&reg.mtx);

        ipcp = __reg_get_ipcp(info->pid);
        if (ipcp == NULL) {
                log_err("IPCP %d not found for response.", info->pid);
                goto fail_ipcp;
        }

        assert(strcmp(info->name, ipcp->info.name) == 0);
        assert(info->type == ipcp->info.type);

        reg_ipcp_update(ipcp, info);

        pthread_cond_broadcast(&reg.cond);

        pthread_mutex_unlock(&reg.mtx);

        return 0;

 fail_ipcp:
        pthread_mutex_unlock(&reg.mtx);
        return -EIPCP;
}
