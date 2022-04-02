/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * The IPC Resource Manager - Registry
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

#define OUROBOROS_PREFIX "registry"

#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/pthread.h>

#include "registry.h"
#include "utils.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

static struct reg_entry * reg_entry_create(void)
{
        struct reg_entry * e;

        e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        e->name         = NULL;
        e->state        = REG_NAME_NULL;

        return e;
}

static int reg_entry_init(struct reg_entry * e,
                          char *             name)
{
        pthread_condattr_t cattr;

        assert(e);
        assert(name);

        list_head_init(&e->next);
        list_head_init(&e->reg_progs);
        list_head_init(&e->reg_pids);

        e->name   = name;
        e->pol_lb = 0;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&e->state_cond, &cattr))
                goto fail_cond;

        if (pthread_mutex_init(&e->state_lock, NULL))
                goto fail_mutex;

        pthread_condattr_destroy(&cattr);

        e->state = REG_NAME_IDLE;

        return 0;

 fail_mutex:
        pthread_cond_destroy(&e->state_cond);
 fail_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        return -1;
}

static void cancel_reg_entry_destroy(void * o)
{
        struct reg_entry * e;
        struct list_head * p;
        struct list_head * h;

        e = (struct reg_entry *) o;

        pthread_mutex_unlock(&e->state_lock);

        pthread_cond_destroy(&e->state_cond);
        pthread_mutex_destroy(&e->state_lock);

        if (e->name != NULL)
                free(e->name);

        list_for_each_safe(p, h, &e->reg_pids) {
                struct pid_el * pe = list_entry(p, struct pid_el, next);
                list_del(&pe->next);
                free(pe);
        }

        list_for_each_safe(p, h, &e->reg_progs) {
                struct str_el * a = list_entry(p, struct str_el, next);
                list_del(&a->next);
                free(a->str);
                free(a);
        }

        free(e);
}

static void reg_entry_destroy(struct reg_entry * e)
{
        if (e == NULL)
                return;

        pthread_mutex_lock(&e->state_lock);

        if (e->state == REG_NAME_DESTROY) {
                pthread_mutex_unlock(&e->state_lock);
                return;
        }

        if (e->state != REG_NAME_FLOW_ACCEPT)
                e->state = REG_NAME_NULL;
        else
                e->state = REG_NAME_DESTROY;

        pthread_cond_broadcast(&e->state_cond);

        pthread_cleanup_push(cancel_reg_entry_destroy, e);

        while (e->state != REG_NAME_NULL)
                pthread_cond_wait(&e->state_cond, &e->state_lock);

        pthread_cleanup_pop(true);
}

static bool reg_entry_has_prog(struct reg_entry * e,
                               const char *       prog)
{
        struct list_head * p;

        list_for_each(p, &e->reg_progs) {
                struct str_el * e = list_entry(p, struct str_el, next);
                if (!strcmp(e->str, prog))
                        return true;
        }

        return false;
}

int reg_entry_add_prog(struct reg_entry *  e,
                       struct prog_entry * a)
{
        struct str_el * n;

        if (reg_entry_has_prog(e, a->prog)) {
                log_warn("Program %s already accepting flows for %s.",
                         a->prog, e->name);
                return 0;
        }

        if (!(a->flags & BIND_AUTO)) {
                log_dbg("Program %s cannot be auto-instantiated.", a->prog);
                return 0;
        }

        n = malloc(sizeof(*n));
        if (n == NULL)
                return -ENOMEM;

        n->str = strdup(a->prog);
        if (n->str == NULL) {
                free(n);
                return -ENOMEM;
        }

        list_add(&n->next, &e->reg_progs);

        pthread_mutex_lock(&e->state_lock);

        if (e->state == REG_NAME_IDLE)
                e->state = REG_NAME_AUTO_ACCEPT;

        pthread_mutex_unlock(&e->state_lock);

        return 0;
}

void reg_entry_del_prog(struct reg_entry * e,
                        const char *       prog)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &e->reg_progs) {
                struct str_el * e = list_entry(p, struct str_el, next);
                if (!strcmp(prog, e->str)) {
                        list_del(&e->next);
                        free(e->str);
                        free(e);
                }
        }

        pthread_mutex_lock(&e->state_lock);

        if (e->state == REG_NAME_AUTO_ACCEPT && list_is_empty(&e->reg_progs)) {
                e->state = REG_NAME_IDLE;
                pthread_cond_broadcast(&e->state_cond);
        }

        pthread_mutex_unlock(&e->state_lock);
}

char * reg_entry_get_prog(struct reg_entry * e)
{
        if (!list_is_empty(&e->reg_pids) || list_is_empty(&e->reg_progs))
                return NULL;

        return list_first_entry(&e->reg_progs, struct str_el, next)->str;
}

static bool reg_entry_has_pid(struct reg_entry * e,
                              pid_t              pid)
{
        struct list_head * p;

        list_for_each(p, &e->reg_progs) {
                struct pid_el * e = list_entry(p, struct pid_el, next);
                if (e->pid == pid)
                        return true;
        }

        return false;
}

int reg_entry_add_pid(struct reg_entry * e,
                      pid_t              pid)
{
        struct pid_el * i;

        assert(e);

        if (reg_entry_has_pid(e, pid)) {
                log_dbg("Process already registered with this name.");
                return -EPERM;
        }

        pthread_mutex_lock(&e->state_lock);

        if (e->state == REG_NAME_NULL) {
                pthread_mutex_unlock(&e->state_lock);
                log_dbg("Tried to add instance in NULL state.");
                return -EPERM;
        }

        i = malloc(sizeof(*i));
        if (i == NULL) {
                pthread_mutex_unlock(&e->state_lock);
                return -ENOMEM;
        }

        i->pid = pid;

        /* load balancing policy assigns queue order for this process. */
        switch(e->pol_lb) {
        case LB_RR:    /* Round robin policy. */
                list_add_tail(&i->next, &e->reg_pids);
                break;
        case LB_SPILL: /* Keep accepting flows on the current process */
                list_add(&i->next, &e->reg_pids);
                break;
        default:
                assert(false);
        };

        if (e->state == REG_NAME_IDLE ||
            e->state == REG_NAME_AUTO_ACCEPT ||
            e->state == REG_NAME_AUTO_EXEC) {
                e->state = REG_NAME_FLOW_ACCEPT;
                pthread_cond_broadcast(&e->state_cond);
        }

        pthread_mutex_unlock(&e->state_lock);

        return 0;
}

void reg_entry_set_policy(struct reg_entry * e,
                          enum pol_balance   p)
{
        e->pol_lb = p;
}


static void reg_entry_check_state(struct reg_entry * e)
{
        assert(e);

        if (e->state == REG_NAME_DESTROY) {
                e->state = REG_NAME_NULL;
                pthread_cond_broadcast(&e->state_cond);
                return;
        }

        if (list_is_empty(&e->reg_pids)) {
                if (!list_is_empty(&e->reg_progs))
                        e->state = REG_NAME_AUTO_ACCEPT;
                else
                        e->state = REG_NAME_IDLE;
        } else {
                e->state = REG_NAME_FLOW_ACCEPT;
        }

        pthread_cond_broadcast(&e->state_cond);
}

void reg_entry_del_pid_el(struct reg_entry * e,
                          struct pid_el *    p)
{
        assert(e);
        assert(p);

        list_del(&p->next);
        free(p);

        reg_entry_check_state(e);
}

void reg_entry_del_pid(struct reg_entry * e,
                       pid_t              pid)
{
        struct list_head * p;
        struct list_head * h;

        assert(e);

        if (e == NULL)
                return;

        list_for_each_safe(p, h, &e->reg_pids) {
                struct pid_el * a = list_entry(p, struct pid_el, next);
                if (a->pid == pid) {
                        list_del(&a->next);
                        free(a);
                }
        }

        reg_entry_check_state(e);
}

pid_t reg_entry_get_pid(struct reg_entry * e)
{
        if (e == NULL)
                return -1;

        if (list_is_empty(&e->reg_pids))
                return -1;

        return list_first_entry(&e->reg_pids, struct pid_el, next)->pid;
}

enum reg_name_state reg_entry_get_state(struct reg_entry * e)
{
        enum reg_name_state state;

        assert(e);

        pthread_mutex_lock(&e->state_lock);

        state = e->state;

        pthread_mutex_unlock(&e->state_lock);

        return state;
}

int reg_entry_set_state(struct reg_entry *  e,
                        enum reg_name_state state)
{
        assert(state != REG_NAME_DESTROY);

        pthread_mutex_lock(&e->state_lock);

        e->state = state;
        pthread_cond_broadcast(&e->state_cond);

        pthread_mutex_unlock(&e->state_lock);

        return 0;
}

int reg_entry_leave_state(struct reg_entry *  e,
                          enum reg_name_state state,
                          struct timespec *   timeout)
{
        struct timespec abstime;
        int ret = 0;

        assert(e);
        assert(state != REG_NAME_DESTROY);

        if (timeout != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

        pthread_mutex_lock(&e->state_lock);

        pthread_cleanup_push(__cleanup_mutex_unlock, &e->state_lock);

        while (e->state == state && ret != -ETIMEDOUT)
                if (timeout)
                        ret = -pthread_cond_timedwait(&e->state_cond,
                                                      &e->state_lock,
                                                      &abstime);
                else
                        ret = -pthread_cond_wait(&e->state_cond,
                                                 &e->state_lock);

        if (e->state == REG_NAME_DESTROY) {
                ret = -1;
                e->state = REG_NAME_NULL;
                pthread_cond_broadcast(&e->state_cond);
        }

        pthread_cleanup_pop(true);

        return ret;
}

int reg_entry_wait_state(struct reg_entry *  e,
                         enum reg_name_state state,
                         struct timespec *   timeout)
{
        struct timespec abstime;
        int ret = 0;

        assert(e);
        assert(state != REG_NAME_DESTROY);

        if (timeout != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

        pthread_mutex_lock(&e->state_lock);

        while (e->state != state &&
               e->state != REG_NAME_DESTROY &&
               ret != -ETIMEDOUT)
                if (timeout)
                        ret = -pthread_cond_timedwait(&e->state_cond,
                                                      &e->state_lock,
                                                      &abstime);
                else
                        ret = -pthread_cond_wait(&e->state_cond,
                                                 &e->state_lock);

        if (e->state == REG_NAME_DESTROY) {
                ret = -1;
                e->state = REG_NAME_NULL;
                pthread_cond_broadcast(&e->state_cond);
        }

        pthread_mutex_unlock(&e->state_lock);

        return ret;
}

struct reg_entry * registry_get_entry(struct list_head * registry,
                                      const char *       name)
{
        struct list_head * p = NULL;

        assert(registry);

        list_for_each(p, registry) {
                struct reg_entry * e = list_entry(p, struct reg_entry, next);
                if (!strcmp(name, e->name))
                        return e;
        }

        return NULL;
}

struct reg_entry * registry_get_entry_by_hash(struct list_head * registry,
                                              enum hash_algo     algo,
                                              const uint8_t *    hash,
                                              size_t             len)
{
        struct list_head * p = NULL;
        uint8_t * thash;

        thash = malloc(len);
        if (thash == NULL)
                return NULL;

        assert(registry);

        list_for_each(p, registry) {
                struct reg_entry * e = list_entry(p, struct reg_entry, next);
                str_hash(algo, thash, e->name);
                if (memcmp(thash, hash, len) == 0) {
                        free(thash);
                        return e;
                }
        }

        free(thash);

        return NULL;
}

struct reg_entry * registry_add_name(struct list_head * registry,
                                     const char *       name)
{
        struct reg_entry * e = NULL;

        assert(registry);
        assert(name);

        if (registry_has_name(registry, name)) {
                log_dbg("Name %s already registered.", name);
                return NULL;
        }

        e = reg_entry_create();
        if (e == NULL) {
                log_dbg("Could not create registry entry.");
                return NULL;
        }

        if (reg_entry_init(e, strdup(name))) {
                reg_entry_destroy(e);
                log_dbg("Could not initialize registry entry.");
                return NULL;
        }

        list_add(&e->next, registry);

        return e;
}

void registry_del_name(struct list_head * registry,
                       const char *       name)
{
        struct reg_entry * e = registry_get_entry(registry, name);
        if (e == NULL)
                return;

        list_del(&e->next);
        reg_entry_destroy(e);

        return;
}

void registry_del_process(struct list_head * registry,
                          pid_t              pid)
{
        struct list_head * p;

        assert(registry);
        assert(pid > 0);

        list_for_each(p, registry) {
                struct reg_entry * e = list_entry(p, struct reg_entry, next);
                pthread_mutex_lock(&e->state_lock);
                assert(e);
                reg_entry_del_pid(e, pid);
                pthread_mutex_unlock(&e->state_lock);
        }

        return;
}

void registry_destroy(struct list_head * registry)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        assert(registry);

        list_for_each_safe(p, h, registry) {
                struct reg_entry * e = list_entry(p, struct reg_entry, next);
                list_del(&e->next);
                reg_entry_set_state(e, REG_NAME_NULL);
                reg_entry_destroy(e);
        }
}
