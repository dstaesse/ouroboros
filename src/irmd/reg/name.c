/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * The IPC Resource Manager - Registry - Names
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

#define OUROBOROS_PREFIX "reg_name"

#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/pthread.h>

#include "name.h"
#include "utils.h"

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

struct reg_name * reg_name_create(const char *     name,
                                  enum pol_balance lb)
{
        pthread_condattr_t cattr;
        struct reg_name *  n;

        assert(name != NULL);

        n = malloc(sizeof(*n));
        if (n == NULL)
                goto fail_malloc;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&n->cond, &cattr))
                goto fail_cond;

        if (pthread_mutex_init(&n->mtx, NULL))
                goto fail_mutex;

        n->name = strdup(name);
        if (n->name == NULL)
                goto fail_name;

        pthread_condattr_destroy(&cattr);

        list_head_init(&n->next);
        list_head_init(&n->reg_progs);
        list_head_init(&n->reg_pids);

        n->pol_lb = lb;
        n->state = NAME_IDLE;

        return n;

 fail_name:
        pthread_mutex_destroy(&n->mtx);
 fail_mutex:
        pthread_cond_destroy(&n->cond);
 fail_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        free(n);
 fail_malloc:
        return NULL;
}

static void cancel_reg_name_destroy(void * o)
{
        struct reg_name * name;
        struct list_head * p;
        struct list_head * h;

        name = (struct reg_name *) o;

        pthread_mutex_unlock(&name->mtx);

        pthread_cond_destroy(&name->cond);
        pthread_mutex_destroy(&name->mtx);

        if (name->name != NULL)
                free(name->name);

        list_for_each_safe(p, h, &name->reg_pids) {
                struct pid_el * pe = list_entry(p, struct pid_el, next);
                list_del(&pe->next);
                free(pe);
        }

        list_for_each_safe(p, h, &name->reg_progs) {
                struct str_el * se = list_entry(p, struct str_el, next);
                list_del(&se->next);
                free(se->str);
                free(se);
        }

        free(name);
}

void reg_name_destroy(struct reg_name * name)
{
        if (name == NULL)
                return;

        pthread_mutex_lock(&name->mtx);

        if (name->state == NAME_DESTROY) {
                pthread_mutex_unlock(&name->mtx);
                return;
        }

        if (name->state != NAME_FLOW_ACCEPT)
                name->state = NAME_NULL;
        else
                name->state = NAME_DESTROY;

        pthread_cond_broadcast(&name->cond);

        pthread_cleanup_push(cancel_reg_name_destroy, name);

        while (name->state != NAME_NULL)
                pthread_cond_wait(&name->cond, &name->mtx);

        pthread_cleanup_pop(true);
}

static bool reg_name_has_prog(struct reg_name * name,
                              const char *      prog)
{
        struct list_head * p;

        list_for_each(p, &name->reg_progs) {
                struct str_el * name = list_entry(p, struct str_el, next);
                if (!strcmp(name->str, prog))
                        return true;
        }

        return false;
}

int reg_name_add_prog(struct reg_name * name,
                      struct reg_prog * a)
{
        struct str_el * n;

        if (reg_name_has_prog(name, a->prog)) {
                log_warn("Program %s already accepting flows for %s.",
                         a->prog, name->name);
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

        list_add(&n->next, &name->reg_progs);

        pthread_mutex_lock(&name->mtx);

        if (name->state == NAME_IDLE)
                name->state = NAME_AUTO_ACCEPT;

        pthread_mutex_unlock(&name->mtx);

        return 0;
}

void reg_name_del_prog(struct reg_name * name,
                       const char *      prog)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &name->reg_progs) {
                struct str_el * se = list_entry(p, struct str_el, next);
                if (strcmp(prog, se->str) == 0) {
                        list_del(&se->next);
                        free(se->str);
                        free(se);
                }
        }

        pthread_mutex_lock(&name->mtx);

        if (name->state == NAME_AUTO_ACCEPT && list_is_empty(&name->reg_progs)) {
                name->state = NAME_IDLE;
                pthread_cond_broadcast(&name->cond);
        }

        pthread_mutex_unlock(&name->mtx);
}

char * reg_name_get_prog(struct reg_name * name)
{
        if (!list_is_empty(&name->reg_pids) || list_is_empty(&name->reg_progs))
                return NULL;

        return list_first_entry(&name->reg_progs, struct str_el, next)->str;
}

static bool reg_name_has_pid(struct reg_name * name,
                             pid_t             pid)
{
        struct list_head * p;

        list_for_each(p, &name->reg_progs) {
                struct pid_el * name = list_entry(p, struct pid_el, next);
                if (name->pid == pid)
                        return true;
        }

        return false;
}

int reg_name_add_pid(struct reg_name * name,
                     pid_t             pid)
{
        struct pid_el * i;

        assert(name);

        if (reg_name_has_pid(name, pid)) {
                log_dbg("Process already registered with this name.");
                return -EPERM;
        }

        pthread_mutex_lock(&name->mtx);

        if (name->state == NAME_NULL) {
                pthread_mutex_unlock(&name->mtx);
                log_dbg("Tried to add instance in NULL state.");
                return -EPERM;
        }

        i = malloc(sizeof(*i));
        if (i == NULL) {
                pthread_mutex_unlock(&name->mtx);
                return -ENOMEM;
        }

        i->pid = pid;

        /* load balancing policy assigns queue order for this process. */
        switch(name->pol_lb) {
        case LB_RR:    /* Round robin policy. */
                list_add_tail(&i->next, &name->reg_pids);
                break;
        case LB_SPILL: /* Keep accepting flows on the current process */
                list_add(&i->next, &name->reg_pids);
                break;
        default:
                free(i);
                assert(false);
        };

        if (name->state == NAME_IDLE ||
            name->state == NAME_AUTO_ACCEPT ||
            name->state == NAME_AUTO_EXEC) {
                name->state = NAME_FLOW_ACCEPT;
                pthread_cond_broadcast(&name->cond);
        }

        pthread_mutex_unlock(&name->mtx);

        return 0;
}

void reg_name_set_policy(struct reg_name * name,
                         enum pol_balance  lb)
{
        name->pol_lb = lb;
}

static void reg_name_check_state(struct reg_name * name)
{
        assert(name);

        if (name->state == NAME_DESTROY) {
                name->state = NAME_NULL;
                pthread_cond_broadcast(&name->cond);
                return;
        }

        if (list_is_empty(&name->reg_pids)) {
                if (!list_is_empty(&name->reg_progs))
                        name->state = NAME_AUTO_ACCEPT;
                else
                        name->state = NAME_IDLE;
        } else {
                name->state = NAME_FLOW_ACCEPT;
        }

        pthread_cond_broadcast(&name->cond);
}

void reg_name_del_pid_el(struct reg_name * name,
                         struct pid_el *   p)
{
        assert(name);
        assert(p);

        list_del(&p->next);
        free(p);

        reg_name_check_state(name);
}

void reg_name_del_pid(struct reg_name * name,
                      pid_t             pid)
{
        struct list_head * p;
        struct list_head * h;

        assert(name);

        if (name == NULL)
                return;

        list_for_each_safe(p, h, &name->reg_pids) {
                struct pid_el * a = list_entry(p, struct pid_el, next);
                if (a->pid == pid) {
                        list_del(&a->next);
                        free(a);
                }
        }

        reg_name_check_state(name);
}

pid_t reg_name_get_pid(struct reg_name * name)
{
        if (name == NULL)
                return -1;

        if (list_is_empty(&name->reg_pids))
                return -1;

        return list_first_entry(&name->reg_pids, struct pid_el, next)->pid;
}

enum name_state reg_name_get_state(struct reg_name * name)
{
        enum name_state state;

        assert(name);

        pthread_mutex_lock(&name->mtx);

        state = name->state;

        pthread_mutex_unlock(&name->mtx);

        return state;
}

int reg_name_set_state(struct reg_name * name,
                       enum name_state   state)
{
        assert(state != NAME_DESTROY);

        pthread_mutex_lock(&name->mtx);

        name->state = state;
        pthread_cond_broadcast(&name->cond);

        pthread_mutex_unlock(&name->mtx);

        return 0;
}

int reg_name_leave_state(struct reg_name * name,
                         enum name_state   state,
                         struct timespec * timeout)
{
        struct timespec abstime;
        int ret = 0;

        assert(name);
        assert(state != NAME_DESTROY);

        if (timeout != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

        pthread_mutex_lock(&name->mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, &name->mtx);

        while (name->state == state && ret != -ETIMEDOUT)
                if (timeout)
                        ret = -pthread_cond_timedwait(&name->cond,
                                                      &name->mtx,
                                                      &abstime);
                else
                        ret = -pthread_cond_wait(&name->cond,
                                                 &name->mtx);

        if (name->state == NAME_DESTROY) {
                ret = -1;
                name->state = NAME_NULL;
                pthread_cond_broadcast(&name->cond);
        }

        pthread_cleanup_pop(true);

        return ret;
}
