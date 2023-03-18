/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * The IPC Resource Manager - Registry - Processes
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
#define _POSIX_C_SOURCE 200112L
#endif

#include "config.h"

#include <ouroboros/list.h>
#include <ouroboros/errno.h>
#include <ouroboros/time_utils.h>

#include "proc.h"
#include "name.h"

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

struct reg_proc * reg_proc_create(pid_t        pid,
                                  const char * prog)
{
        struct reg_proc *  proc;
        pthread_condattr_t cattr;

        assert(prog);

        proc = malloc(sizeof(*proc));
        if (proc == NULL)
                goto fail_malloc;

        if (pthread_condattr_init(&cattr))
                goto fail_condattr;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif

        if (pthread_mutex_init(&proc->lock, NULL))
                goto fail_mutex;

        if (pthread_cond_init(&proc->cond, &cattr))
                goto fail_cond;

        proc->set = shm_flow_set_create(pid);
        if (proc->set == NULL)
                goto fail_set;

        proc->prog = strdup(prog);
        if(proc->prog == NULL)
                goto fail_prog;

        list_head_init(&proc->next);
        list_head_init(&proc->names);

        proc->pid      = pid;
        proc->name     = NULL;
        proc->state    = PROC_INIT;

        return proc;

 fail_prog:
        shm_flow_set_destroy(proc->set);
 fail_set:
        pthread_cond_destroy(&proc->cond);;
 fail_cond:
        pthread_mutex_destroy(&proc->lock);
 fail_mutex:
        pthread_condattr_destroy(&cattr);
 fail_condattr:
        free(proc);
 fail_malloc:
        return NULL;
}

static void cancel_reg_proc(void * o)
{
        struct reg_proc * proc = (struct reg_proc *) o;

        proc->state = PROC_NULL;

        pthread_mutex_unlock(&proc->lock);
}

void reg_proc_destroy(struct reg_proc * proc)
{
        struct list_head * p;
        struct list_head * h;

        assert(proc);

        pthread_mutex_lock(&proc->lock);

        if (proc->state == PROC_DESTROY) {
                pthread_mutex_unlock(&proc->lock);
                return;
        }

        if (proc->state == PROC_SLEEP)
                proc->state = PROC_DESTROY;

        pthread_cond_signal(&proc->cond);

        pthread_cleanup_push(cancel_reg_proc, proc);

        while (proc->state != PROC_INIT)
                pthread_cond_wait(&proc->cond, &proc->lock);

        pthread_cleanup_pop(false);

        pthread_mutex_unlock(&proc->lock);

        shm_flow_set_destroy(proc->set);

        pthread_cond_destroy(&proc->cond);
        pthread_mutex_destroy(&proc->lock);

        list_for_each_safe(p, h, &proc->names) {
                struct str_el * n = list_entry(p, struct str_el, next);
                list_del(&n->next);
                if (n->str != NULL)
                        free(n->str);
                free(n);
        }

        free(proc->prog);
        free(proc);
}

int reg_proc_add_name(struct reg_proc * proc,
                      const char *      name)
{
        struct str_el * s;

        assert(proc);
        assert(name);

        s = malloc(sizeof(*s));
        if (s == NULL)
                goto fail_malloc;

        s->str = strdup(name);
        if (s->str == NULL)
                goto fail_name;

        list_add(&s->next, &proc->names);

        return 0;

 fail_name:
        free(s);
 fail_malloc:
        return -ENOMEM;
}

void reg_proc_del_name(struct reg_proc * proc,
                       const char *      name)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        assert(proc);
        assert(name);

        list_for_each_safe(p, h, &proc->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                if (!strcmp(name, s->str)) {
                        list_del(&s->next);
                        free(s->str);
                        free(s);
                }
        }
}

int reg_proc_sleep(struct reg_proc * proc,
                   struct timespec * dl)
{

        int ret = 0;

        assert(proc);

        pthread_mutex_lock(&proc->lock);

        if (proc->state != PROC_WAKE && proc->state != PROC_DESTROY)
                proc->state = PROC_SLEEP;

        pthread_cleanup_push(cancel_reg_proc, proc);

        while (proc->state == PROC_SLEEP && ret != -ETIMEDOUT)
                if (dl != NULL)
                        ret = -pthread_cond_timedwait(&proc->cond,
                                                      &proc->lock, dl);
                else
                        ret = -pthread_cond_wait(&proc->cond, &proc->lock);

        pthread_cleanup_pop(false);

        if (proc->state == PROC_DESTROY) {
                if (proc->name != NULL)
                        reg_name_del_pid(proc->name, proc->pid);
                ret = -1;
        }

        proc->state = PROC_INIT;

        pthread_cond_broadcast(&proc->cond);
        pthread_mutex_unlock(&proc->lock);

        return ret;
}

void reg_proc_wake(struct reg_proc * proc,
                   struct reg_name * name)
{
        assert(proc);
        assert(name);

        pthread_mutex_lock(&proc->lock);

        if (proc->state != PROC_SLEEP) {
                pthread_mutex_unlock(&proc->lock);
                return;
        }

        proc->state = PROC_WAKE;
        proc->name  = name;

        pthread_cond_broadcast(&proc->cond);

        pthread_cleanup_push(cancel_reg_proc, proc);

        while (proc->state == PROC_WAKE)
                pthread_cond_wait(&proc->cond, &proc->lock);

        pthread_cleanup_pop(false);

        if (proc->state == PROC_DESTROY)
                proc->state = PROC_INIT;

        pthread_mutex_unlock(&proc->lock);
}
