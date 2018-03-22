/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * The IPC Resource Manager - Process Table
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

#define _POSIX_C_SOURCE 200112L

#include "config.h"

#include <ouroboros/list.h>
#include <ouroboros/errno.h>
#include <ouroboros/time_utils.h>

#include "proc_table.h"
#include "registry.h"

#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <assert.h>

struct proc_entry * proc_entry_create(pid_t  pid,
                                      char * prog)
{
        struct proc_entry * e;
        pthread_condattr_t  cattr;

        assert(prog);

        e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        list_head_init(&e->next);
        list_head_init(&e->names);

        e->pid      = pid;
        e->prog     = prog;
        e->daf_name = NULL;

        e->re       = NULL;

        e->state    = PROC_INIT;

        if (pthread_condattr_init(&cattr)) {
                free(e);
                return NULL;
        }

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif

        if (pthread_mutex_init(&e->lock, NULL)) {
                free(e);
                return NULL;
        }


        if (pthread_cond_init(&e->cond, &cattr)) {
                pthread_mutex_destroy(&e->lock);
                free(e);
                return NULL;
        }

        return e;
}

static void cancel_proc_entry(void * o)
{
        struct proc_entry * e = (struct proc_entry *) o;

        e->state = PROC_NULL;

        pthread_mutex_unlock(&e->lock);
}

void proc_entry_destroy(struct proc_entry * e)
{
        struct list_head * p;
        struct list_head * h;

        assert(e);

        pthread_mutex_lock(&e->lock);

        if (e->state == PROC_DESTROY) {
                pthread_mutex_unlock(&e->lock);
                return;
        }

        if (e->state == PROC_SLEEP)
                e->state = PROC_DESTROY;

        pthread_cond_signal(&e->cond);

        pthread_cleanup_push(cancel_proc_entry, e);

        while (e->state != PROC_INIT)
                pthread_cond_wait(&e->cond, &e->lock);

        pthread_cleanup_pop(false);

        pthread_mutex_unlock(&e->lock);

        pthread_cond_destroy(&e->cond);
        pthread_mutex_destroy(&e->lock);

        if (e->prog != NULL)
                free(e->prog);

        list_for_each_safe(p, h, &e->names) {
                struct str_el * n = list_entry(p, struct str_el, next);
                list_del(&n->next);
                if (n->str != NULL)
                        free(n->str);
                free(n);
        }

        free(e);
}

int proc_entry_add_name(struct proc_entry * e,
                        char *              name)
{
        struct str_el * s;

        assert(e);
        assert(name);

        s = malloc(sizeof(*s));
        if (s == NULL)
                return -ENOMEM;

        s->str = name;
        list_add(&s->next, &e->names);

        return 0;
}

void proc_entry_del_name(struct proc_entry * e,
                         const char *        name)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        assert(e);
        assert(name);

        list_for_each_safe(p, h, &e->names) {
                struct str_el * s = list_entry(p, struct str_el, next);
                if (!strcmp(name, s->str)) {
                        list_del(&s->next);
                        if (s->str != NULL)
                                free(s->str);
                        free(s);
                }
        }
}

int proc_entry_sleep(struct proc_entry * e,
                     struct timespec *   timeo)
{
        struct timespec dl;

        int ret = 0;

        assert(e);

        if (timeo != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &dl);
                ts_add(&dl, timeo, &dl);
        }

        pthread_mutex_lock(&e->lock);

        if (e->state != PROC_WAKE && e->state != PROC_DESTROY)
                e->state = PROC_SLEEP;

        pthread_cleanup_push(cancel_proc_entry, e);

        while (e->state == PROC_SLEEP && ret != -ETIMEDOUT)
                if (timeo)
                        ret = -pthread_cond_timedwait(&e->cond, &e->lock, &dl);
                else
                        ret = -pthread_cond_wait(&e->cond, &e->lock);

        pthread_cleanup_pop(false);

        if (e->state == PROC_DESTROY) {
                if (e->re != NULL)
                        reg_entry_del_pid(e->re, e->pid);
                ret = -1;
        }

        e->state = PROC_INIT;

        pthread_cond_broadcast(&e->cond);
        pthread_mutex_unlock(&e->lock);

        return ret;
}

void proc_entry_wake(struct proc_entry * e,
                     struct reg_entry *  re)
{
        assert(e);
        assert(re);

        pthread_mutex_lock(&e->lock);

        if (e->state != PROC_SLEEP) {
                pthread_mutex_unlock(&e->lock);
                return;
        }

        e->state = PROC_WAKE;
        e->re    = re;

        pthread_cond_broadcast(&e->cond);

        pthread_cleanup_push(cancel_proc_entry, e);

        while (e->state == PROC_WAKE)
                pthread_cond_wait(&e->cond, &e->lock);

        pthread_cleanup_pop(false);

        if (e->state == PROC_DESTROY)
                e->state = PROC_INIT;

        pthread_mutex_unlock(&e->lock);
}

int proc_table_add(struct list_head *  proc_table,
                   struct proc_entry * e)
{

        assert(proc_table);
        assert(e);

        list_add(&e->next, proc_table);

        return 0;
}

void proc_table_del(struct list_head * proc_table,
                    pid_t              pid)
{
        struct list_head * p;
        struct list_head * h;

        assert(proc_table);

        list_for_each_safe(p, h, proc_table) {
                struct proc_entry * e = list_entry(p, struct proc_entry, next);
                if (pid == e->pid) {
                        list_del(&e->next);
                        proc_entry_destroy(e);
                }
        }
}

struct proc_entry * proc_table_get(struct list_head * proc_table,
                                   pid_t              pid)
{
        struct list_head * h;

        assert(proc_table);

        list_for_each(h, proc_table) {
                struct proc_entry * e = list_entry(h, struct proc_entry, next);
                if (pid == e->pid)
                        return e;
        }

        return NULL;
}
