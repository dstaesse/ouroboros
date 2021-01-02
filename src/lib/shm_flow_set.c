/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Management of flow_sets for fqueue
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <ouroboros/lockfile.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/shm_flow_set.h>
#include <ouroboros/errno.h>

#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>

/*
 * pthread_cond_timedwait has a WONTFIX bug as of glibc 2.25 where it
 * doesn't test pthread cancellation when passed an expired timeout
 * with the clock set to CLOCK_MONOTONIC.
 */
#if ((defined(__linux__) || (defined(__MACH__) && !defined(__APPLE__)))        \
     && (defined(__GLIBC__) && ((__GLIBC__ * 1000 + __GLIBC_MINOR__) >= 2025)) \
     && (PTHREAD_COND_CLOCK == CLOCK_MONOTONIC))
#define HAVE_CANCEL_BUG
#endif

#define FN_MAX_CHARS 255

#define QUEUESIZE ((SHM_BUFFER_SIZE) * sizeof(struct portevent))

#define SHM_FLOW_SET_FILE_SIZE (SYS_MAX_FLOWS * sizeof(ssize_t)             \
                                + PROG_MAX_FQUEUES * sizeof(size_t)         \
                                + PROG_MAX_FQUEUES * sizeof(pthread_cond_t) \
                                + PROG_MAX_FQUEUES * QUEUESIZE              \
                                + sizeof(pthread_mutex_t))

#define fqueue_ptr(fs, idx) (fs->fqueues + (SHM_BUFFER_SIZE) * idx)

struct portevent {
        int flow_id;
        int event;
};

struct shm_flow_set {
        ssize_t *          mtable;
        size_t *           heads;
        pthread_cond_t *   conds;
        struct portevent * fqueues;
        pthread_mutex_t *  lock;

        pid_t pid;
};

static struct shm_flow_set * flow_set_create(pid_t pid,
                                             int   flags)
{
        struct shm_flow_set * set;
        ssize_t *             shm_base;
        char                  fn[FN_MAX_CHARS];
        int                   shm_fd;

        sprintf(fn, SHM_FLOW_SET_PREFIX "%d", pid);

        set = malloc(sizeof(*set));
        if (set == NULL)
                goto fail_malloc;

        shm_fd = shm_open(fn, flags, 0666);
        if (shm_fd == -1)
                goto fail_shm_open;

        if (ftruncate(shm_fd, SHM_FLOW_SET_FILE_SIZE - 1) < 0) {
                close(shm_fd);
                goto fail_shm_open;
        }

        shm_base = mmap(NULL,
                        SHM_FLOW_SET_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);

        close(shm_fd);

        if (shm_base == MAP_FAILED)
                goto fail_mmap;

        set->mtable  = shm_base;
        set->heads   = (size_t *) (set->mtable + SYS_MAX_FLOWS);
        set->conds   = (pthread_cond_t *)(set->heads + PROG_MAX_FQUEUES);
        set->fqueues = (struct portevent *) (set->conds + PROG_MAX_FQUEUES);
        set->lock    = (pthread_mutex_t *)
                (set->fqueues + PROG_MAX_FQUEUES * (SHM_BUFFER_SIZE));

        return set;

 fail_mmap:
        if (flags & O_CREAT)
                shm_unlink(fn);
 fail_shm_open:
        free(set);
 fail_malloc:
        return NULL;
}

struct shm_flow_set * shm_flow_set_create(pid_t pid)
{
        struct shm_flow_set * set;
        pthread_mutexattr_t   mattr;
        pthread_condattr_t    cattr;
        mode_t                mask;
        int                   i;

        mask = umask(0);

        set = flow_set_create(pid, O_CREAT | O_RDWR);

        umask(mask);

        if (set == NULL)
                goto fail_set;

        set->pid = pid;

        if (pthread_mutexattr_init(&mattr))
                goto fail_mutexattr_init;

#ifdef HAVE_ROBUST_MUTEX
        if (pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST))
                goto fail_mattr_set;
#endif
        if (pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED))
                goto fail_mattr_set;

        if (pthread_mutex_init(set->lock, &mattr))
                goto fail_mattr_set;

        if (pthread_condattr_init(&cattr))
                goto fail_condattr_init;

        if (pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED))
                goto fail_condattr_set;

#ifndef __APPLE__
        if (pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK))
                goto fail_condattr_set;
#endif
        for (i = 0; i < PROG_MAX_FQUEUES; ++i) {
                set->heads[i] = 0;
                if (pthread_cond_init(&set->conds[i], &cattr))
                        goto fail_init;
        }

        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                set->mtable[i] = -1;

        return set;

 fail_init:
        while (i-- > 0)
                pthread_cond_destroy(&set->conds[i]);
 fail_condattr_set:
        pthread_condattr_destroy(&cattr);
 fail_condattr_init:
        pthread_mutex_destroy(set->lock);
 fail_mattr_set:
        pthread_mutexattr_destroy(&mattr);
 fail_mutexattr_init:
        shm_flow_set_destroy(set);
 fail_set:
        return NULL;
}

struct shm_flow_set * shm_flow_set_open(pid_t pid)
{
        return flow_set_create(pid, O_RDWR);
}

void shm_flow_set_destroy(struct shm_flow_set * set)
{
        char fn[25];

        assert(set);

        sprintf(fn, SHM_FLOW_SET_PREFIX "%d", set->pid);

        shm_flow_set_close(set);

        shm_unlink(fn);
}

void shm_flow_set_close(struct shm_flow_set * set)
{
        assert(set);

        munmap(set->mtable, SHM_FLOW_SET_FILE_SIZE);
        free(set);
}

void shm_flow_set_zero(struct shm_flow_set * set,
                       size_t                idx)
{
        ssize_t i = 0;

        assert(set);
        assert(idx < PROG_MAX_FQUEUES);

        pthread_mutex_lock(set->lock);

        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                if (set->mtable[i] == (ssize_t) idx)
                        set->mtable[i] = -1;

        set->heads[idx] = 0;

        pthread_mutex_unlock(set->lock);
}


int shm_flow_set_add(struct shm_flow_set * set,
                     size_t                idx,
                     int                   flow_id)
{
        assert(set);
        assert(!(flow_id < 0) && flow_id < SYS_MAX_FLOWS);
        assert(idx < PROG_MAX_FQUEUES);

        pthread_mutex_lock(set->lock);

        if (set->mtable[flow_id] != -1) {
                pthread_mutex_unlock(set->lock);
                return -EPERM;
        }

        set->mtable[flow_id] = idx;

        pthread_mutex_unlock(set->lock);

        return 0;
}

void shm_flow_set_del(struct shm_flow_set * set,
                      size_t                idx,
                      int                   flow_id)
{
        assert(set);
        assert(!(flow_id < 0) && flow_id < SYS_MAX_FLOWS);
        assert(idx < PROG_MAX_FQUEUES);

        pthread_mutex_lock(set->lock);

        if (set->mtable[flow_id] == (ssize_t) idx)
                set->mtable[flow_id] = -1;

        pthread_mutex_unlock(set->lock);
}

int shm_flow_set_has(struct shm_flow_set * set,
                     size_t                idx,
                     int                   flow_id)
{
        int ret = 0;

        assert(set);
        assert(!(flow_id < 0) && flow_id < SYS_MAX_FLOWS);
        assert(idx < PROG_MAX_FQUEUES);

        pthread_mutex_lock(set->lock);

        if (set->mtable[flow_id] == (ssize_t) idx)
                ret = 1;

        pthread_mutex_unlock(set->lock);

        return ret;
}

void shm_flow_set_notify(struct shm_flow_set * set,
                         int                   flow_id,
                         int                   event)
{
        assert(set);
        assert(!(flow_id < 0) && flow_id < SYS_MAX_FLOWS);

        pthread_mutex_lock(set->lock);

        if (set->mtable[flow_id] == -1) {
                pthread_mutex_unlock(set->lock);
                return;
        }

        (fqueue_ptr(set, set->mtable[flow_id]) +
         (set->heads[set->mtable[flow_id]]))->flow_id = flow_id;
        (fqueue_ptr(set, set->mtable[flow_id]) +
         (set->heads[set->mtable[flow_id]])++)->event = event;

        pthread_cond_signal(&set->conds[set->mtable[flow_id]]);

        pthread_mutex_unlock(set->lock);
}


ssize_t shm_flow_set_wait(const struct shm_flow_set * set,
                          size_t                      idx,
                          int *                       fqueue,
                          const struct timespec *     abstime)
{
        ssize_t ret = 0;

        assert(set);
        assert(idx < PROG_MAX_FQUEUES);
        assert(fqueue);

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(set->lock);
#else
        if (pthread_mutex_lock(set->lock) == EOWNERDEAD)
                pthread_mutex_consistent(set->lock);
#endif

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) set->lock);

        while (set->heads[idx] == 0 && ret != -ETIMEDOUT) {
                if (abstime != NULL) {
                        ret = -pthread_cond_timedwait(set->conds + idx,
                                                      set->lock,
                                                      abstime);
#ifdef HAVE_CANCEL_BUG
                        if (ret == -ETIMEDOUT)
                                pthread_testcancel();
#endif
                } else {
                        ret = -pthread_cond_wait(set->conds + idx,
                                                 set->lock);
                }
#ifdef HAVE_ROBUST_MUTEX
                if (ret == -EOWNERDEAD)
                        pthread_mutex_consistent(set->lock);
#endif
        }

        if (ret != -ETIMEDOUT) {
                memcpy(fqueue,
                       fqueue_ptr(set, idx),
                       set->heads[idx] * sizeof(struct portevent));
                ret = set->heads[idx];
                set->heads[idx] = 0;
        }

        pthread_cleanup_pop(true);

        assert(ret);

        return ret;
}
