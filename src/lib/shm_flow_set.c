/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Management of flow_sets for fqueue
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <ouroboros/config.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/shm_flow_set.h>
#include <ouroboros/fqueue.h>
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

#define FN_MAX_CHARS 255

#define FQUEUESIZE ((SHM_BUFFER_SIZE) * sizeof(int))

#define SHM_FLOW_SET_FILE_SIZE (IRMD_MAX_FLOWS * sizeof(ssize_t)          \
                                + AP_MAX_FQUEUES * sizeof(size_t)         \
                                + AP_MAX_FQUEUES * sizeof(pthread_cond_t) \
                                + AP_MAX_FQUEUES * FQUEUESIZE             \
                                + sizeof(pthread_mutex_t))

#define fqueue_ptr(fs, idx) (fs->fqueues + (SHM_BUFFER_SIZE) * idx)

struct shm_flow_set {
        ssize_t *         mtable;
        size_t *          heads;
        pthread_cond_t *  conds;
        int *             fqueues;
        pthread_mutex_t * lock;

        pid_t             api;
};

struct shm_flow_set * shm_flow_set_create()
{
        struct shm_flow_set * set;
        ssize_t *             shm_base;
        pthread_mutexattr_t   mattr;
        pthread_condattr_t    cattr;
        char                  fn[FN_MAX_CHARS];
        mode_t                mask;
        int                   shm_fd;
        int                   i;

        sprintf(fn, SHM_FLOW_SET_PREFIX "%d", getpid());

        set = malloc(sizeof(*set));
        if (set == NULL)
                return NULL;

        mask = umask(0);

        shm_fd = shm_open(fn, O_CREAT | O_EXCL | O_RDWR, 0666);
        if (shm_fd == -1) {
                free(set);
                return NULL;
        }

        umask(mask);

        if (ftruncate(shm_fd, SHM_FLOW_SET_FILE_SIZE - 1) < 0) {
                free(set);
                close(shm_fd);
                return NULL;
        }

        shm_base = mmap(NULL,
                        SHM_FLOW_SET_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);

        close(shm_fd);

        if (shm_base == MAP_FAILED) {
                shm_unlink(fn);
                free(set);
                return NULL;
        }

        set->mtable  = shm_base;
        set->heads   = (size_t *) (set->mtable + IRMD_MAX_FLOWS);
        set->conds   = (pthread_cond_t *)(set->heads + AP_MAX_FQUEUES);
        set->fqueues = (int *) (set->conds + AP_MAX_FQUEUES);
        set->lock    = (pthread_mutex_t *)
                (set->fqueues + AP_MAX_FQUEUES * (SHM_BUFFER_SIZE));

        pthread_mutexattr_init(&mattr);
#ifndef __APPLE__
        pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
#endif
        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(set->lock, &mattr);

        pthread_condattr_init(&cattr);
        pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        for (i = 0; i < AP_MAX_FQUEUES; ++i) {
                set->heads[i] = 0;
                pthread_cond_init(&set->conds[i], &cattr);
        }

        for (i = 0; i < IRMD_MAX_FLOWS; ++i)
                set->mtable[i] = -1;

        set->api = getpid();

        return set;
}

struct shm_flow_set * shm_flow_set_open(pid_t api)
{
        struct shm_flow_set * set;
        ssize_t *             shm_base;
        char                  fn[FN_MAX_CHARS];
        int                   shm_fd;

        sprintf(fn, SHM_FLOW_SET_PREFIX "%d", api);

        set = malloc(sizeof(*set));
        if (set == NULL)
                return NULL;

        shm_fd = shm_open(fn, O_RDWR, 0666);
        if (shm_fd == -1) {
                free(set);
                return NULL;
        }

        shm_base = mmap(NULL,
                        SHM_FLOW_SET_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);

        close(shm_fd);

        if (shm_base == MAP_FAILED) {
                shm_unlink(fn);
                free(set);
                return NULL;
        }

        set->mtable  = shm_base;
        set->heads   = (size_t *) (set->mtable + IRMD_MAX_FLOWS);
        set->conds   = (pthread_cond_t *)(set->heads + AP_MAX_FQUEUES);
        set->fqueues = (int *) (set->conds + AP_MAX_FQUEUES);
        set->lock    = (pthread_mutex_t *)
                (set->fqueues + AP_MAX_FQUEUES * (SHM_BUFFER_SIZE));

        set->api = api;

        return set;
}

void shm_flow_set_destroy(struct shm_flow_set * set)
{
        char fn[25];
        struct lockfile * lf = NULL;

        assert(set);

        if (set->api != getpid()) {
                lf = lockfile_open();
                if (lf == NULL)
                        return;

                if (lockfile_owner(lf) == getpid()) {
                        lockfile_close(lf);
                } else {
                        lockfile_close(lf);
                        return;
                }
        }

        sprintf(fn, SHM_FLOW_SET_PREFIX "%d", set->api);

        munmap(set->mtable, SHM_FLOW_SET_FILE_SIZE);
        shm_unlink(fn);

        free(set);
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
        assert(idx < AP_MAX_FQUEUES);

        pthread_mutex_lock(set->lock);

        for (i = 0; i < IRMD_MAX_FLOWS; ++i)
                if (set->mtable[i] == (ssize_t) idx)
                        set->mtable[i] = -1;

        set->heads[idx] = 0;

        pthread_mutex_unlock(set->lock);
}


int shm_flow_set_add(struct shm_flow_set * set,
                     size_t                idx,
                     int                   port_id)
{
        assert(set);
        assert(!(port_id < 0) && port_id < IRMD_MAX_FLOWS);
        assert(idx < AP_MAX_FQUEUES);

        pthread_mutex_lock(set->lock);

        if (set->mtable[port_id] != -1) {
                pthread_mutex_unlock(set->lock);
                return -EPERM;
        }

        set->mtable[port_id] = idx;

        pthread_mutex_unlock(set->lock);

        return 0;
}

void shm_flow_set_del(struct shm_flow_set * set,
                      size_t                idx,
                      int                   port_id)
{
        assert(set);
        assert(!(port_id < 0) && port_id < IRMD_MAX_FLOWS);
        assert(idx < AP_MAX_FQUEUES);

        pthread_mutex_lock(set->lock);

        if (set->mtable[port_id] == (ssize_t) idx)
                set->mtable[port_id] = -1;

        pthread_mutex_unlock(set->lock);
}

int shm_flow_set_has(struct shm_flow_set * set,
                     size_t                idx,
                     int                   port_id)
{
        int ret = 0;

        assert(set);
        assert(!(port_id < 0) && port_id < IRMD_MAX_FLOWS);
        assert(idx < AP_MAX_FQUEUES);

        pthread_mutex_lock(set->lock);

        if (set->mtable[port_id] == (ssize_t) idx)
                ret = 1;

        pthread_mutex_unlock(set->lock);

        return ret;
}

void shm_flow_set_notify(struct shm_flow_set * set, int port_id)
{
        assert(set);
        assert(!(port_id < 0) && port_id < IRMD_MAX_FLOWS);

        pthread_mutex_lock(set->lock);

        if (set->mtable[port_id] == -1) {
                pthread_mutex_unlock(set->lock);
                return;
        }

        *(fqueue_ptr(set, set->mtable[port_id]) +
                     (set->heads[set->mtable[port_id]])++) = port_id;

        pthread_cond_signal(&set->conds[set->mtable[port_id]]);

        pthread_mutex_unlock(set->lock);
}


ssize_t shm_flow_set_wait(const struct shm_flow_set * set,
                          size_t                      idx,
                          int *                       fqueue,
                          const struct timespec *     timeout)
{
        ssize_t ret = 0;
        struct timespec abstime;

        assert(set);
        assert(idx < AP_MAX_FQUEUES);
        assert(fqueue);

#ifdef __APPLE__
        pthread_mutex_lock(set->lock);
#else
        if (pthread_mutex_lock(set->lock) == EOWNERDEAD)
                pthread_mutex_consistent(set->lock);
#endif
        if (timeout != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) set->lock);

        while (set->heads[idx] == 0 && ret != -ETIMEDOUT) {
                if (timeout != NULL)
                        ret = -pthread_cond_timedwait(set->conds + idx,
                                                      set->lock,
                                                      &abstime);
                else
                        ret = -pthread_cond_wait(set->conds + idx,
                                                 set->lock);
#ifndef __APPLE__
                if (ret == -EOWNERDEAD)
                        pthread_mutex_consistent(set->lock);
#endif
                if (ret == -ETIMEDOUT)
                        break;
        }

        if (ret != -ETIMEDOUT) {
                memcpy(fqueue,
                       fqueue_ptr(set, idx),
                       set->heads[idx] * sizeof(int));
                ret = set->heads[idx];
                set->heads[idx] = 0;
        }

        pthread_cleanup_pop(true);

        assert(ret);

        return ret;
}
