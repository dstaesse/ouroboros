/*
 * Ouroboros - Copyright (C) 2016
 *
 * Management of flow_sets for fqueue
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <ouroboros/config.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/shm_flow_set.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/errno.h>

#define OUROBOROS_PREFIX "shm_flow_set"

#include <ouroboros/logs.h>

#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>

#define FN_MAX_CHARS 255

#define FQUEUESIZE (SHM_BUFFER_SIZE * sizeof(int))

#define SHM_FLOW_SET_FILE_SIZE (IRMD_MAX_FLOWS * sizeof(ssize_t)          \
                                + AP_MAX_FQUEUES * sizeof(size_t)         \
                                + AP_MAX_FQUEUES * sizeof(pthread_cond_t) \
                                + AP_MAX_FQUEUES * FQUEUESIZE             \
                                + sizeof(pthread_mutex_t))

#define fqueue_ptr(fs, idx) (fs->fqueues + SHM_BUFFER_SIZE * idx)

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
        if (set == NULL) {
                LOG_DBG("Could not allocate struct.");
                return NULL;
        }

        mask = umask(0);

        shm_fd = shm_open(fn, O_CREAT | O_EXCL | O_RDWR, 0666);
        if (shm_fd == -1) {
                LOG_DBG("Failed creating flag file.");
                free(set);
                return NULL;
        }

        umask(mask);

        if (ftruncate(shm_fd, SHM_FLOW_SET_FILE_SIZE - 1) < 0) {
                LOG_DBG("Failed to extend flag file.");
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
                LOG_DBG("Failed to map shared memory.");
                if (shm_unlink(fn) == -1)
                        LOG_DBG("Failed to remove invalid shm.");

                free(set);
                return NULL;
        }

        set->mtable  = shm_base;
        set->heads   = (size_t *) (set->mtable + IRMD_MAX_FLOWS);
        set->conds   = (pthread_cond_t *)(set->heads + AP_MAX_FQUEUES);
        set->fqueues = (int *) (set->conds + AP_MAX_FQUEUES);
        set->lock    = (pthread_mutex_t *)
                (set->fqueues + AP_MAX_FQUEUES * SHM_BUFFER_SIZE);

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
        if (set == NULL) {
                LOG_DBG("Could not allocate struct.");
                return NULL;
        }

        shm_fd = shm_open(fn, O_RDWR, 0666);
        if (shm_fd == -1) {
                LOG_DBG("%d failed opening shared memory %s.", getpid(), fn);
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
                LOG_DBG("Failed to map shared memory.");
                if (shm_unlink(fn) == -1)
                        LOG_DBG("Failed to remove invalid shm.");
                free(set);
                return NULL;
        }

        set->mtable  = shm_base;
        set->heads   = (size_t *) (set->mtable + IRMD_MAX_FLOWS);
        set->conds   = (pthread_cond_t *)(set->heads + AP_MAX_FQUEUES);
        set->fqueues = (int *) (set->conds + AP_MAX_FQUEUES);
        set->lock    = (pthread_mutex_t *)
                (set->fqueues + AP_MAX_FQUEUES * SHM_BUFFER_SIZE);

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
                if (lf == NULL) {
                        LOG_ERR("Failed to open lockfile.");
                        return;
                }

                if (lockfile_owner(lf) == getpid()) {
                        LOG_DBG("Flow set %d destroyed by IRMd %d.",
                                set->api, getpid());
                        lockfile_close(lf);
                } else {
                        LOG_ERR("AP-I %d tried to destroy flowset owned by %d.",
                                getpid(), set->api);
                        lockfile_close(lf);
                        return;
                }
        }

        sprintf(fn, SHM_FLOW_SET_PREFIX "%d", set->api);

        if (munmap(set->mtable, SHM_FLOW_SET_FILE_SIZE) == -1)
                LOG_DBG("Couldn't unmap shared memory.");

        if (shm_unlink(fn) == -1)
                LOG_DBG("Failed to unlink shm.");

        free(set);
}

void shm_flow_set_close(struct shm_flow_set * set)
{
        assert(set);

        if (munmap(set->mtable, SHM_FLOW_SET_FILE_SIZE) == -1)
                LOG_DBG("Couldn't unmap shared memory.");

        free(set);
}

void shm_flow_set_zero(struct shm_flow_set * shm_set,
                       ssize_t               idx)
{
        ssize_t i = 0;

        assert(!(idx < 0) && idx < AP_MAX_FQUEUES);

        pthread_mutex_lock(shm_set->lock);

        for (i = 0; i < IRMD_MAX_FLOWS; ++i)
                if (shm_set->mtable[i] == idx)
                        shm_set->mtable[i] = -1;

        shm_set->heads[idx] = 0;

        pthread_mutex_unlock(shm_set->lock);
}


int shm_flow_set_add(struct shm_flow_set * shm_set,
                     ssize_t               idx,
                     int                   port_id)
{
        assert(shm_set);
        assert(!(port_id < 0) && port_id < IRMD_MAX_FLOWS);
        assert(!(idx < 0) && idx < AP_MAX_FQUEUES);

        pthread_mutex_lock(shm_set->lock);

        if (shm_set->mtable[port_id] != -1) {
                pthread_mutex_unlock(shm_set->lock);
                return -EPERM;
        }

        shm_set->mtable[port_id] = idx;

        pthread_mutex_unlock(shm_set->lock);

        return 0;
}

void shm_flow_set_del(struct shm_flow_set * shm_set,
                      ssize_t               idx,
                      int                   port_id)
{
        assert(shm_set);
        assert(!(port_id < 0) && port_id < IRMD_MAX_FLOWS);
        assert(!(idx < 0) && idx < AP_MAX_FQUEUES);

        pthread_mutex_lock(shm_set->lock);

        if (shm_set->mtable[port_id] == idx)
                shm_set->mtable[port_id] = -1;

        pthread_mutex_unlock(shm_set->lock);
}

int shm_flow_set_has(struct shm_flow_set * shm_set,
                     ssize_t               idx,
                     int                   port_id)
{
        int ret = 0;

        assert(shm_set);
        assert(!(port_id < 0) && port_id < IRMD_MAX_FLOWS);
        assert(!(idx < 0) && idx < AP_MAX_FQUEUES);


        pthread_mutex_lock(shm_set->lock);

        if (shm_set->mtable[port_id] == idx)
                ret = 1;

        pthread_mutex_unlock(shm_set->lock);

        return ret;
}

void shm_flow_set_notify(struct shm_flow_set * shm_set, int port_id)
{
        assert(shm_set);
        assert(!(port_id < 0) && port_id < IRMD_MAX_FLOWS);

        pthread_mutex_lock(shm_set->lock);

        if (shm_set->mtable[port_id] == -1) {
                pthread_mutex_unlock(shm_set->lock);
                return;
        }

        *(fqueue_ptr(shm_set, shm_set->mtable[port_id]) +
                     (shm_set->heads[shm_set->mtable[port_id]])++) = port_id;

        pthread_cond_signal(&shm_set->conds[shm_set->mtable[port_id]]);

        pthread_mutex_unlock(shm_set->lock);
}


int shm_flow_set_wait(const struct shm_flow_set * shm_set,
                      ssize_t                     idx,
                      int *                       fqueue,
                      const struct timespec *     timeout)
{
        int ret = 0;
        struct timespec abstime;

        assert(shm_set);
        assert(!(idx < 0) && idx < AP_MAX_FQUEUES);

#ifdef __APPLE__
        pthread_mutex_lock(shm_set->lock);
#else
        if (pthread_mutex_lock(shm_set->lock) == EOWNERDEAD) {
                LOG_DBG("Recovering dead mutex.");
                pthread_mutex_consistent(shm_set->lock);
        }
#endif
        if (timeout != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) shm_set->lock);

        while (shm_set->heads[idx] == 0 && ret != -ETIMEDOUT) {
                if (timeout != NULL)
                        ret = pthread_cond_timedwait(shm_set->conds + idx,
                                                     shm_set->lock,
                                                     &abstime);
                else
                        ret = pthread_cond_wait(shm_set->conds + idx,
                                                shm_set->lock);
#ifndef __APPLE__
                if (ret == EOWNERDEAD) {
                        LOG_DBG("Recovering dead mutex.");
                        pthread_mutex_consistent(shm_set->lock);
                }
#endif
                if (ret == ETIMEDOUT) {
                        ret = -ETIMEDOUT;
                        break;
                }
        }

        if (ret != -ETIMEDOUT) {
                memcpy(fqueue,
                       fqueue_ptr(shm_set, idx),
                       shm_set->heads[idx] * sizeof(int));
                ret = shm_set->heads[idx];
                shm_set->heads[idx] = 0;
        }

        pthread_cleanup_pop(true);

        return ret;
}
