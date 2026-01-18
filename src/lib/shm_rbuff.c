/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Ring buffer implementations for incoming packets
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

#include <ouroboros/shm_rbuff.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/errno.h>
#include <ouroboros/fccntl.h>
#include <ouroboros/pthread.h>
#include <ouroboros/time.h>

#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define FN_MAX_CHARS 255

#define SHM_RBUFF_FILESIZE ((SHM_RBUFF_SIZE) * sizeof(ssize_t)          \
                          + 3 * sizeof(size_t)                          \
                          + sizeof(pthread_mutex_t)                     \
                          + 2 * sizeof(pthread_cond_t))

#define HEAD(rb)     \
        *(rb->shm_base + *rb->head)
#define TAIL(rb)     \
        *(rb->shm_base + *rb->tail)
#define ADVANCE(el)  \
        (*(el) = (*(el) + 1) & ((SHM_RBUFF_SIZE) - 1))
#define QUEUED(rb)   \
         ((*rb->head - *rb->tail + (SHM_RBUFF_SIZE)) & (SHM_RBUFF_SIZE - 1))
#define IS_FULL(rb)  \
        (QUEUED(rb) == (SHM_RBUFF_SIZE) - 1)
#define IS_EMPTY(rb) \
        (*rb->head == *rb->tail)

struct shm_rbuff {
        ssize_t *         shm_base; /* start of entry                */
        size_t *          head;     /* start of ringbuffer head      */
        size_t *          tail;     /* start of ringbuffer tail      */
        size_t *          acl;      /* access control                */
        pthread_mutex_t * mtx;      /* lock all space in shm         */
        pthread_cond_t *  add;      /* packet arrived                */
        pthread_cond_t *  del;      /* packet removed                */
        pid_t             pid;      /* pid of the owner              */
        int               flow_id;  /* flow_id of the flow           */
};

static void robust_mutex_lock(pthread_mutex_t * mtx)
{
#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(mtx);
#else
        if (pthread_mutex_lock(mtx) == EOWNERDEAD)
                pthread_mutex_consistent(mtx);
#endif
}

static int robust_wait(pthread_cond_t *        cond,
                       pthread_mutex_t *       mtx,
                       const struct timespec * abstime)
{
        int ret = __timedwait(cond, mtx, abstime);
#ifdef HAVE_ROBUST_MUTEX
                if (ret == EOWNERDEAD)
                        pthread_mutex_consistent(mtx);
#endif
        return ret;
}


#define MM_FLAGS (PROT_READ | PROT_WRITE)

static struct shm_rbuff * rbuff_create(pid_t pid,
                                       int   flow_id,
                                       int   flags)
{
        struct shm_rbuff * rb;
        int                fd;
        ssize_t *          shm_base;
        char               fn[FN_MAX_CHARS];

        sprintf(fn, SHM_RBUFF_PREFIX "%d.%d", pid, flow_id);

        rb = malloc(sizeof(*rb));
        if (rb == NULL)
                goto fail_malloc;

        fd = shm_open(fn, flags, 0666);
        if (fd == -1)
                goto fail_open;

        if ((flags & O_CREAT) && ftruncate(fd, SHM_RBUFF_FILESIZE) < 0)
                goto fail_truncate;

        shm_base = mmap(NULL, SHM_RBUFF_FILESIZE, MM_FLAGS, MAP_SHARED, fd, 0);
        if (shm_base == MAP_FAILED)
                goto fail_truncate;

        close(fd);

        rb->shm_base = shm_base;
        rb->head     = (size_t *) (rb->shm_base + (SHM_RBUFF_SIZE));
        rb->tail     = rb->head + 1;
        rb->acl      = rb->tail + 1;
        rb->mtx      = (pthread_mutex_t *) (rb->acl + 1);
        rb->add      = (pthread_cond_t *) (rb->mtx + 1);
        rb->del      = rb->add + 1;
        rb->pid      = pid;
        rb->flow_id  = flow_id;

        return rb;

 fail_truncate:
        close(fd);
        if (flags & O_CREAT)
                shm_unlink(fn);
 fail_open:
        free(rb);
 fail_malloc:
        return NULL;
}

static void rbuff_destroy(struct shm_rbuff * rb)
{
        munmap(rb->shm_base, SHM_RBUFF_FILESIZE);

        free(rb);
}

struct shm_rbuff * shm_rbuff_create(pid_t pid,
                                    int   flow_id)
{
        struct shm_rbuff *  rb;
        pthread_mutexattr_t mattr;
        pthread_condattr_t  cattr;
        mode_t              mask;

        mask = umask(0);

        rb = rbuff_create(pid, flow_id, O_CREAT | O_EXCL | O_RDWR);

        umask(mask);

        if (rb == NULL)
                goto fail_rb;

        if (pthread_mutexattr_init(&mattr))
                goto fail_mattr;

        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
#ifdef HAVE_ROBUST_MUTEX
        pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
#endif
        if (pthread_mutex_init(rb->mtx, &mattr))
                goto fail_mutex;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;

        pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(rb->add, &cattr))
                goto fail_add;

        if (pthread_cond_init(rb->del, &cattr))
                goto fail_del;

        *rb->acl  = ACL_RDWR;
        *rb->head = 0;
        *rb->tail = 0;

        rb->pid     = pid;
        rb->flow_id = flow_id;

        pthread_mutexattr_destroy(&mattr);
        pthread_condattr_destroy(&cattr);

        return rb;

 fail_del:
        pthread_cond_destroy(rb->add);
 fail_add:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(rb->mtx);
 fail_mutex:
        pthread_mutexattr_destroy(&mattr);
 fail_mattr:
        shm_rbuff_destroy(rb);
 fail_rb:
        return NULL;
}

void shm_rbuff_destroy(struct shm_rbuff * rb)
{
        char fn[FN_MAX_CHARS];

        assert(rb != NULL);

        sprintf(fn, SHM_RBUFF_PREFIX "%d.%d", rb->pid, rb->flow_id);

        shm_rbuff_close(rb);

        shm_unlink(fn);
}

struct shm_rbuff * shm_rbuff_open(pid_t pid,
                                  int   flow_id)
{
        return rbuff_create(pid, flow_id, O_RDWR);
}

void shm_rbuff_close(struct shm_rbuff * rb)
{
        assert(rb);

        rbuff_destroy(rb);
}

int shm_rbuff_write(struct shm_rbuff * rb,
                    size_t             idx)
{
        int ret = 0;

        assert(rb != NULL);
        assert(idx < SHM_BUFFER_SIZE);

        robust_mutex_lock(rb->mtx);

        if (*rb->acl != ACL_RDWR) {
                if (*rb->acl & ACL_FLOWDOWN)
                        ret = -EFLOWDOWN;
                else if (*rb->acl & ACL_RDONLY)
                        ret = -ENOTALLOC;
                goto err;
        }

        if (IS_FULL(rb)) {
                ret = -EAGAIN;
                goto err;
        }

        if (IS_EMPTY(rb))
                pthread_cond_broadcast(rb->add);

        HEAD(rb) = (ssize_t) idx;
        ADVANCE(rb->head);

        pthread_mutex_unlock(rb->mtx);

        return 0;
 err:
        pthread_mutex_unlock(rb->mtx);
        return ret;
}

int shm_rbuff_write_b(struct shm_rbuff *      rb,
                      size_t                  idx,
                      const struct timespec * abstime)
{
        int ret = 0;

        assert(rb != NULL);
        assert(idx < SHM_BUFFER_SIZE);

        robust_mutex_lock(rb->mtx);

        if (*rb->acl != ACL_RDWR) {
                if (*rb->acl & ACL_FLOWDOWN)
                        ret = -EFLOWDOWN;
                else if (*rb->acl & ACL_RDONLY)
                        ret = -ENOTALLOC;
                goto err;
        }

        pthread_cleanup_push(__cleanup_mutex_unlock, rb->mtx);

        while (IS_FULL(rb)
               && ret != -ETIMEDOUT
               && !(*rb->acl & ACL_FLOWDOWN)) {
                ret = -robust_wait(rb->del, rb->mtx, abstime);
        }

        if (ret != -ETIMEDOUT) {
                if (IS_EMPTY(rb))
                        pthread_cond_broadcast(rb->add);
                HEAD(rb) = (ssize_t) idx;
                ADVANCE(rb->head);
        }

        pthread_cleanup_pop(true);

        return ret;
 err:
        pthread_mutex_unlock(rb->mtx);
        return ret;
}

static int check_rb_acl(struct shm_rbuff * rb)
{
        assert(rb != NULL);

        if (*rb->acl & ACL_FLOWDOWN)
                return -EFLOWDOWN;

        if (*rb->acl & ACL_FLOWPEER)
                return -EFLOWPEER;

        return -EAGAIN;
}

ssize_t shm_rbuff_read(struct shm_rbuff * rb)
{
        ssize_t ret = 0;

        assert(rb != NULL);

        robust_mutex_lock(rb->mtx);

        if (IS_EMPTY(rb)) {
                ret = check_rb_acl(rb);
                pthread_mutex_unlock(rb->mtx);
                return ret;
        }

        ret = TAIL(rb);
        ADVANCE(rb->tail);
        pthread_cond_broadcast(rb->del);

        pthread_mutex_unlock(rb->mtx);

        return ret;
}

ssize_t shm_rbuff_read_b(struct shm_rbuff *      rb,
                         const struct timespec * abstime)
{
        ssize_t idx = -1;

        assert(rb != NULL);

        robust_mutex_lock(rb->mtx);

        if (IS_EMPTY(rb) && (*rb->acl & ACL_FLOWDOWN)) {
                pthread_mutex_unlock(rb->mtx);
                return -EFLOWDOWN;
        }

        pthread_cleanup_push(__cleanup_mutex_unlock, rb->mtx);

        while (IS_EMPTY(rb) &&
               idx != -ETIMEDOUT &&
               check_rb_acl(rb) == -EAGAIN) {
                idx = -robust_wait(rb->add, rb->mtx, abstime);
        }

        if (!IS_EMPTY(rb)) {
                idx = TAIL(rb);
                ADVANCE(rb->tail);
                pthread_cond_broadcast(rb->del);
        } else if (idx != -ETIMEDOUT) {
                idx = check_rb_acl(rb);
        }

        pthread_cleanup_pop(true);

        assert(idx != -EAGAIN);

        return idx;
}

void shm_rbuff_set_acl(struct shm_rbuff * rb,
                       uint32_t           flags)
{
        assert(rb != NULL);

        robust_mutex_lock(rb->mtx);
        *rb->acl = (size_t) flags;

        pthread_mutex_unlock(rb->mtx);
}

uint32_t shm_rbuff_get_acl(struct shm_rbuff * rb)
{
        uint32_t flags;

        assert(rb != NULL);

        robust_mutex_lock(rb->mtx);

        flags = (uint32_t) *rb->acl;

        pthread_mutex_unlock(rb->mtx);

        return flags;
}

void shm_rbuff_fini(struct shm_rbuff * rb)
{
        assert(rb != NULL);

        robust_mutex_lock(rb->mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, rb->mtx);

        while (!IS_EMPTY(rb))
                robust_wait(rb->del, rb->mtx, NULL);

        pthread_cleanup_pop(true);
}

size_t shm_rbuff_queued(struct shm_rbuff * rb)
{
        size_t ret;

        assert(rb != NULL);

        robust_mutex_lock(rb->mtx);

        ret = QUEUED(rb);

        pthread_mutex_unlock(rb->mtx);

        return ret;
}

int shm_rbuff_mlock(struct shm_rbuff * rb)
{
        assert(rb != NULL);

        return mlock(rb->shm_base, SHM_RBUFF_FILESIZE);
}
