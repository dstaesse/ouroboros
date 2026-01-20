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
#include "ssm.h"

#include <ouroboros/ssm_rbuff.h>
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

#define SSM_RBUFF_FILESIZE ((SSM_RBUFF_SIZE) * sizeof(ssize_t)                 \
                          + 3 * sizeof(size_t)                                 \
                          + sizeof(pthread_mutex_t)                            \
                          + 2 * sizeof(pthread_cond_t))

#define MODB(x)           ((x) & (SSM_RBUFF_SIZE - 1))

#define LOAD_RELAXED(ptr) (__atomic_load_n(ptr, __ATOMIC_RELAXED))
#define LOAD_ACQUIRE(ptr) (__atomic_load_n(ptr, __ATOMIC_ACQUIRE))
#define STORE_RELEASE(ptr, val)                                                \
        (__atomic_store_n(ptr, val, __ATOMIC_RELEASE))

#define HEAD(rb)       (rb->shm_base[LOAD_RELAXED(rb->head)])
#define TAIL(rb)       (rb->shm_base[LOAD_RELAXED(rb->tail)])
#define HEAD_IDX(rb)   (LOAD_ACQUIRE(rb->head))
#define TAIL_IDX(rb)   (LOAD_ACQUIRE(rb->tail))
#define ADVANCE_HEAD(rb)                                                       \
        (STORE_RELEASE(rb->head, MODB(LOAD_RELAXED(rb->head) + 1)))
#define ADVANCE_TAIL(rb)                                                       \
        (STORE_RELEASE(rb->tail, MODB(LOAD_RELAXED(rb->tail) + 1)))
#define QUEUED(rb)     (MODB(HEAD_IDX(rb) - TAIL_IDX(rb)))
#define IS_FULL(rb)    (QUEUED(rb) == (SSM_RBUFF_SIZE - 1))
#define IS_EMPTY(rb)   (HEAD_IDX(rb) == TAIL_IDX(rb))

struct ssm_rbuff {
        ssize_t *         shm_base;     /* start of shared memory   */
        size_t *          head;         /* start of ringbuffer      */
        size_t *          tail;
        size_t *          acl;          /* access control           */
        pthread_mutex_t * mtx;          /* lock for cond vars only  */
        pthread_cond_t *  add;          /* signal when new data     */
        pthread_cond_t *  del;          /* signal when data removed */
        pid_t             pid;          /* pid of the owner         */
        int               flow_id;      /* flow_id of the flow      */
};

#define MM_FLAGS (PROT_READ | PROT_WRITE)

static struct ssm_rbuff * rbuff_create(pid_t pid,
                                       int   flow_id,
                                       int   flags)
{
        struct ssm_rbuff * rb;
        int                fd;
        ssize_t *          shm_base;
        char               fn[FN_MAX_CHARS];

        sprintf(fn, SSM_RBUFF_PREFIX "%d.%d", pid, flow_id);

        rb = malloc(sizeof(*rb));
        if (rb == NULL)
                goto fail_malloc;

        fd = shm_open(fn, flags, 0666);
        if (fd == -1)
                goto fail_open;

        if ((flags & O_CREAT) && ftruncate(fd, SSM_RBUFF_FILESIZE) < 0)
                goto fail_truncate;

        shm_base = mmap(NULL, SSM_RBUFF_FILESIZE, MM_FLAGS, MAP_SHARED, fd, 0);

        close(fd);

        rb->shm_base = shm_base;
        rb->head     = (size_t *) (rb->shm_base + (SSM_RBUFF_SIZE));
        rb->tail     = (size_t *) (rb->head + 1);
        rb->acl      = (size_t *) (rb->tail + 1);
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

static void rbuff_destroy(struct ssm_rbuff * rb)
{
        munmap(rb->shm_base, SSM_RBUFF_FILESIZE);

        free(rb);
}

struct ssm_rbuff * ssm_rbuff_create(pid_t pid,
                                    int   flow_id)
{
        struct ssm_rbuff *  rb;
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
        ssm_rbuff_destroy(rb);
 fail_rb:
        return NULL;
}

void ssm_rbuff_destroy(struct ssm_rbuff * rb)
{
        char fn[FN_MAX_CHARS];

        assert(rb != NULL);

        sprintf(fn, SSM_RBUFF_PREFIX "%d.%d", rb->pid, rb->flow_id);

        ssm_rbuff_close(rb);

        shm_unlink(fn);
}

struct ssm_rbuff * ssm_rbuff_open(pid_t pid,
                                  int   flow_id)
{
        return rbuff_create(pid, flow_id, O_RDWR);
}

void ssm_rbuff_close(struct ssm_rbuff * rb)
{
        assert(rb);

        rbuff_destroy(rb);
}

int ssm_rbuff_write(struct ssm_rbuff * rb,
                    size_t             idx)
{
        size_t acl;
        bool   was_empty;
        int    ret = 0;

        assert(rb != NULL);

        acl = __atomic_load_n(rb->acl, __ATOMIC_SEQ_CST);
        if (acl != ACL_RDWR) {
                if (acl & ACL_FLOWDOWN) {
                        ret = -EFLOWDOWN;
                        goto fail_acl;
                }
                if (acl & ACL_RDONLY) {
                        ret = -ENOTALLOC;
                        goto fail_acl;
                }
        }

        robust_mutex_lock(rb->mtx);

        if (IS_FULL(rb)) {
                ret = -EAGAIN;
                goto fail_mutex;
        }

        was_empty = IS_EMPTY(rb);

        HEAD(rb) = (ssize_t) idx;
        ADVANCE_HEAD(rb);

        if (was_empty)
                pthread_cond_broadcast(rb->add);

        pthread_mutex_unlock(rb->mtx);

        return 0;

 fail_mutex:
        pthread_mutex_unlock(rb->mtx);
 fail_acl:
        return ret;
}

int ssm_rbuff_write_b(struct ssm_rbuff *      rb,
                      size_t                  idx,
                      const struct timespec * abstime)
{
        size_t acl;
        int    ret = 0;
        bool   was_empty;

        assert(rb != NULL);

        acl = __atomic_load_n(rb->acl, __ATOMIC_SEQ_CST);
        if (acl != ACL_RDWR) {
                if (acl & ACL_FLOWDOWN) {
                        ret = -EFLOWDOWN;
                        goto fail_acl;
                }
                if (acl & ACL_RDONLY) {
                        ret = -ENOTALLOC;
                        goto fail_acl;
                }
        }

        robust_mutex_lock(rb->mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, rb->mtx);

        while (IS_FULL(rb) && ret != -ETIMEDOUT) {
                acl = __atomic_load_n(rb->acl, __ATOMIC_SEQ_CST);
                if (acl & ACL_FLOWDOWN) {
                        ret = -EFLOWDOWN;
                        break;
                }
                ret = -robust_wait(rb->del, rb->mtx, abstime);
        }

        pthread_cleanup_pop(false);

        if (ret != -ETIMEDOUT && ret != -EFLOWDOWN) {
                was_empty = IS_EMPTY(rb);
                HEAD(rb) = (ssize_t) idx;
                ADVANCE_HEAD(rb);
                if (was_empty)
                        pthread_cond_broadcast(rb->add);
        }

        pthread_mutex_unlock(rb->mtx);

 fail_acl:
        return ret;
}

static int check_rb_acl(struct ssm_rbuff * rb)
{
        size_t acl;

        assert(rb != NULL);

        acl = __atomic_load_n(rb->acl, __ATOMIC_SEQ_CST);

        if (acl & ACL_FLOWDOWN)
                return -EFLOWDOWN;

        if (acl & ACL_FLOWPEER)
                return -EFLOWPEER;

        return -EAGAIN;
}

ssize_t ssm_rbuff_read(struct ssm_rbuff * rb)
{
        ssize_t ret;

        assert(rb != NULL);

        if (IS_EMPTY(rb))
                return check_rb_acl(rb);

        robust_mutex_lock(rb->mtx);

        ret = TAIL(rb);
        ADVANCE_TAIL(rb);

        pthread_cond_broadcast(rb->del);

        pthread_mutex_unlock(rb->mtx);

        return ret;
}

ssize_t ssm_rbuff_read_b(struct ssm_rbuff *      rb,
                         const struct timespec * abstime)
{
        ssize_t idx = -1;
        size_t  acl;

        assert(rb != NULL);

        acl = __atomic_load_n(rb->acl, __ATOMIC_SEQ_CST);
        if (IS_EMPTY(rb) && (acl & ACL_FLOWDOWN))
                return -EFLOWDOWN;

        robust_mutex_lock(rb->mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, rb->mtx);

        while (IS_EMPTY(rb) &&
               idx != -ETIMEDOUT &&
               check_rb_acl(rb) == -EAGAIN) {
                idx = -robust_wait(rb->add, rb->mtx, abstime);
        }

        pthread_cleanup_pop(false);

        if (!IS_EMPTY(rb)) {
                idx = TAIL(rb);
                ADVANCE_TAIL(rb);
                pthread_cond_broadcast(rb->del);
        } else if (idx != -ETIMEDOUT) {
                idx = check_rb_acl(rb);
        }

        pthread_mutex_unlock(rb->mtx);

        assert(idx != -EAGAIN);

        return idx;
}

void ssm_rbuff_set_acl(struct ssm_rbuff * rb,
                       uint32_t           flags)
{
        assert(rb != NULL);

        __atomic_store_n(rb->acl, (size_t) flags, __ATOMIC_SEQ_CST);
}

uint32_t ssm_rbuff_get_acl(struct ssm_rbuff * rb)
{
        assert(rb != NULL);

        return (uint32_t) __atomic_load_n(rb->acl, __ATOMIC_SEQ_CST);
}

void ssm_rbuff_fini(struct ssm_rbuff * rb)
{
        assert(rb != NULL);

        robust_mutex_lock(rb->mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, rb->mtx);

        while (!IS_EMPTY(rb))
                robust_wait(rb->del, rb->mtx, NULL);

        pthread_cleanup_pop(true);
}

size_t ssm_rbuff_queued(struct ssm_rbuff * rb)
{
        assert(rb != NULL);

        return QUEUED(rb);
}

int ssm_rbuff_mlock(struct ssm_rbuff * rb)
{
        assert(rb != NULL);

        return mlock(rb->shm_base, SSM_RBUFF_FILESIZE);
}
