/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Lockless ring buffer for incoming SDUs
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
#include <ouroboros/shm_rbuff.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/errno.h>

#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <assert.h>
#include <stdbool.h>

#define FN_MAX_CHARS 255
#define RB_OPEN 0
#define RB_CLOSED 1

#define SHM_RBUFF_FILE_SIZE ((SHM_BUFFER_SIZE) * sizeof(ssize_t)        \
                             + 3 * sizeof(size_t)                       \
                             + sizeof(pthread_mutex_t)                  \
                             + 2 * sizeof (pthread_cond_t))

#define RB_HEAD __sync_fetch_and_add(rb->head, 0)
#define RB_TAIL __sync_fetch_and_add(rb->tail, 0)

#define shm_rbuff_used(rb) ((RB_HEAD + (SHM_BUFFER_SIZE) - RB_TAIL)     \
                            & ((SHM_BUFFER_SIZE) - 1))
#define shm_rbuff_free(rb) (shm_rbuff_used(rb) + 1 < (SHM_BUFFER_SIZE))
#define shm_rbuff_empty(rb) (RB_HEAD == RB_TAIL)
#define head_el_ptr(rb) (rb->shm_base + RB_HEAD)
#define tail_el_ptr(rb) (rb->shm_base + RB_TAIL)

struct shm_rbuff {
        ssize_t *         shm_base; /* start of entry                */
        size_t *          head;     /* start of ringbuffer head      */
        size_t *          tail;     /* start of ringbuffer tail      */
        size_t *          acl;      /* access control                */
        pthread_mutex_t * lock;     /* lock all free space in shm    */
        pthread_cond_t *  add;      /* SDU arrived                   */
        pthread_cond_t *  del;      /* SDU removed                   */
        pid_t             api;      /* api of the owner              */
        int               port_id;  /* port_id of the flow           */
};

struct shm_rbuff * shm_rbuff_create(pid_t api, int port_id)
{
        struct shm_rbuff *  rb;
        int                 shm_fd;
        ssize_t *           shm_base;
        pthread_mutexattr_t mattr;
        pthread_condattr_t  cattr;
        char                fn[FN_MAX_CHARS];
        mode_t              mask;

        sprintf(fn, SHM_RBUFF_PREFIX "%d.%d", api, port_id);

        rb = malloc(sizeof(*rb));
        if (rb == NULL)
                return NULL;

        mask = umask(0);

        shm_fd = shm_open(fn, O_CREAT | O_EXCL | O_RDWR, 0666);
        if (shm_fd == -1) {
                free(rb);
                return NULL;
        }

        umask(mask);

        if (ftruncate(shm_fd, SHM_RBUFF_FILE_SIZE - 1) < 0) {
                free(rb);
                close(shm_fd);
                return NULL;
        }

        shm_base = mmap(NULL,
                        SHM_RBUFF_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);

        close(shm_fd);

        if (shm_base == MAP_FAILED) {
                shm_unlink(fn);
                free(rb);
                return NULL;
        }

        rb->shm_base = shm_base;
        rb->head     = (size_t *) (rb->shm_base + (SHM_BUFFER_SIZE));
        rb->tail     = rb->head + 1;
        rb->acl      = rb->tail + 1;
        rb->lock     = (pthread_mutex_t *) (rb->acl + 1);
        rb->add      = (pthread_cond_t *) (rb->lock + 1);
        rb->del      = rb->add + 1;

        pthread_mutexattr_init(&mattr);
#ifdef HAVE_ROBUST_MUTEX
        pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
#endif
        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(rb->lock, &mattr);

        pthread_condattr_init(&cattr);
        pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        pthread_cond_init(rb->add, &cattr);
        pthread_cond_init(rb->del, &cattr);

        *rb->acl = RB_OPEN;
        *rb->head = 0;
        *rb->tail = 0;

        rb->api = api;
        rb->port_id = port_id;

        return rb;
}

struct shm_rbuff * shm_rbuff_open(pid_t api, int port_id)
{
        struct shm_rbuff * rb;
        int                shm_fd;
        ssize_t *          shm_base;
        char               fn[FN_MAX_CHARS];

        sprintf(fn, SHM_RBUFF_PREFIX "%d.%d", api, port_id);

        rb = malloc(sizeof(*rb));
        if (rb == NULL)
                return NULL;

        shm_fd = shm_open(fn, O_RDWR, 0666);
        if (shm_fd == -1) {
                free(rb);
                return NULL;
        }

        shm_base = mmap(NULL,
                        SHM_RBUFF_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);

        close(shm_fd);

        if (shm_base == MAP_FAILED) {
                shm_unlink(fn);
                free(rb);
                return NULL;
        }

        rb->shm_base = shm_base;
        rb->head     = (size_t *) (rb->shm_base + (SHM_BUFFER_SIZE));
        rb->tail     = rb->head + 1;
        rb->acl      = rb->tail + 1;
        rb->lock     = (pthread_mutex_t *) (rb->acl + 1);
        rb->add      = (pthread_cond_t *) (rb->lock + 1);
        rb->del      = rb->add + 1;

        rb->api = api;
        rb->port_id = port_id;

        return rb;
}

void shm_rbuff_close(struct shm_rbuff * rb)
{
        assert(rb);

        munmap(rb->shm_base, SHM_RBUFF_FILE_SIZE);

        free(rb);
}

void shm_rbuff_destroy(struct shm_rbuff * rb)
{
        char fn[FN_MAX_CHARS];

        assert(rb);

        sprintf(fn, SHM_RBUFF_PREFIX "%d.%d", rb->api, rb->port_id);

        munmap(rb->shm_base, SHM_RBUFF_FILE_SIZE);
        shm_unlink(fn);

        free(rb);
}

int shm_rbuff_write(struct shm_rbuff * rb,
                    size_t             idx)
{
        size_t ohead;
        size_t nhead;

        bool was_empty = false;

        assert(rb);
        assert(idx < SHM_BUFFER_SIZE);

        if (__sync_fetch_and_add(rb->acl, 0)) /* CLOSED */
                return -ENOTALLOC;

        if (!shm_rbuff_free(rb))
                return -EAGAIN;

        if (shm_rbuff_empty(rb))
                was_empty = true;

        nhead = RB_HEAD;

        *(rb->shm_base + nhead) = (ssize_t) idx;

        do {
                ohead = nhead;
                nhead = (ohead + 1) & ((SHM_BUFFER_SIZE) - 1);
                nhead = __sync_val_compare_and_swap(rb->head, ohead, nhead);
        } while (nhead != ohead);

        if (was_empty)
                pthread_cond_broadcast(rb->add);

        return 0;
}

ssize_t shm_rbuff_read(struct shm_rbuff * rb)
{
        size_t otail;
        size_t ntail;

        assert(rb);

        if (shm_rbuff_empty(rb))
                return -EAGAIN;

        ntail = RB_TAIL;

        do {
                otail = ntail;
                ntail = (otail + 1) & ((SHM_BUFFER_SIZE) - 1);
                ntail = __sync_val_compare_and_swap(rb->tail, otail, ntail);
        } while (ntail != otail);

        pthread_cond_broadcast(rb->del);

        return *(rb->shm_base + ntail);
}

ssize_t shm_rbuff_read_b(struct shm_rbuff *      rb,
                         const struct timespec * timeout)
{
        struct timespec abstime;
        ssize_t idx = -1;

        assert(rb);

        /* try a non-blocking read first */
        idx = shm_rbuff_read(rb);
        if (idx != -EAGAIN)
                return idx;

        if (timeout != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rb->lock);
#endif
        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) rb->lock);

        while (shm_rbuff_empty(rb) && (idx != -ETIMEDOUT)) {
                if (timeout != NULL)
                        idx = -pthread_cond_timedwait(rb->add,
                                                      rb->lock,
                                                      &abstime);
                else
                        idx = -pthread_cond_wait(rb->add, rb->lock);
#ifdef HAVE_ROBUST_MUTEX
                if (idx == -EOWNERDEAD)
                        pthread_mutex_consistent(rb->lock);
#endif
        }

        if (idx != -ETIMEDOUT) {
                /* do a nonblocking read */
                idx = shm_rbuff_read(rb);

                assert(idx >= 0);
        }

        pthread_cleanup_pop(true);

        return idx;
}

void shm_rbuff_block(struct shm_rbuff * rb)
{
        assert(rb);

        __sync_bool_compare_and_swap(rb->acl, RB_OPEN, RB_CLOSED);
}

void shm_rbuff_unblock(struct shm_rbuff * rb)
{
        assert(rb);

        __sync_bool_compare_and_swap(rb->acl, RB_CLOSED, RB_OPEN);
}

void shm_rbuff_fini(struct shm_rbuff * rb)
{
        assert(rb);

        assert(__sync_fetch_and_add(rb->acl, 0) == RB_CLOSED);

        if (shm_rbuff_empty(rb))
                return;

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rb->lock);
#endif

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) rb->lock);

        while (!shm_rbuff_empty(rb))
#ifndef HAVE_ROBUST_MUTEX
                pthread_cond_wait(rb->del, rb->lock);
#else
                if (pthread_cond_wait(rb->del, rb->lock) == EOWNERDEAD)
                        pthread_mutex_consistent(rb->lock);
#endif
        pthread_cleanup_pop(true);
}

size_t shm_rbuff_queued(struct shm_rbuff * rb)
{
        assert(rb);

        return shm_rbuff_used(rb);
}
