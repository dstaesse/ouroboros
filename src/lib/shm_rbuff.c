/*
 * Ouroboros - Copyright (C) 2016
 *
 * Ring buffer for incoming SDUs
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
#include <ouroboros/shm_rbuff.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/errno.h>

#define OUROBOROS_PREFIX "shm_rbuff"

#include <ouroboros/logs.h>

#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <sys/stat.h>
#include <assert.h>
#include <stdbool.h>

#define FN_MAX_CHARS 255

#define SHM_RBUFF_FILE_SIZE (SHM_BUFFER_SIZE * sizeof(ssize_t)          \
                             + 2 * sizeof(size_t) + sizeof(int8_t)      \
                             + sizeof(pthread_mutex_t)                  \
                             + 2 * sizeof (pthread_cond_t))

#define shm_rbuff_used(rb) ((*rb->head + SHM_BUFFER_SIZE - *rb->tail)   \
                            & (SHM_BUFFER_SIZE - 1))
#define shm_rbuff_free(rb) (shm_rbuff_used(rb) + 1 < SHM_BUFFER_SIZE)
#define shm_rbuff_empty(rb) (*rb->head == *rb->tail)
#define head_el_ptr(rb) (rb->shm_base + *rb->head)
#define tail_el_ptr(rb) (rb->shm_base + *rb->tail)

struct shm_rbuff {
        ssize_t *         shm_base; /* start of entry                */
        size_t *          head;     /* start of ringbuffer head      */
        size_t *          tail;     /* start of ringbuffer tail      */
        int8_t *          acl;      /* access control                */
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
        if (rb == NULL) {
                LOG_DBG("Could not allocate struct.");
                return NULL;
        }

        mask = umask(0);

        shm_fd = shm_open(fn, O_CREAT | O_EXCL | O_RDWR, 0666);
        if (shm_fd == -1) {
                LOG_DBG("Failed creating ring buffer.");
                free(rb);
                return NULL;
        }

        umask(mask);

        if (ftruncate(shm_fd, SHM_RBUFF_FILE_SIZE - 1) < 0) {
                LOG_DBG("Failed to extend ringbuffer.");
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
                LOG_DBG("Failed to map shared memory.");
                if (shm_unlink(fn) == -1)
                        LOG_DBG("Failed to remove invalid shm.");
                free(rb);
                return NULL;
        }

        rb->shm_base = shm_base;
        rb->head     = (size_t *) (rb->shm_base + SHM_BUFFER_SIZE);
        rb->tail     = rb->head + 1;
        rb->acl      = (int8_t *) (rb->tail + 1);
        rb->lock     = (pthread_mutex_t *) (rb->acl + 1);
        rb->add      = (pthread_cond_t *) (rb->lock + 1);
        rb->del      = rb->add + 1;

        pthread_mutexattr_init(&mattr);
#ifndef __APPLE__
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

        *rb->acl = 0;
        *rb->head = 0;
        *rb->tail = 0;

        rb->api = api;
        rb->port_id = port_id;

        if (munmap(rb->shm_base, SHM_RBUFF_FILE_SIZE) == -1)
                LOG_DBG("Couldn't unmap shared memory.");

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
        if (rb == NULL) {
                LOG_DBG("Could not allocate struct.");
                return NULL;
        }

        shm_fd = shm_open(fn, O_RDWR, 0666);
        if (shm_fd == -1) {
                LOG_DBG("%d failed opening shared memory %s.", getpid(), fn);
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
                LOG_DBG("Failed to map shared memory.");
                if (shm_unlink(fn) == -1)
                        LOG_DBG("Failed to remove invalid shm.");

                free(rb);
                return NULL;
        }

        rb->shm_base = shm_base;
        rb->head     = (size_t *) (rb->shm_base + SHM_BUFFER_SIZE);
        rb->tail     = rb->head + 1;
        rb->acl      = (int8_t *) (rb->tail + 1);
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

        if (munmap(rb->shm_base, SHM_RBUFF_FILE_SIZE) == -1)
                LOG_DBG("Couldn't unmap shared memory.");

        free(rb);
}

void shm_rbuff_destroy(struct shm_rbuff * rb)
{
        char fn[25];

        if (rb == NULL)
                return;

        sprintf(fn, SHM_RBUFF_PREFIX "%d.%d", rb->api, rb->port_id);

        if (shm_unlink(fn) == -1)
                LOG_DBG("Failed to unlink shm %s.", fn);

        free(rb);
}

int shm_rbuff_write(struct shm_rbuff * rb, ssize_t idx)
{
        assert(rb);
        assert(idx >= 0);

#ifdef __APPLE__
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD) {
                LOG_DBG("Recovering dead mutex.");
                pthread_mutex_consistent(rb->lock);
        }
#endif
        if (*rb->acl) {
                pthread_mutex_unlock(rb->lock);
                return -ENOTALLOC;
        }

        if (!shm_rbuff_free(rb)) {
                pthread_mutex_unlock(rb->lock);
                return -1;
        }

        if (shm_rbuff_empty(rb))
                pthread_cond_broadcast(rb->add);

        *head_el_ptr(rb) = idx;
        *rb->head = (*rb->head + 1) & (SHM_BUFFER_SIZE -1);

        pthread_mutex_unlock(rb->lock);

        return 0;
}

ssize_t shm_rbuff_read(struct shm_rbuff * rb)
{
        int ret = 0;

        assert(rb);

#ifdef __APPLE__
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD) {
                LOG_DBG("Recovering dead mutex.");
                pthread_mutex_consistent(rb->lock);
        }
#endif
        if (shm_rbuff_empty(rb)) {
                pthread_mutex_unlock(rb->lock);
                return -1;
        }

        ret = *tail_el_ptr(rb);
        *rb->tail = (*rb->tail + 1) & (SHM_BUFFER_SIZE -1);

        pthread_mutex_unlock(rb->lock);

        return ret;
}

ssize_t shm_rbuff_read_b(struct shm_rbuff *      rb,
                         const struct timespec * timeout)
{
        struct timespec abstime;
        int ret = 0;
        ssize_t idx = -1;

        assert(rb);

#ifdef __APPLE__
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD) {
                LOG_DBG("Recovering dead mutex.");
                pthread_mutex_consistent(rb->lock);
        }
#endif
        if (timeout != NULL) {
                idx = -ETIMEDOUT;
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) rb->lock);

        while (shm_rbuff_empty(rb) && (ret != ETIMEDOUT)) {
                if (timeout != NULL)
                        ret = pthread_cond_timedwait(rb->add,
                                                     rb->lock,
                                                     &abstime);
                else
                        ret = pthread_cond_wait(rb->add, rb->lock);
#ifndef __APPLE__
                if (ret == EOWNERDEAD) {
                        LOG_DBG("Recovering dead mutex.");
                        pthread_mutex_consistent(rb->lock);
                }
#endif
                if (ret == ETIMEDOUT) {
                        idx = -ETIMEDOUT;
                        break;
                }
        }

        if (idx != -ETIMEDOUT) {
                idx = *tail_el_ptr(rb);
                *rb->tail = (*rb->tail + 1) & (SHM_BUFFER_SIZE -1);
                pthread_cond_broadcast(rb->del);
        }

        pthread_cleanup_pop(true);

        return idx;
}

int shm_rbuff_block(struct shm_rbuff * rb)
{
        int ret = 0;

        assert(rb);

#ifdef __APPLE__
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD) {
                LOG_DBG("Recovering dead mutex.");
                pthread_mutex_consistent(rb->lock);
        }
#endif
        *rb->acl = -1;

        if (!shm_rbuff_empty(rb))
                ret = -EBUSY;

        pthread_mutex_unlock(rb->lock);

        return ret;
}

void shm_rbuff_unblock(struct shm_rbuff * rb)
{
        assert(rb);

#ifdef __APPLE__
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD) {
                LOG_DBG("Recovering dead mutex.");
                pthread_mutex_consistent(rb->lock);
        }
#endif
        *rb->acl = 0; /* open */

        pthread_mutex_unlock(rb->lock);
}

void shm_rbuff_reset(struct shm_rbuff * rb)
{
        assert(rb);

        pthread_mutex_lock(rb->lock);
        *rb->tail = 0;
        *rb->head = 0;
        pthread_mutex_unlock(rb->lock);
}
