/*
 * Ouroboros - Copyright (C) 2016
 *
 * Ring buffer for application processes
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
#include <ouroboros/shm_ap_rbuff.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/errno.h>

#define OUROBOROS_PREFIX "shm_ap_rbuff"

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

#define FN_MAX_CHARS 255

#define SHM_RBUFF_FILE_SIZE (SHM_BUFFER_SIZE * sizeof(struct rb_entry)         \
                             + IRMD_MAX_FLOWS * sizeof(int8_t)                 \
                             + IRMD_MAX_FLOWS * sizeof (ssize_t)               \
                             + 2 * sizeof(size_t) + sizeof(pthread_mutex_t)    \
                             + 2 * sizeof (pthread_cond_t))

#define shm_rbuff_used(rb)((*rb->head + SHM_BUFFER_SIZE - *rb->tail)   \
                          & (SHM_BUFFER_SIZE - 1))
#define shm_rbuff_free(rb)(shm_rbuff_used(rb) + 1 < SHM_BUFFER_SIZE)
#define shm_rbuff_empty(rb) (*rb->head == *rb->tail)
#define head_el_ptr(rb) (rb->shm_base + *rb->head)
#define tail_el_ptr(rb) (rb->shm_base + *rb->tail)

struct shm_ap_rbuff {
        struct rb_entry * shm_base; /* start of entry                */
        size_t *          head;     /* start of ringbuffer head      */
        size_t *          tail;     /* start of ringbuffer tail      */
        int8_t *          acl;      /* start of port_id access table */
        ssize_t *         cntrs;    /* start of port_id counters     */
        pthread_mutex_t * lock;     /* lock all free space in shm    */
        pthread_cond_t *  add;      /* SDU arrived                   */
        pthread_cond_t *  del;      /* SDU removed                   */
        pid_t             api;      /* api to which this rb belongs  */
        int               fd;
};

struct shm_ap_rbuff * shm_ap_rbuff_create()
{
        struct shm_ap_rbuff * rb;
        int                   shm_fd;
        struct rb_entry *     shm_base;
        pthread_mutexattr_t   mattr;
        pthread_condattr_t    cattr;
        char                  fn[FN_MAX_CHARS];
        mode_t                mask;
        int                   i;

        sprintf(fn, SHM_AP_RBUFF_PREFIX "%d", getpid());

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
                return NULL;
        }
#ifndef __APPLE__
        if (write(shm_fd, "", 1) != 1) {
                LOG_DBG("Failed to finalise extension of ringbuffer.");
                free(rb);
                return NULL;
        }
#endif
        shm_base = mmap(NULL,
                        SHM_RBUFF_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);

        if (shm_base == MAP_FAILED) {
                LOG_DBG("Failed to map shared memory.");
                if (close(shm_fd) == -1)
                        LOG_DBG("Failed to close invalid shm.");

                if (shm_unlink(fn) == -1)
                        LOG_DBG("Failed to remove invalid shm.");

                free(rb);
                return NULL;
        }

        rb->shm_base = shm_base;
        rb->head     = (size_t *) (rb->shm_base + SHM_BUFFER_SIZE);
        rb->tail     = rb->head + 1;
        rb->acl      = (int8_t *) (rb->tail + 1);
        rb->cntrs    = (ssize_t *) (rb->acl + IRMD_MAX_FLOWS);
        rb->lock     = (pthread_mutex_t *) (rb->cntrs + IRMD_MAX_FLOWS);
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
        for (i = 0; i < IRMD_MAX_FLOWS; ++i) {
                rb->cntrs[i] = 0;
                rb->acl[i] = -1;
        }

        pthread_cond_init(rb->add, &cattr);
        pthread_cond_init(rb->del, &cattr);

        *rb->head = 0;
        *rb->tail = 0;

        rb->fd  = shm_fd;
        rb->api = getpid();

        return rb;
}

struct shm_ap_rbuff * shm_ap_rbuff_open(pid_t api)
{
        struct shm_ap_rbuff * rb;
        int                   shm_fd;
        struct rb_entry *     shm_base;
        char                  fn[FN_MAX_CHARS];

        sprintf(fn, SHM_AP_RBUFF_PREFIX "%d", api);

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

        if (shm_base == MAP_FAILED) {
                LOG_DBG("Failed to map shared memory.");
                if (close(shm_fd) == -1)
                        LOG_DBG("Failed to close invalid shm.");

                if (shm_unlink(fn) == -1)
                        LOG_DBG("Failed to remove invalid shm.");

                free(rb);
                return NULL;
        }

        rb->shm_base = shm_base;
        rb->head     = (size_t *) (rb->shm_base + SHM_BUFFER_SIZE);
        rb->tail     = rb->head + 1;
        rb->acl      = (int8_t *) (rb->tail + 1);
        rb->cntrs    = (ssize_t *) (rb->acl + IRMD_MAX_FLOWS);
        rb->lock     = (pthread_mutex_t *) (rb->cntrs + IRMD_MAX_FLOWS);
        rb->add      = (pthread_cond_t *) (rb->lock + 1);
        rb->del      = rb->add + 1;

        rb->fd = shm_fd;
        rb->api = api;

        return rb;
}

void shm_ap_rbuff_close(struct shm_ap_rbuff * rb)
{
        assert(rb);

        if (close(rb->fd) < 0)
                LOG_DBG("Couldn't close shared memory.");

        if (munmap(rb->shm_base, SHM_RBUFF_FILE_SIZE) == -1)
                LOG_DBG("Couldn't unmap shared memory.");

        free(rb);
}

void shm_ap_rbuff_open_port(struct shm_ap_rbuff * rb, int port_id)
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

#ifdef OUROBOROS_CONFIG_DEBUG
        if (!rb->acl[port_id])
                LOG_DBG("Trying to open open port.");
#endif
        rb->acl[port_id] = 0; /* open */

        pthread_mutex_unlock(rb->lock);
}

void shm_ap_rbuff_close_port(struct shm_ap_rbuff * rb, int port_id)
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
#ifdef OUROBOROS_CONFIG_DEBUG
        if (rb->acl[port_id])
                LOG_DBG("Trying to close closed port.");
#endif
        rb->acl[port_id] = -1;

        pthread_mutex_unlock(rb->lock);
}

void shm_ap_rbuff_destroy(struct shm_ap_rbuff * rb)
{
        char fn[25];
        struct lockfile * lf = NULL;

        assert(rb);

        if (rb->api != getpid()) {
                lf = lockfile_open();
                if (lf == NULL)
                        return;
                if (lockfile_owner(lf) == getpid()) {
                        LOG_DBG("Ringbuffer %d destroyed by IRMd %d.",
                                 rb->api, getpid());
                        lockfile_close(lf);
                } else {
                        LOG_ERR("AP-I %d tried to destroy rbuff owned by %d.",
                                getpid(), rb->api);
                        lockfile_close(lf);
                        return;
                }
        }

        if (close(rb->fd) < 0)
                LOG_DBG("Couldn't close shared memory.");

        sprintf(fn, SHM_AP_RBUFF_PREFIX "%d", rb->api);

        if (munmap(rb->shm_base, SHM_RBUFF_FILE_SIZE) == -1)
                LOG_DBG("Couldn't unmap shared memory.");

        if (shm_unlink(fn) == -1)
                LOG_DBG("Failed to unlink shm.");

        free(rb);
}

int shm_ap_rbuff_write(struct shm_ap_rbuff * rb, struct rb_entry * e)
{
        assert(rb);
        assert(e);

#ifdef __APPLE__
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD) {
                LOG_DBG("Recovering dead mutex.");
                pthread_mutex_consistent(rb->lock);
        }
#endif
        if (rb->acl[e->port_id]) {
                pthread_mutex_unlock(rb->lock);
                return -ENOTALLOC;
        }

        if (!shm_rbuff_free(rb)) {
                pthread_mutex_unlock(rb->lock);
                return -1;
        }

        if (shm_rbuff_empty(rb))
                pthread_cond_broadcast(rb->add);

        *head_el_ptr(rb) = *e;
        *rb->head = (*rb->head + 1) & (SHM_BUFFER_SIZE -1);

        ++rb->cntrs[e->port_id];

        pthread_mutex_unlock(rb->lock);

        return 0;
}

int shm_ap_rbuff_pop_idx(struct shm_ap_rbuff * rb)
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

        ret = tail_el_ptr(rb)->index;
        --rb->cntrs[tail_el_ptr(rb)->port_id];
        *rb->tail = (*rb->tail + 1) & (SHM_BUFFER_SIZE -1);

        pthread_mutex_unlock(rb->lock);

        return ret;
}

static int shm_ap_rbuff_peek_b_all(struct shm_ap_rbuff * rb,
                                   const struct timespec * timeout)
{
        struct timespec abstime;
        int ret = 0;

        assert(rb);

        if (timeout != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) rb->lock);
#ifdef __APPLE__
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD) {
                LOG_DBG("Recovering dead mutex.");
                pthread_mutex_consistent(rb->lock);
        }
#endif
        while (shm_rbuff_empty(rb)) {
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
                if (ret == ETIMEDOUT)
                        break;
        }

        if (ret != ETIMEDOUT)
                ret = tail_el_ptr(rb)->port_id;
        else
                ret = -ETIMEDOUT;

        pthread_cleanup_pop(true);

        return ret;
}

int shm_ap_rbuff_peek_b(struct shm_ap_rbuff *   rb,
                        bool *                  set,
                        const struct timespec * timeout)
{
        struct timespec abstime;
        int ret;

        assert(rb);

        if (set == NULL)
                return shm_ap_rbuff_peek_b_all(rb, timeout);

#ifdef __APPLE__
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD) {
                LOG_DBG("Recovering dead mutex.");
                pthread_mutex_consistent(rb->lock);
        }
#endif
        if (timeout != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) rb->lock);

        while ((shm_rbuff_empty(rb) || !set[tail_el_ptr(rb)->port_id])
               && (ret != ETIMEDOUT)) {
                while (shm_rbuff_empty(rb)) {
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
                        if (ret == ETIMEDOUT)
                                break;
                }

                while (!set[tail_el_ptr(rb)->port_id]) {
                        if (timeout != NULL)
                                ret = pthread_cond_timedwait(rb->del,
                                                             rb->lock,
                                                             &abstime);
                        else
                                ret = pthread_cond_wait(rb->del, rb->lock);

#ifndef __APPLE__
                        if (ret == EOWNERDEAD) {
                                LOG_DBG("Recovering dead mutex.");
                                pthread_mutex_consistent(rb->lock);
                        }
#endif
                        if (ret == ETIMEDOUT)
                                break;
                }
        }

        if (ret != ETIMEDOUT)
                ret = tail_el_ptr(rb)->port_id;
        else
                ret = -ETIMEDOUT;

        pthread_cleanup_pop(true);

        return ret;
}


struct rb_entry * shm_ap_rbuff_read(struct shm_ap_rbuff * rb)
{
        struct rb_entry * e = NULL;

        assert(rb);

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) rb->lock);
#ifdef __APPLE__
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD) {
                LOG_DBG("Recovering dead mutex.");
                pthread_mutex_consistent(rb->lock);
        }
#endif
        while (shm_rbuff_empty(rb))
#ifdef __APPLE__
                pthread_cond_wait(rb->add, rb->lock);
#else
                if (pthread_cond_wait(rb->add, rb->lock) == EOWNERDEAD) {
                        LOG_DBG("Recovering dead mutex.");
                        pthread_mutex_consistent(rb->lock);
                }
#endif
        e = malloc(sizeof(*e));
        if (e != NULL) {
                *e = *(rb->shm_base + *rb->tail);
                --rb->cntrs[e->port_id];
                *rb->tail = (*rb->tail + 1) & (SHM_BUFFER_SIZE -1);
        }

        pthread_cleanup_pop(true);

        return e;
}

ssize_t shm_ap_rbuff_read_port(struct shm_ap_rbuff * rb, int port_id)
{
        ssize_t idx = -1;

#ifdef __APPLE__
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD) {
                LOG_DBG("Recovering dead mutex.");
                pthread_mutex_consistent(rb->lock);
        }
#endif
        if (rb->acl[port_id]) {
                pthread_mutex_unlock(rb->lock);
                return -ENOTALLOC;
        }

        if (shm_rbuff_empty(rb) || tail_el_ptr(rb)->port_id != port_id) {
                pthread_mutex_unlock(rb->lock);
                return -1;
        }

        idx = tail_el_ptr(rb)->index;
        --rb->cntrs[port_id];
        *rb->tail = (*rb->tail + 1) & (SHM_BUFFER_SIZE -1);

        pthread_cond_broadcast(rb->del);
        pthread_mutex_unlock(rb->lock);

        return idx;
}

ssize_t shm_ap_rbuff_read_port_b(struct shm_ap_rbuff *   rb,
                                 int                     port_id,
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
        if (rb->acl[port_id]) {
                pthread_mutex_unlock(rb->lock);
                return -ENOTALLOC;
        }

        if (timeout != NULL) {
                idx = -ETIMEDOUT;
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) rb->lock);

        while ((shm_rbuff_empty(rb) || tail_el_ptr(rb)->port_id != port_id)
               && (ret != ETIMEDOUT)) {
                while (shm_rbuff_empty(rb)) {
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
                        if (ret == ETIMEDOUT)
                                break;
                }

                while (tail_el_ptr(rb)->port_id != port_id) {
                        if (timeout != NULL)
                                ret = pthread_cond_timedwait(rb->del,
                                                             rb->lock,
                                                             &abstime);
                        else
                                ret = pthread_cond_wait(rb->del, rb->lock);
#ifndef __APPLE__
                        if (ret == EOWNERDEAD) {
                                LOG_DBG("Recovering dead mutex.");
                                pthread_mutex_consistent(rb->lock);
                        }
#endif
                        if (ret == ETIMEDOUT)
                                break;
                }
        }

        if (ret != ETIMEDOUT) {
                idx = tail_el_ptr(rb)->index;
                  --rb->cntrs[port_id];
                *rb->tail = (*rb->tail + 1) & (SHM_BUFFER_SIZE -1);

                pthread_cond_broadcast(rb->del);
        }

        pthread_cleanup_pop(true);

        return idx;
}

void shm_ap_rbuff_reset(struct shm_ap_rbuff * rb)
{
        assert(rb);

        pthread_mutex_lock(rb->lock);
        *rb->tail = 0;
        *rb->head = 0;
        pthread_mutex_unlock(rb->lock);
}
