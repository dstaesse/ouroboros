/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Random Deletion Ring Buffer for Data Units
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

#include <ouroboros/errno.h>
#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/shm_du_buff.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/pthread.h>

#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <assert.h>

#define SHM_BLOCKS_SIZE ((SHM_BUFFER_SIZE) * SHM_RDRB_BLOCK_SIZE)
#define SHM_FILE_SIZE (SHM_BLOCKS_SIZE + 2 * sizeof(size_t)                    \
                       + sizeof(pthread_mutex_t) + 2 * sizeof(pthread_cond_t)  \
                       + sizeof(pid_t))
#define DU_BUFF_OVERHEAD (DU_BUFF_HEADSPACE + DU_BUFF_TAILSPACE)

#define get_head_ptr(rdrb)                                                     \
        idx_to_du_buff_ptr(rdrb, *rdrb->head)

#define get_tail_ptr(rdrb)                                                     \
        idx_to_du_buff_ptr(rdrb, *rdrb->tail)

#define idx_to_du_buff_ptr(rdrb, idx)                                          \
        ((struct shm_du_buff *) (rdrb->shm_base + idx * SHM_RDRB_BLOCK_SIZE))

#define shm_rdrb_used(rdrb)                                                    \
        (((*rdrb->head + (SHM_BUFFER_SIZE) - *rdrb->tail) + 1)                 \
         & ((SHM_BUFFER_SIZE) - 1))

#define shm_rdrb_free(rdrb, i)                                                 \
        (shm_rdrb_used(rdrb) + i < (SHM_BUFFER_SIZE))

#define shm_rdrb_empty(rdrb)                                                   \
        (*rdrb->tail == *rdrb->head)

struct shm_du_buff {
        size_t size;
#ifdef SHM_RDRB_MULTI_BLOCK
        size_t blocks;
#endif
        size_t du_head;
        size_t du_tail;
        size_t refs;
        size_t idx;
};

struct shm_rdrbuff {
        uint8_t *         shm_base; /* start of blocks */
        size_t *          head;     /* start of ringbuffer head */
        size_t *          tail;     /* start of ringbuffer tail */
        pthread_mutex_t * lock;     /* lock all free space in shm */
        pthread_cond_t *  healthy;  /* flag when packet is read */
        pid_t *           pid;      /* pid of the irmd owner */
};

static void garbage_collect(struct shm_rdrbuff * rdrb)
{
#ifdef SHM_RDRB_MULTI_BLOCK
        struct shm_du_buff * sdb;
        while (!shm_rdrb_empty(rdrb) &&
               (sdb = get_tail_ptr(rdrb))->refs == 0)
                *rdrb->tail = (*rdrb->tail + sdb->blocks)
                        & ((SHM_BUFFER_SIZE) - 1);
#else
        while (!shm_rdrb_empty(rdrb) && get_tail_ptr(rdrb)->refs == 0)
                *rdrb->tail = (*rdrb->tail + 1) & ((SHM_BUFFER_SIZE) - 1);
#endif
        pthread_cond_broadcast(rdrb->healthy);
}

#ifdef HAVE_ROBUST_MUTEX
static void sanitize(struct shm_rdrbuff * rdrb)
{
        --get_head_ptr(rdrb)->refs;
        garbage_collect(rdrb);
        pthread_mutex_consistent(rdrb->lock);
}
#endif

static char * rdrb_filename(void)
{
        char * str;

        str = malloc(strlen(SHM_RDRB_NAME) + 1);
        if (str == NULL)
                return NULL;

        sprintf(str, "%s", SHM_RDRB_NAME);

        return str;
}

void shm_rdrbuff_close(struct shm_rdrbuff * rdrb)
{
        assert(rdrb);

        munmap(rdrb->shm_base, SHM_FILE_SIZE);
        free(rdrb);
}

void shm_rdrbuff_destroy(struct shm_rdrbuff * rdrb)
{
        char * shm_rdrb_fn;

        assert(rdrb);

        if (getpid() != *rdrb->pid && kill(*rdrb->pid, 0) == 0) {
                free(rdrb);
                return;
        }

        shm_rdrbuff_close(rdrb);

        shm_rdrb_fn = rdrb_filename();
        if (shm_rdrb_fn == NULL)
                return;

        shm_unlink(shm_rdrb_fn);
        free(shm_rdrb_fn);
}

#define MM_FLAGS (PROT_READ | PROT_WRITE)

static struct shm_rdrbuff * rdrb_create(int flags)
{
        struct shm_rdrbuff * rdrb;
        int                  fd;
        uint8_t *            shm_base;
        char *               shm_rdrb_fn;

        shm_rdrb_fn = rdrb_filename();
        if (shm_rdrb_fn == NULL)
                goto fail_fn;

        rdrb = malloc(sizeof *rdrb);
        if (rdrb == NULL)
                goto fail_rdrb;

        fd = shm_open(shm_rdrb_fn, flags, 0666);
        if (fd == -1)
                goto fail_open;

        if ((flags & O_CREAT) && ftruncate(fd, SHM_FILE_SIZE - 1) < 0)
                goto fail_truncate;

        shm_base = mmap(NULL, SHM_FILE_SIZE, MM_FLAGS, MAP_SHARED, fd, 0);
        if (shm_base == MAP_FAILED)
                goto fail_truncate;

        close(fd);

        rdrb->shm_base = shm_base;
        rdrb->head = (size_t *) ((uint8_t *) rdrb->shm_base + SHM_BLOCKS_SIZE);
        rdrb->tail = rdrb->head + 1;
        rdrb->lock = (pthread_mutex_t *) (rdrb->tail + 1);
        rdrb->healthy = (pthread_cond_t *) (rdrb->lock + 1);
        rdrb->pid = (pid_t *) (rdrb->healthy + 1);

        free(shm_rdrb_fn);

        return rdrb;

 fail_truncate:
        close(fd);
        if (flags & O_CREAT)
                shm_unlink(shm_rdrb_fn);
 fail_open:
        free(rdrb);
 fail_rdrb:
        free(shm_rdrb_fn);
 fail_fn:
        return NULL;
}

struct shm_rdrbuff * shm_rdrbuff_create()
{
        struct shm_rdrbuff * rdrb;
        mode_t               mask;
        pthread_mutexattr_t  mattr;
        pthread_condattr_t   cattr;

        mask = umask(0);

        rdrb = rdrb_create(O_CREAT | O_EXCL | O_RDWR);

        umask(mask);

        if (rdrb == NULL)
                goto fail_rdrb;

        if (pthread_mutexattr_init(&mattr))
                goto fail_mattr;

        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
#ifdef HAVE_ROBUST_MUTEX
        pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
#endif
        if (pthread_mutex_init(rdrb->lock, &mattr))
                goto fail_mutex;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;

        pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(rdrb->healthy, &cattr))
                goto fail_healthy;

        *rdrb->head = 0;
        *rdrb->tail = 0;

        *rdrb->pid = getpid();

        pthread_mutexattr_destroy(&mattr);
        pthread_condattr_destroy(&cattr);

        return rdrb;

 fail_healthy:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(rdrb->lock);
 fail_mutex:
        pthread_mutexattr_destroy(&mattr);
 fail_mattr:
        shm_rdrbuff_destroy(rdrb);
 fail_rdrb:
        return NULL;
}

struct shm_rdrbuff * shm_rdrbuff_open()
{
        return rdrb_create(O_RDWR);
}

void shm_rdrbuff_purge(void)
{
        char * shm_rdrb_fn;

        shm_rdrb_fn = rdrb_filename();
        if (shm_rdrb_fn == NULL)
                return;

        shm_unlink(shm_rdrb_fn);
        free(shm_rdrb_fn);
}

ssize_t shm_rdrbuff_alloc(struct shm_rdrbuff *  rdrb,
                          size_t                len,
                          uint8_t **            ptr,
                          struct shm_du_buff ** psdb)
{
        struct shm_du_buff * sdb;
        size_t               size = DU_BUFF_OVERHEAD + len;
#ifdef SHM_RDRB_MULTI_BLOCK
        size_t               blocks = 0;
        size_t               padblocks = 0;
#endif
        ssize_t              sz = size + sizeof(*sdb);

        assert(rdrb);
        assert(psdb);

#ifndef SHM_RDRB_MULTI_BLOCK
        if (sz > SHM_RDRB_BLOCK_SIZE)
                return -EMSGSIZE;
#else
        while (sz > 0) {
                sz -= SHM_RDRB_BLOCK_SIZE;
                ++blocks;
        }
#endif
#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD)
                sanitize(rdrb);
#endif
#ifdef SHM_RDRB_MULTI_BLOCK
        if (blocks + *rdrb->head > (SHM_BUFFER_SIZE))
                padblocks = (SHM_BUFFER_SIZE) - *rdrb->head;

        if (!shm_rdrb_free(rdrb, blocks + padblocks)) {
#else
        if (!shm_rdrb_free(rdrb, 1)) {
#endif
                pthread_mutex_unlock(rdrb->lock);
                return -EAGAIN;
        }

#ifdef SHM_RDRB_MULTI_BLOCK
        if (padblocks) {
                sdb = get_head_ptr(rdrb);
                sdb->size    = 0;
                sdb->blocks  = padblocks;
                sdb->refs    = 0;
                sdb->du_head = 0;
                sdb->du_tail = 0;
                sdb->idx     = *rdrb->head;

                *rdrb->head = 0;
        }
#endif
        sdb        = get_head_ptr(rdrb);
        sdb->refs  = 1;
        sdb->idx   = *rdrb->head;
#ifdef SHM_RDRB_MULTI_BLOCK
        sdb->blocks  = blocks;

        *rdrb->head = (*rdrb->head + blocks) & ((SHM_BUFFER_SIZE) - 1);
#else
        *rdrb->head = (*rdrb->head + 1) & ((SHM_BUFFER_SIZE) - 1);
#endif
        pthread_mutex_unlock(rdrb->lock);

        sdb->size    = size;
        sdb->du_head = DU_BUFF_HEADSPACE;
        sdb->du_tail = sdb->du_head + len;

        *psdb = sdb;
        if (ptr != NULL)
                *ptr = (uint8_t *) (sdb + 1) + sdb->du_head;

        return sdb->idx;
}

ssize_t shm_rdrbuff_alloc_b(struct shm_rdrbuff *    rdrb,
                            size_t                  len,
                            uint8_t **              ptr,
                            struct shm_du_buff **   psdb,
                            const struct timespec * abstime)
{
        struct shm_du_buff * sdb;
        size_t               size      = DU_BUFF_OVERHEAD + len;
#ifdef SHM_RDRB_MULTI_BLOCK
        size_t               blocks    = 0;
        size_t               padblocks = 0;
#endif
        ssize_t              sz        = size + sizeof(*sdb);
        int                  ret       = 0;

        assert(rdrb);
        assert(psdb);

#ifndef SHM_RDRB_MULTI_BLOCK
        if (sz > SHM_RDRB_BLOCK_SIZE)
                return -EMSGSIZE;
#else
        while (sz > 0) {
                sz -= SHM_RDRB_BLOCK_SIZE;
                ++blocks;
        }
#endif
#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD)
                sanitize(rdrb);
#endif
        pthread_cleanup_push(__cleanup_mutex_unlock, rdrb->lock);

#ifdef SHM_RDRB_MULTI_BLOCK
        if (blocks + *rdrb->head > (SHM_BUFFER_SIZE))
                padblocks = (SHM_BUFFER_SIZE) - *rdrb->head;

        while (!shm_rdrb_free(rdrb, blocks + padblocks) && ret != ETIMEDOUT) {
#else
        while (!shm_rdrb_free(rdrb, 1) && ret != ETIMEDOUT) {
#endif
                if (abstime != NULL)
                        ret = pthread_cond_timedwait(rdrb->healthy,
                                                     rdrb->lock,
                                                     abstime);
                else
                        ret = pthread_cond_wait(rdrb->healthy, rdrb->lock);

#ifdef SHM_RDRB_MULTI_BLOCK
                if (blocks + *rdrb->head > (SHM_BUFFER_SIZE))
                        padblocks = (SHM_BUFFER_SIZE) - *rdrb->head;
#endif
        }

        if (ret != ETIMEDOUT) {
#ifdef SHM_RDRB_MULTI_BLOCK
                if (padblocks) {
                        sdb = get_head_ptr(rdrb);
                        sdb->size    = 0;
                        sdb->blocks  = padblocks;
                        sdb->refs    = 0;
                        sdb->du_head = 0;
                        sdb->du_tail = 0;
                        sdb->idx     = *rdrb->head;

                        *rdrb->head = 0;
                }
#endif
                sdb        = get_head_ptr(rdrb);
                sdb->refs  = 1;
                sdb->idx   = *rdrb->head;
#ifdef SHM_RDRB_MULTI_BLOCK
                sdb->blocks  = blocks;

                *rdrb->head = (*rdrb->head + blocks) & ((SHM_BUFFER_SIZE) - 1);
#else
                *rdrb->head = (*rdrb->head + 1) & ((SHM_BUFFER_SIZE) - 1);
#endif
        }

        pthread_cleanup_pop(true);

        if (ret == ETIMEDOUT)
                return -ETIMEDOUT;

        sdb->size    = size;
        sdb->du_head = DU_BUFF_HEADSPACE;
        sdb->du_tail = sdb->du_head + len;

        *psdb = sdb;
        if (ptr != NULL)
                *ptr = (uint8_t *) (sdb + 1) + sdb->du_head;

        return sdb->idx;
}

ssize_t shm_rdrbuff_read(uint8_t **           dst,
                         struct shm_rdrbuff * rdrb,
                         size_t               idx)
{
        struct shm_du_buff * sdb;

        assert(dst);
        assert(rdrb);
        assert(idx < (SHM_BUFFER_SIZE));

        sdb = idx_to_du_buff_ptr(rdrb, idx);
        *dst = ((uint8_t *) (sdb + 1)) + sdb->du_head;

        return (ssize_t) (sdb->du_tail - sdb->du_head);
}

struct shm_du_buff * shm_rdrbuff_get(struct shm_rdrbuff * rdrb,
                                     size_t               idx)
{
        assert(rdrb);
        assert(idx < (SHM_BUFFER_SIZE));

        return idx_to_du_buff_ptr(rdrb, idx);
}

int shm_rdrbuff_remove(struct shm_rdrbuff * rdrb,
                       size_t               idx)
{
        struct shm_du_buff * sdb;

        assert(rdrb);
        assert(idx < (SHM_BUFFER_SIZE));

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD)
                sanitize(rdrb);
#endif
        /* assert(!shm_rdrb_empty(rdrb)); */

        sdb = idx_to_du_buff_ptr(rdrb, idx);

        if (sdb->refs == 1) { /* only stack needs it, can be removed */
                sdb->refs = 0;
                if (idx == *rdrb->tail)
                        garbage_collect(rdrb);
        }

        pthread_mutex_unlock(rdrb->lock);

        return 0;
}

size_t shm_du_buff_get_idx(struct shm_du_buff * sdb)
{
        assert(sdb);

        return sdb->idx;
}

uint8_t * shm_du_buff_head(struct shm_du_buff * sdb)
{
        assert(sdb);

        return (uint8_t *) (sdb + 1) + sdb->du_head;
}

uint8_t * shm_du_buff_tail(struct shm_du_buff * sdb)
{
        assert(sdb);

        return (uint8_t *) (sdb + 1) + sdb->du_tail;
}

uint8_t * shm_du_buff_head_alloc(struct shm_du_buff * sdb,
                                 size_t               size)
{
        assert(sdb);

        if (sdb->du_head < size)
                return NULL;

        sdb->du_head -= size;

        return (uint8_t *) (sdb + 1) + sdb->du_head;
}

uint8_t * shm_du_buff_tail_alloc(struct shm_du_buff * sdb,
                                 size_t               size)
{
        uint8_t * buf;

        assert(sdb);

        if (sdb->du_tail + size >= sdb->size)
                return NULL;

        buf = (uint8_t *) (sdb + 1) + sdb->du_tail;

        sdb->du_tail += size;

        return buf;
}

uint8_t * shm_du_buff_head_release(struct shm_du_buff * sdb,
                                   size_t               size)
{
        uint8_t * buf;

        assert(sdb);
        assert(!(size > sdb->du_tail - sdb->du_head));

        buf = (uint8_t *) (sdb + 1) + sdb->du_head;

        sdb->du_head += size;

        return buf;
}

uint8_t * shm_du_buff_tail_release(struct shm_du_buff * sdb,
                                   size_t               size)
{
        assert(sdb);
        assert(!(size > sdb->du_tail - sdb->du_head));

        sdb->du_tail -= size;

        return (uint8_t *) (sdb + 1) + sdb->du_tail;
}

void shm_du_buff_truncate(struct shm_du_buff * sdb,
                          size_t               len)
{
        assert(sdb);
        assert(len <= sdb->size);

        sdb->du_tail = sdb->du_head + len;
}

int shm_du_buff_wait_ack(struct shm_du_buff * sdb)
{
        __sync_add_and_fetch(&sdb->refs, 1);

        return 0;
}

int shm_du_buff_ack(struct shm_du_buff * sdb)
{
        __sync_sub_and_fetch(&sdb->refs, 1);
        return 0;
}
