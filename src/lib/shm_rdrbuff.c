/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Random Deletion Ring Buffer for Data Units
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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
#include <ouroboros/errno.h>
#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/time_utils.h>

#include <pthread.h>
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

#ifndef SHM_RDRB_MULTI_BLOCK
#define WAIT_BLOCKS 1
#else
#define WAIT_BLOCKS ((SHM_BUFFER_SIZE) >> 4)
#if WAIT_BLOCKS == 0
#undef WAIT_BLOCKS
#define WAIT_BLOCKS 1
#endif
#endif

#define get_head_ptr(rdrb)                                                     \
        ((struct shm_du_buff *) (rdrb->shm_base + (*rdrb->head                 \
                                                   * SHM_RDRB_BLOCK_SIZE)))

#define get_tail_ptr(rdrb)                                                     \
        ((struct shm_du_buff *) (rdrb->shm_base + (*rdrb->tail                 \
                                                   * SHM_RDRB_BLOCK_SIZE)))

#define idx_to_du_buff_ptr(rdrb, idx)                                          \
        ((struct shm_du_buff *) (rdrb->shm_base + idx * SHM_RDRB_BLOCK_SIZE))

#define block_ptr_to_idx(rdrb, sdb)                                            \
        (((uint8_t *)sdb - rdrb->shm_base) / SHM_RDRB_BLOCK_SIZE)

#define shm_rdrb_used(rdrb)                                                    \
        ((*rdrb->head + (SHM_BUFFER_SIZE) - *rdrb->tail)                       \
         & ((SHM_BUFFER_SIZE) - 1))

#define shm_rdrb_free(rdrb, i)                                                 \
        (shm_rdrb_used(rdrb) + i < (SHM_BUFFER_SIZE))

#define shm_rdrb_empty(rdrb)                                                   \
        (*rdrb->tail == *rdrb->head)

enum shm_du_buff_flags {
        SDB_VALID = 0,
        SDB_NULL
};

struct shm_du_buff {
        size_t size;
#ifdef SHM_RDRB_MULTI_BLOCK
        size_t blocks;
#endif
        size_t du_head;
        size_t du_tail;
        size_t flags;
        size_t idx;
};

struct shm_rdrbuff {
        uint8_t *         shm_base; /* start of blocks */
        size_t *          head;     /* start of ringbuffer head */
        size_t *          tail;     /* start of ringbuffer tail */
        pthread_mutex_t * lock;     /* lock all free space in shm */
        pthread_cond_t *  full;     /* flag when full */
        pthread_cond_t *  healthy;  /* flag when SDU is read */
        pid_t *           api;      /* api of the irmd owner */
};

static void garbage_collect(struct shm_rdrbuff * rdrb)
{
#ifdef SHM_RDRB_MULTI_BLOCK
        struct shm_du_buff * sdb;
        while (!shm_rdrb_empty(rdrb) &&
               (sdb = get_tail_ptr(rdrb))->flags == SDB_NULL)
                *rdrb->tail = (*rdrb->tail + sdb->blocks)
                        & ((SHM_BUFFER_SIZE) - 1);
#else
        while (!shm_rdrb_empty(rdrb) && get_tail_ptr(rdrb)->flags == SDB_NULL)
                *rdrb->tail = (*rdrb->tail + 1) & ((SHM_BUFFER_SIZE) - 1);
#endif
        pthread_cond_broadcast(rdrb->healthy);
}

static char * rdrb_filename(void)
{
        char * str;

        str = malloc(strlen(SHM_RDRB_PREFIX) + 1);
        if (str == NULL)
                return NULL;

        sprintf(str, "%s", SHM_RDRB_PREFIX);

        return str;
}

struct shm_rdrbuff * shm_rdrbuff_create()
{
        struct shm_rdrbuff * rdrb;
        mode_t               mask;
        int                  shm_fd;
        uint8_t *            shm_base;
        pthread_mutexattr_t  mattr;
        pthread_condattr_t   cattr;
        char *               shm_rdrb_fn = rdrb_filename();
        if (shm_rdrb_fn == NULL)
                return NULL;

        rdrb = malloc(sizeof *rdrb);
        if (rdrb == NULL)
                return NULL;

        mask = umask(0);

        shm_fd = shm_open(shm_rdrb_fn, O_CREAT | O_EXCL | O_RDWR, 0666);
        if (shm_fd == -1) {
                free(shm_rdrb_fn);
                free(rdrb);
                return NULL;
        }

        umask(mask);

        if (ftruncate(shm_fd, SHM_FILE_SIZE - 1) < 0) {
                free(shm_rdrb_fn);
                close(shm_fd);
                free(rdrb);
                return NULL;
        }

        shm_base = mmap(NULL,
                        SHM_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);

        close(shm_fd);

        if (shm_base == MAP_FAILED) {
                shm_unlink(shm_rdrb_fn);
                free(shm_rdrb_fn);
                free(rdrb);
                return NULL;
        }

        rdrb->shm_base = shm_base;
        rdrb->head = (size_t *) ((uint8_t *) rdrb->shm_base + SHM_BLOCKS_SIZE);
        rdrb->tail = rdrb->head + 1;
        rdrb->lock = (pthread_mutex_t *) (rdrb->tail + 1);
        rdrb->full = (pthread_cond_t *) (rdrb->lock + 1);
        rdrb->healthy = rdrb->full + 1;
        rdrb->api = (pid_t *) (rdrb->healthy + 1);

        pthread_mutexattr_init(&mattr);
        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
#ifndef __APPLE__
        pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
#endif
        pthread_mutex_init(rdrb->lock, &mattr);

        pthread_condattr_init(&cattr);
        pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        pthread_cond_init(rdrb->full, &cattr);
        pthread_cond_init(rdrb->healthy, &cattr);

        *rdrb->head = 0;
        *rdrb->tail = 0;

        *rdrb->api = getpid();

        free(shm_rdrb_fn);

        return rdrb;
}

struct shm_rdrbuff * shm_rdrbuff_open()
{
        struct shm_rdrbuff * rdrb;
        int                  shm_fd;
        uint8_t *            shm_base;
        char *               shm_rdrb_fn = rdrb_filename();
        if (shm_rdrb_fn == NULL)
                return NULL;

        rdrb = malloc(sizeof *rdrb);
        if (rdrb == NULL)
                return NULL;

        shm_fd = shm_open(shm_rdrb_fn, O_RDWR, 0666);
        if (shm_fd < 0) {
                free(shm_rdrb_fn);
                free(rdrb);
                return NULL;
        }

        shm_base = mmap(NULL,
                        SHM_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);

        close(shm_fd);

        if (shm_base == MAP_FAILED) {
                shm_unlink(shm_rdrb_fn);
                free(shm_rdrb_fn);
                free(rdrb);
                return NULL;
        }

        rdrb->shm_base = shm_base;
        rdrb->head = (size_t *) ((uint8_t *) rdrb->shm_base + SHM_BLOCKS_SIZE);
        rdrb->tail = rdrb->head + 1;
        rdrb->lock = (pthread_mutex_t *) (rdrb->tail + 1);
        rdrb->full = (pthread_cond_t *) (rdrb->lock + 1);
        rdrb->healthy = rdrb->full + 1;
        rdrb->api = (pid_t *) (rdrb->healthy + 1);

        free(shm_rdrb_fn);

        return rdrb;
}

void shm_rdrbuff_wait_full(struct shm_rdrbuff * rdrb)
{

#ifdef __APPLE__
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rdrb->lock);
#endif
        pthread_cleanup_push((void (*)(void *)) pthread_mutex_unlock,
                             (void *) rdrb->lock);

        while (shm_rdrb_free(rdrb, WAIT_BLOCKS)) {
#ifdef __APPLE__
                pthread_cond_wait(rdrb->full, rdrb->lock);
#else
                if (pthread_cond_wait(rdrb->full, rdrb->lock) == EOWNERDEAD)
                        pthread_mutex_consistent(rdrb->lock);
#endif
        }

        garbage_collect(rdrb);

        pthread_cleanup_pop(true);
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

        if (getpid() != *rdrb->api && kill(*rdrb->api, 0) == 0)
                return;

        munmap(rdrb->shm_base, SHM_FILE_SIZE);

        shm_rdrb_fn = rdrb_filename();
        if (shm_rdrb_fn == NULL)
                return;

        shm_unlink(shm_rdrb_fn);

        free(rdrb);
        free(shm_rdrb_fn);
}

ssize_t shm_rdrbuff_write(struct shm_rdrbuff * rdrb,
                          size_t               headspace,
                          size_t               tailspace,
                          const uint8_t *      data,
                          size_t               len)
{
        struct shm_du_buff * sdb;
        size_t               size = headspace + len + tailspace;
#ifdef SHM_RDRB_MULTI_BLOCK
        size_t               blocks = 0;
        size_t               padblocks = 0;
#endif
        ssize_t              sz = size + sizeof(*sdb);

        assert(rdrb);
        assert(data);

#ifndef SHM_RDRB_MULTI_BLOCK
        if (sz > SHM_RDRB_BLOCK_SIZE)
                return -EMSGSIZE;
#endif
#ifdef __APPLE__
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rdrb->lock);
#endif
#ifdef SHM_RDRB_MULTI_BLOCK
        while (sz > 0) {
                sz -= SHM_RDRB_BLOCK_SIZE;
                ++blocks;
        }

        if (blocks + *rdrb->head > (SHM_BUFFER_SIZE))
                padblocks = (SHM_BUFFER_SIZE) - *rdrb->head;

        if (!shm_rdrb_free(rdrb, blocks + padblocks)) {
#else
        if (!shm_rdrb_free(rdrb, 1)) {
#endif
                pthread_cond_broadcast(rdrb->full);
                pthread_mutex_unlock(rdrb->lock);
                return -EAGAIN;
        }

#ifdef SHM_RDRB_MULTI_BLOCK
        if (padblocks) {
                sdb = get_head_ptr(rdrb);
                sdb->size    = 0;
                sdb->blocks  = padblocks;
                sdb->flags   = SDB_NULL;
                sdb->du_head = 0;
                sdb->du_tail = 0;
                sdb->idx     = *rdrb->head;

                *rdrb->head = 0;
        }
#endif
        sdb          = get_head_ptr(rdrb);
        sdb->size    = size;
        sdb->flags   = SDB_VALID;
        sdb->du_head = headspace;
        sdb->du_tail = sdb->du_head + len;
#ifdef  SHM_RDRB_MULTI_BLOCK
        sdb->blocks  = blocks;
#endif
        memcpy(((uint8_t *) (sdb + 1)) + headspace, data, len);

        sdb->idx = *rdrb->head;
#ifdef SHM_RDRB_MULTI_BLOCK
        *rdrb->head = (*rdrb->head + blocks) & ((SHM_BUFFER_SIZE) - 1);
#else
        *rdrb->head = (*rdrb->head + 1) & ((SHM_BUFFER_SIZE) - 1);
#endif
        pthread_mutex_unlock(rdrb->lock);

        return sdb->idx;
}

ssize_t shm_rdrbuff_write_b(struct shm_rdrbuff * rdrb,
                            size_t               headspace,
                            size_t               tailspace,
                            const uint8_t *      data,
                            size_t               len)
{
        struct shm_du_buff * sdb;
        size_t               size = headspace + len + tailspace;
#ifdef SHM_RDRB_MULTI_BLOCK
        size_t               blocks = 0;
        size_t               padblocks = 0;
#endif
        ssize_t              sz = size + sizeof(*sdb);

        assert(rdrb);
        assert(data);

#ifndef SHM_RDRB_MULTI_BLOCK
        if (sz > SHM_RDRB_BLOCK_SIZE)
                return -EMSGSIZE;
#endif
#ifdef __APPLE__
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rdrb->lock);
#endif
        pthread_cleanup_push((void (*) (void *)) pthread_mutex_unlock,
                             (void *) rdrb->lock);

#ifdef SHM_RDRB_MULTI_BLOCK
        while (sz > 0) {
                sz -= SHM_RDRB_BLOCK_SIZE;
                ++blocks;
        }

        if (blocks + *rdrb->head > (SHM_BUFFER_SIZE))
                padblocks = (SHM_BUFFER_SIZE) - *rdrb->head;

        while (!shm_rdrb_free(rdrb, (blocks + padblocks))) {
#else
        while (!shm_rdrb_free(rdrb, 1)) {
#endif
                pthread_cond_broadcast(rdrb->full);
                pthread_cond_wait(rdrb->healthy, rdrb->lock);
        }

#ifdef SHM_RDRB_MULTI_BLOCK
        if (padblocks) {
                sdb = get_head_ptr(rdrb);
                sdb->size    = 0;
                sdb->blocks  = padblocks;
                sdb->flags   = SDB_NULL;
                sdb->du_head = 0;
                sdb->du_tail = 0;
                sdb->idx     = *rdrb->head;

                *rdrb->head = 0;
        }
#endif
        sdb          = get_head_ptr(rdrb);
        sdb->size    = size;
        sdb->flags   = SDB_VALID;
        sdb->du_head = headspace;
        sdb->du_tail = sdb->du_head + len;
#ifdef  SHM_RDRB_MULTI_BLOCK
        sdb->blocks  = blocks;
#endif
        memcpy(((uint8_t *) (sdb + 1)) + headspace, data, len);

        sdb->idx = *rdrb->head;
#ifdef SHM_RDRB_MULTI_BLOCK
        *rdrb->head = (*rdrb->head + blocks) & ((SHM_BUFFER_SIZE) - 1);
#else
        *rdrb->head = (*rdrb->head + 1) & ((SHM_BUFFER_SIZE) - 1);
#endif
        pthread_cleanup_pop(true);

        return sdb->idx;
}

ssize_t shm_rdrbuff_read(uint8_t **           dst,
                         struct shm_rdrbuff * rdrb,
                         size_t               idx)
{
        ssize_t len = 0;
        struct shm_du_buff * sdb;

        assert(dst);
        assert(rdrb);
        assert(idx < (SHM_BUFFER_SIZE));

#ifdef __APPLE__
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rdrb->lock);
#endif
        if (shm_rdrb_empty(rdrb)) {
                pthread_mutex_unlock(rdrb->lock);
                return -1;
        }

        sdb = idx_to_du_buff_ptr(rdrb, idx);
        len = (ssize_t) (sdb->du_tail - sdb->du_head);
        *dst = ((uint8_t *) (sdb + 1)) + sdb->du_head;

        pthread_mutex_unlock(rdrb->lock);

        return len;
}

struct shm_du_buff * shm_rdrbuff_get(struct shm_rdrbuff * rdrb, size_t idx)
{
        struct shm_du_buff * sdb;

        assert(rdrb);
        assert(idx < (SHM_BUFFER_SIZE));

#ifdef __APPLE__
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rdrb->lock);
#endif
        if (shm_rdrb_empty(rdrb)) {
                pthread_mutex_unlock(rdrb->lock);
                return NULL;
        }

        sdb = idx_to_du_buff_ptr(rdrb, idx);

        pthread_mutex_unlock(rdrb->lock);

        return sdb;
}

int shm_rdrbuff_remove(struct shm_rdrbuff * rdrb, size_t idx)
{
        assert(rdrb);
        assert(idx < (SHM_BUFFER_SIZE));

#ifdef __APPLE__
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rdrb->lock);
#endif
        if (shm_rdrb_empty(rdrb)) {
                pthread_mutex_unlock(rdrb->lock);
                return -1;
        }

        idx_to_du_buff_ptr(rdrb, idx)->flags = SDB_NULL;

        if (idx != *rdrb->tail) {
                pthread_mutex_unlock(rdrb->lock);
                return 0;
        }

        garbage_collect(rdrb);

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
        uint8_t * buf = NULL;

        assert(sdb);

        if (sdb->du_head < size)
                return NULL;

        sdb->du_head -= size;

        buf = (uint8_t *) (sdb + 1) + sdb->du_head;

        return buf;
}

uint8_t * shm_du_buff_tail_alloc(struct shm_du_buff * sdb,
                                 size_t               size)
{
        uint8_t * buf = NULL;

        assert(sdb);

        if (sdb->du_tail + size >= sdb->size)
                return NULL;

        buf = (uint8_t *) (sdb + 1) + sdb->du_tail;

        sdb->du_tail += size;

        return buf;
}

void shm_du_buff_head_release(struct shm_du_buff * sdb,
                              size_t               size)
{
        assert(sdb);
        assert(!(size > sdb->du_tail - sdb->du_head));

        sdb->du_head += size;
}

void shm_du_buff_tail_release(struct shm_du_buff * sdb,
                              size_t               size)
{
        assert(sdb);
        assert(!(size > sdb->du_tail - sdb->du_head));

        sdb->du_tail -= size;
}
