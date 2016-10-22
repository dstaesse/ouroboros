/*
 * Ouroboros - Copyright (C) 2016
 *
 * Random Deletion Ring Buffer for Data Units
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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
#include <ouroboros/errno.h>
#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/time_utils.h>

#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <assert.h>

#define OUROBOROS_PREFIX "shm_rdrbuff"

#include <ouroboros/logs.h>

#define SHM_BLOCKS_SIZE ((SHM_BUFFER_SIZE) * SHM_RDRB_BLOCK_SIZE)
#define SHM_FILE_SIZE (SHM_BLOCKS_SIZE + 3 * sizeof(size_t)                    \
                       + sizeof(pthread_mutex_t) + 2 * sizeof(pthread_cond_t)  \
                       + sizeof(pid_t))

#define get_head_ptr(rdrb)                                                     \
        ((struct shm_du_buff *) (rdrb->shm_base + (*rdrb->ptr_head             \
                                                   * SHM_RDRB_BLOCK_SIZE)))

#define get_tail_ptr(rdrb)                                                     \
        ((struct shm_du_buff *) (rdrb->shm_base + (*rdrb->ptr_tail             \
                                                   * SHM_RDRB_BLOCK_SIZE)))

#define idx_to_du_buff_ptr(rdrb, idx)                                          \
        ((struct shm_du_buff *) (rdrb->shm_base + idx * SHM_RDRB_BLOCK_SIZE))

#define block_ptr_to_idx(rdrb, sdb)                                            \
        (((uint8_t *)sdb - rdrb->shm_base) / SHM_RDRB_BLOCK_SIZE)

#define shm_rdrb_used(rdrb)                                                    \
        ((*rdrb->ptr_head + (SHM_BUFFER_SIZE) - *rdrb->ptr_tail)               \
         & ((SHM_BUFFER_SIZE) - 1))
#define shm_rdrb_free(rdrb, i)                                                 \
        (shm_rdrb_used(rdrb) + i < (SHM_BUFFER_SIZE))

#define shm_rdrb_empty(rdrb)                                                   \
        (*rdrb->ptr_tail == *rdrb->ptr_head)

struct shm_du_buff {
        size_t size;
#ifdef SHM_RDRB_MULTI_BLOCK
        size_t blocks;
#endif
        size_t du_head;
        size_t du_tail;
        pid_t  dst_api;
        size_t idx;
};

struct shm_rdrbuff {
        uint8_t *         shm_base;    /* start of blocks */
        size_t *          ptr_head;    /* start of ringbuffer head */
        size_t *          ptr_tail;    /* start of ringbuffer tail */
        pthread_mutex_t * lock;        /* lock all free space in shm */
        size_t *          choked;      /* stale sdu detection */
        pthread_cond_t *  healthy;     /* du map is healthy */
        pthread_cond_t *  full;        /* run sanitizer when buffer full */
        pid_t *           api;         /* api of the irmd owner */
        enum qos_cube     qos;         /* qos id which this buffer serves */
};

static void garbage_collect(struct shm_rdrbuff * rdrb)
{
#ifdef SHM_RDRB_MULTI_BLOCK
        struct shm_du_buff * sdb;
        while (!shm_rdrb_empty(rdrb) &&
               (sdb = get_tail_ptr(rdrb))->dst_api == -1)
                *rdrb->ptr_tail = (*rdrb->ptr_tail + sdb->blocks)
                        & ((SHM_BUFFER_SIZE) - 1);
#else
        while (!shm_rdrb_empty(rdrb) && get_tail_ptr(rdrb)->dst_api == -1)
                *rdrb->ptr_tail =
                        (*rdrb->ptr_tail + 1) & ((SHM_BUFFER_SIZE) - 1);

#endif
}

static void clean_sdus(struct shm_rdrbuff * rdrb, pid_t api)
{
        size_t idx = *rdrb->ptr_tail;
        struct shm_du_buff * buf;

        while (idx != *rdrb->ptr_head) {
                buf = idx_to_du_buff_ptr(rdrb, idx);
                if (buf->dst_api == api)
                        buf->dst_api = -1;
#ifdef SHM_RDRB_MULTI_BLOCK
                idx = (idx + buf->blocks) & ((SHM_BUFFER_SIZE) - 1);
#else
                idx = (idx + 1) & ((SHM_BUFFER_SIZE) - 1);
#endif
        }

        garbage_collect(rdrb);

        *rdrb->choked = 0;
}

static char * rdrb_filename(enum qos_cube qos)
{
        size_t chars = 0;
        char * str;
        int qm = QOS_MAX;

        do {
                qm /= 10;
                ++chars;
        } while (qm > 0);

        str = malloc(strlen(SHM_RDRB_PREFIX) + chars + 1);
        if (str == NULL) {
                LOG_ERR("Failed to create shm_rdrbuff: Out of Memory.");
                return NULL;
        }

        sprintf(str, "%s%d", SHM_RDRB_PREFIX, (int) qos);

        return str;
}

/* FIXME: create a ringbuffer for each qos cube in the system */
struct shm_rdrbuff * shm_rdrbuff_create()
{
        struct shm_rdrbuff * rdrb;
        mode_t               mask;
        int                  shm_fd;
        uint8_t *            shm_base;
        pthread_mutexattr_t  mattr;
        pthread_condattr_t   cattr;
        enum qos_cube        qos = QOS_CUBE_BE;
        char *               shm_rdrb_fn = rdrb_filename(qos);
        if (shm_rdrb_fn == NULL) {
                LOG_ERR("Could not create rdrbuff. Out of Memory");
                return NULL;
        }

        rdrb = malloc(sizeof *rdrb);
        if (rdrb == NULL) {
                LOG_DBGF("Could not allocate struct.");
                return NULL;
        }

        mask = umask(0);

        shm_fd = shm_open(shm_rdrb_fn, O_CREAT | O_EXCL | O_RDWR, 0666);
        if (shm_fd == -1) {
                LOG_DBGF("Failed creating shared memory map.");
                free(shm_rdrb_fn);
                free(rdrb);
                return NULL;
        }

        umask(mask);

        if (ftruncate(shm_fd, SHM_FILE_SIZE - 1) < 0) {
                LOG_DBGF("Failed to extend shared memory map.");
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
                LOG_DBGF("Failed to map shared memory.");
                if (shm_unlink(shm_rdrb_fn) == -1)
                        LOG_DBGF("Failed to remove invalid shm.");
                free(shm_rdrb_fn);
                free(rdrb);
                return NULL;
        }

        rdrb->shm_base = shm_base;
        rdrb->ptr_head = (size_t *)
                ((uint8_t *) rdrb->shm_base + SHM_BLOCKS_SIZE);
        rdrb->ptr_tail = rdrb->ptr_head + 1;
        rdrb->lock = (pthread_mutex_t *) (rdrb->ptr_tail + 1);
        rdrb->choked = (size_t *) (rdrb->lock + 1);
        rdrb->healthy = (pthread_cond_t *) (rdrb->choked + 1);
        rdrb->full = rdrb->healthy + 1;
        rdrb->api = (pid_t *) (rdrb->full + 1);

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

        *rdrb->ptr_head = 0;
        *rdrb->ptr_tail = 0;

        *rdrb->choked = 0;

        *rdrb->api = getpid();

        rdrb->qos = qos;

        free(shm_rdrb_fn);

        return rdrb;
}

/* FIXME: open a ringbuffer for each qos cube in the system */
struct shm_rdrbuff * shm_rdrbuff_open()
{
        struct shm_rdrbuff * rdrb;
        int                  shm_fd;
        uint8_t *            shm_base;

        enum qos_cube        qos = QOS_CUBE_BE;
        char *               shm_rdrb_fn = rdrb_filename(qos);
        if (shm_rdrb_fn == NULL) {
                LOG_ERR("Could not create rdrbuff. Out of Memory");
                return NULL;
        }

        rdrb = malloc(sizeof *rdrb);
        if (rdrb == NULL) {
                LOG_DBGF("Could not allocate struct.");
                return NULL;
        }

        shm_fd = shm_open(shm_rdrb_fn, O_RDWR, 0666);
        if (shm_fd < 0) {
                LOG_DBGF("Failed opening shared memory.");
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
                LOG_DBGF("Failed to map shared memory.");
                if (shm_unlink(shm_rdrb_fn) == -1)
                        LOG_DBG("Failed to unlink invalid shm.");
                free(shm_rdrb_fn);
                free(rdrb);
                return NULL;
        }

        rdrb->shm_base = shm_base;
        rdrb->ptr_head = (size_t *)
                ((uint8_t *) rdrb->shm_base + SHM_BLOCKS_SIZE);
        rdrb->ptr_tail = rdrb->ptr_head + 1;
        rdrb->lock = (pthread_mutex_t *) (rdrb->ptr_tail + 1);
        rdrb->choked = (size_t *) (rdrb->lock + 1);
        rdrb->healthy = (pthread_cond_t *) (rdrb->choked + 1);
        rdrb->full = rdrb->healthy + 1;
        rdrb->api = (pid_t *) (rdrb->full + 1);

        rdrb->qos = qos;

        free(shm_rdrb_fn);

        return rdrb;
}

void * shm_rdrbuff_sanitize(void * o)
{
        struct shm_rdrbuff * rdrb = (struct shm_rdrbuff *) o;
        struct timespec intv
                = {SHM_DU_TIMEOUT_MICROS / MILLION,
                   (SHM_DU_TIMEOUT_MICROS % MILLION) * 1000};

        pid_t   api;

        assert(o);

#ifdef __APPLE__
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD) {
                LOG_WARN("Recovering dead mutex.");
                pthread_mutex_consistent(rdrb->lock);
        }
#endif

        pthread_cleanup_push((void (*)(void *)) pthread_mutex_unlock,
                             (void *) rdrb->lock);

        while (true) {
                int ret = 0;
                struct timespec now;
                struct timespec dl;
#ifdef __APPLE__
                pthread_cond_wait(rdrb->full, rdrb->lock);
#else
                if (pthread_cond_wait(rdrb->full, rdrb->lock) == EOWNERDEAD) {
                        LOG_WARN("Recovering dead mutex.");
                        pthread_mutex_consistent(rdrb->lock);
                }
#endif
                *rdrb->choked = 1;

                garbage_collect(rdrb);

                if (shm_rdrb_empty(rdrb)) {
                        pthread_cond_broadcast(rdrb->healthy);
                        continue;
                }

                api = get_tail_ptr(rdrb)->dst_api;

                if (kill(api, 0)) {
                        LOG_DBGF("Dead process %d left stale sdu.", api);
                        clean_sdus(rdrb, api);
                        pthread_cond_broadcast(rdrb->healthy);
                        continue;
                }

                clock_gettime(CLOCK_REALTIME, &now);
                ts_add(&now, &intv, &dl);
                while (*rdrb->choked) {
                        ret = pthread_cond_timedwait(rdrb->healthy,
                                                     rdrb->lock,
                                                     &dl);
                        if (!ret)
                                continue;
#ifndef __APPLE__
                        if (ret == EOWNERDEAD) {
                                LOG_WARN("Recovering dead mutex.");
                                pthread_mutex_consistent(rdrb->lock);
                        }
#endif
                        if (ret == ETIMEDOUT) {
                                LOG_DBGF("SDU timed out (dst: %d).", api);
                                clean_sdus(rdrb, api);
                        }
                }
                pthread_cond_broadcast(rdrb->healthy);
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

void shm_rdrbuff_close(struct shm_rdrbuff * rdrb)
{
        assert(rdrb);

        if (munmap(rdrb->shm_base, SHM_FILE_SIZE) == -1)
                LOG_DBGF("Couldn't unmap shared memory.");

        free(rdrb);
}

void shm_rdrbuff_destroy(struct shm_rdrbuff * rdrb)
{
        char * shm_rdrb_fn;

        assert(rdrb);

        if (getpid() != *rdrb->api && kill(*rdrb->api, 0) == 0) {
                LOG_DBG("Process %d tried to destroy active rdrb.", getpid());
                return;
        }

        if (munmap(rdrb->shm_base, SHM_FILE_SIZE) == -1)
                LOG_DBG("Couldn't unmap shared memory.");

        shm_rdrb_fn = rdrb_filename(rdrb->qos);
        if (shm_rdrb_fn == NULL) {
                LOG_ERR("Could not create rdrbuff. Out of Memory");
                return;
        }

        if (shm_unlink(shm_rdrb_fn) == -1)
                LOG_DBG("Failed to unlink shm.");

        free(rdrb);
        free(shm_rdrb_fn);
}

ssize_t shm_rdrbuff_write(struct shm_rdrbuff * rdrb,
                          pid_t                dst_api,
                          size_t               headspace,
                          size_t               tailspace,
                          uint8_t *            data,
                          size_t               len)
{
        struct shm_du_buff * sdb;
        size_t               size = headspace + len + tailspace;
#ifdef SHM_RDRB_MULTI_BLOCK
        size_t               blocks = 0;
        size_t               padblocks = 0;
#endif
        ssize_t              sz = size + sizeof(*sdb);
        uint8_t *            write_pos;

        assert(rdrb);
        assert(data);

#ifndef SHM_RDRB_MULTI_BLOCK
        if (sz > SHM_RDRB_BLOCK_SIZE) {
                LOG_DBGF("Multi-block SDUs disabled. Dropping.");
                return -1;
        }
#endif
#ifdef __APPLE__
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD) {
                LOG_DBGF("Recovering dead mutex.");
                pthread_mutex_consistent(rdrb->lock);
        }
#endif
#ifdef SHM_RDRB_MULTI_BLOCK
        while (sz > 0) {
                sz -= SHM_RDRB_BLOCK_SIZE;
                ++blocks;
        }

        if (blocks + *rdrb->ptr_head > (SHM_BUFFER_SIZE))
                padblocks = (SHM_BUFFER_SIZE) - *rdrb->ptr_head;

        if (!shm_rdrb_free(rdrb, blocks + padblocks)) {
#else
        if (!shm_rdrb_free(rdrb, 1)) {
#endif
                pthread_cond_signal(rdrb->full);
                pthread_mutex_unlock(rdrb->lock);
                return -1;
        }

#ifdef SHM_RDRB_MULTI_BLOCK
        if (padblocks) {
                sdb = get_head_ptr(rdrb);
                sdb->size    = 0;
                sdb->blocks  = padblocks;
                sdb->dst_api = -1;
                sdb->du_head = 0;
                sdb->du_tail = 0;
                sdb->idx     = *rdrb->ptr_head;

                *rdrb->ptr_head = 0;
        }
#endif
        sdb          = get_head_ptr(rdrb);
        sdb->size    = size;
        sdb->dst_api = dst_api;
        sdb->du_head = headspace;
        sdb->du_tail = sdb->du_head + len;
#ifdef  SHM_RDRB_MULTI_BLOCK
        sdb->blocks  = blocks;
#endif
        write_pos = ((uint8_t *) (sdb + 1)) + headspace;

        memcpy(write_pos, data, len);

        sdb->idx = *rdrb->ptr_head;
#ifdef SHM_RDRB_MULTI_BLOCK
        *rdrb->ptr_head = (*rdrb->ptr_head + blocks) & ((SHM_BUFFER_SIZE) - 1);
#else
        *rdrb->ptr_head = (*rdrb->ptr_head + 1) & ((SHM_BUFFER_SIZE) - 1);
#endif
        pthread_mutex_unlock(rdrb->lock);

        return sdb->idx;
}

ssize_t shm_rdrbuff_write_b(struct shm_rdrbuff * rdrb,
                           pid_t                 dst_api,
                           size_t                headspace,
                           size_t                tailspace,
                           uint8_t *             data,
                           size_t                len)
{
        struct shm_du_buff * sdb;
        size_t               size = headspace + len + tailspace;
#ifdef SHM_RDRB_MULTI_BLOCK
        size_t               blocks = 0;
        size_t               padblocks = 0;
#endif
        ssize_t              sz = size + sizeof(*sdb);
        uint8_t *            write_pos;

        assert(rdrb);
        assert(data);

#ifndef SHM_RDRB_MULTI_BLOCK
        if (sz > SHM_RDRB_BLOCK_SIZE) {
                LOG_DBGF("Multi-block SDUs disabled. Dropping.");
                return -1;
        }
#endif
#ifdef __APPLE__
        pthread_mutex_lock(rdrb->lock);
#else
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD) {
                LOG_DBGF("Recovering dead mutex.");
                pthread_mutex_consistent(rdrb->lock);
        }
#endif
        pthread_cleanup_push((void (*) (void *)) pthread_mutex_unlock,
                             (void *) rdrb->lock);

#ifdef SHM_RDRB_MULTI_BLOCK
        while (sz > 0) {
                sz -= SHM_RDRB_BLOCK_SIZE;
                ++blocks;
        }

        if (blocks + *rdrb->ptr_head > (SHM_BUFFER_SIZE))
                padblocks = (SHM_BUFFER_SIZE) - *rdrb->ptr_head;

        while (!shm_rdrb_free(rdrb, (blocks + padblocks))) {
#else
        while (!shm_rdrb_free(rdrb, 1)) {
#endif
                pthread_cond_signal(rdrb->full);
                pthread_cond_wait(rdrb->healthy, rdrb->lock);
        }

#ifdef SHM_RDRB_MULTI_BLOCK
        if (padblocks) {
                sdb = get_head_ptr(rdrb);
                sdb->size    = 0;
                sdb->blocks  = padblocks;
                sdb->dst_api = -1;
                sdb->du_head = 0;
                sdb->du_tail = 0;
                sdb->idx     = *rdrb->ptr_head;

                *rdrb->ptr_head = 0;
        }
#endif
        sdb          = get_head_ptr(rdrb);
        sdb->size    = size;
        sdb->dst_api = dst_api;
        sdb->du_head = headspace;
        sdb->du_tail = sdb->du_head + len;
#ifdef  SHM_RDRB_MULTI_BLOCK
        sdb->blocks  = blocks;
#endif
        write_pos = ((uint8_t *) (sdb + 1)) + headspace;

        memcpy(write_pos, data, len);

        sdb->idx = *rdrb->ptr_head;
#ifdef SHM_RDRB_MULTI_BLOCK
        *rdrb->ptr_head = (*rdrb->ptr_head + blocks) & ((SHM_BUFFER_SIZE) - 1);
#else
        *rdrb->ptr_head = (*rdrb->ptr_head + 1) & ((SHM_BUFFER_SIZE) - 1);
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
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD) {
                LOG_DBGF("Recovering dead mutex.");
                pthread_mutex_consistent(rdrb->lock);
        }
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
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD) {
                LOG_DBGF("Recovering dead mutex.");
                pthread_mutex_consistent(rdrb->lock);
        }
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
        if (pthread_mutex_lock(rdrb->lock) == EOWNERDEAD) {
                LOG_DBGF("Recovering dead mutex.");
                pthread_mutex_consistent(rdrb->lock);
        }
#endif
        if (shm_rdrb_empty(rdrb)) {
                pthread_mutex_unlock(rdrb->lock);
                return -1;
        }

        idx_to_du_buff_ptr(rdrb, idx)->dst_api = -1;

        if (idx != *rdrb->ptr_tail) {
                pthread_mutex_unlock(rdrb->lock);
                return 0;
        }

        garbage_collect(rdrb);

        *rdrb->choked = 0;

        pthread_cond_broadcast(rdrb->healthy);
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

        if ((long) (sdb->du_head - size) < 0) {
                LOG_ERR("Failed to allocate PCI headspace.");
                return NULL;
        }

        sdb->du_head -= size;

        buf = (uint8_t *) (sdb + 1) + sdb->du_head;

        return buf;
}

uint8_t * shm_du_buff_tail_alloc(struct shm_du_buff * sdb,
                                 size_t               size)
{
        uint8_t * buf = NULL;

        assert(sdb);

        if (sdb->du_tail + size >= sdb->size) {
                LOG_ERR("Failed to allocate PCI tailspace.");
                return NULL;
        }

        buf = (uint8_t *) (sdb + 1) + sdb->du_tail;

        sdb->du_tail += size;

        return buf;
}

int shm_du_buff_head_release(struct shm_du_buff * sdb,
                             size_t               size)
{
        assert(sdb);

        if (size > sdb->du_tail - sdb->du_head) {
                LOG_DBGF("Tried to release beyond SDU boundary.");
                return -EOVERFLOW;
        }

        sdb->du_head += size;

        return 0;
}

int shm_du_buff_tail_release(struct shm_du_buff * sdb,
                             size_t               size)
{
        assert(sdb);

        if (size > sdb->du_tail - sdb->du_head) {
                LOG_ERR("Tried to release beyond SDU boundary.");
                return -EOVERFLOW;
        }

        sdb->du_tail -= size;

        return 0;
}
