/*
 * Ouroboros - Copyright (C) 2016
 *
 * Shared memory map for data units
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
#include <ouroboros/shm_du_map.h>
#include <ouroboros/shm_ap_rbuff.h>
#include <ouroboros/time_utils.h>
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>

#define OUROBOROS_PREFIX "shm_du_map"

#include <ouroboros/logs.h>

#define SHM_BLOCKS_SIZE (SHM_BLOCKS_IN_MAP * SHM_DU_BUFF_BLOCK_SIZE)
#define SHM_FILE_SIZE (SHM_BLOCKS_SIZE + 3 * sizeof (size_t)                   \
                       + sizeof(pthread_mutex_t) + 2 * sizeof(pthread_cond_t)  \
                       + sizeof(pid_t))

#define get_head_ptr(dum)                                                      \
((struct shm_du_buff *)(dum->shm_base + (*dum->ptr_head *                      \
                                         SHM_DU_BUFF_BLOCK_SIZE)))

#define get_tail_ptr(dum)                                                      \
((struct shm_du_buff *)(dum->shm_base + (*dum->ptr_tail *                      \
                                         SHM_DU_BUFF_BLOCK_SIZE)))

#define idx_to_du_buff_ptr(dum, idx)                                           \
        ((struct shm_du_buff *)(dum->shm_base + (idx * SHM_DU_BUFF_BLOCK_SIZE)))

#define block_ptr_to_idx(dum, sdb)                                             \
        (((uint8_t *)sdb - dum->shm_base) / SHM_DU_BUFF_BLOCK_SIZE)

#define shm_map_used(dum)((*dum->ptr_head + SHM_BLOCKS_IN_MAP - *dum->ptr_tail)\
                          & (SHM_BLOCKS_IN_MAP - 1))
#define shm_map_free(dum, i)(shm_map_used(dum) + i < SHM_BLOCKS_IN_MAP)

#define shm_map_empty(dum) (*dum->ptr_tail == *dum->ptr_head)

struct shm_du_buff {
        size_t size;
#ifdef SHM_DU_MAP_MULTI_BLOCK
        size_t blocks;
#endif
        size_t du_head;
        size_t du_tail;
        pid_t  dst_api;
};

struct shm_du_map {
        uint8_t *         shm_base;    /* start of blocks */
        size_t *          ptr_head;    /* start of ringbuffer head */
        size_t *          ptr_tail;    /* start of ringbuffer tail */
        pthread_mutex_t * shm_mutex;   /* lock all free space in shm */
        size_t *          choked;      /* stale sdu detection */
        pthread_cond_t *  healthy;     /* du map is healthy */
        pthread_cond_t *  full;        /* run sanitizer when buffer full */
        pid_t *           api;         /* api of the irmd owner */
        int               fd;
};

static void garbage_collect(struct shm_du_map * dum)
{
#ifdef SHM_DU_MAP_MULTI_BLOCK
        struct shm_du_buff * sdb;
        while ((sdb = get_tail_ptr(dum))->dst_api == 0 &&
               !shm_map_empty(dum))
                *dum->ptr_tail = (*dum->ptr_tail + sdb->blocks)
                        & (SHM_BLOCKS_IN_MAP - 1);
#else
        while (get_tail_ptr(dum)->dst_api == 0 &&
               !shm_map_empty(dum))
                *dum->ptr_tail =
                        (*dum->ptr_tail + 1) & (SHM_BLOCKS_IN_MAP - 1);

#endif
}

static void clean_sdus(struct shm_du_map * dum, pid_t api)
{
        size_t idx = *dum->ptr_tail;
        struct shm_du_buff * buf;

        while (idx != *dum->ptr_head) {
                buf = idx_to_du_buff_ptr(dum, idx);
                if (buf->dst_api == api)
                        buf->dst_api = 0;
#ifdef SHM_DU_MAP_MULTI_BLOCK
                idx = (idx + buf->blocks) & (SHM_BLOCKS_IN_MAP - 1);
#else
                idx = (idx + 1) & (SHM_BLOCKS_IN_MAP - 1);
#endif
        }

        garbage_collect(dum);

        if (kill(api, 0) == 0) {
                struct shm_ap_rbuff * rb;
                rb = shm_ap_rbuff_open(api);
                shm_ap_rbuff_reset(rb);
                shm_ap_rbuff_close(rb);
        }

        *dum->choked = 0;
}

struct shm_du_map * shm_du_map_create()
{
        struct shm_du_map * dum;
        int                 shm_fd;
        uint8_t *           shm_base;
        pthread_mutexattr_t mattr;
        pthread_condattr_t  cattr;

        dum = malloc(sizeof *dum);
        if (dum == NULL) {
                LOG_DBGF("Could not allocate struct.");
                return NULL;
        }

        shm_fd = shm_open(SHM_DU_MAP_FILENAME, O_CREAT | O_EXCL | O_RDWR, 0666);
        if (shm_fd == -1) {
                LOG_DBGF("Failed creating shared memory map.");
                free(dum);
                return NULL;
        }

        if (fchmod(shm_fd, 0666)) {
                LOG_DBGF("Failed to chmod shared memory map.");
                free(dum);
                return NULL;
        }

        if (lseek(shm_fd, SHM_FILE_SIZE - 1, SEEK_SET) < 0) {
                LOG_DBGF("Failed to extend shared memory map.");
                free(dum);
                return NULL;
        }

        if (write(shm_fd, "", 1) != 1) {
                LOG_DBGF("Failed to finalise extension of shared memory map.");
                free(dum);
                return NULL;
        }

        shm_base = mmap(NULL,
                        SHM_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);

        if (shm_base == MAP_FAILED) {
                LOG_DBGF("Failed to map shared memory.");

                if (shm_unlink(SHM_DU_MAP_FILENAME) == -1)
                        LOG_DBGF("Failed to remove invalid shm.");

                free(dum);
                return NULL;
        }

        dum->shm_base = shm_base;
        dum->ptr_head = (size_t *)
                ((uint8_t *) dum->shm_base + SHM_BLOCKS_SIZE);
        dum->ptr_tail = dum->ptr_head + 1;
        dum->shm_mutex = (pthread_mutex_t *) (dum->ptr_tail + 1);
        dum->choked = (size_t *) (dum->shm_mutex + 1);
        dum->healthy = (pthread_cond_t *) (dum->choked + 1);
        dum->full = dum->healthy + 1;
        dum->api = (pid_t *) (dum->full + 1);

        pthread_mutexattr_init(&mattr);
        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
        pthread_mutex_init(dum->shm_mutex, &mattr);

        pthread_condattr_init(&cattr);
        pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
        pthread_cond_init(dum->full, &cattr);
        pthread_cond_init(dum->healthy, &cattr);

        *dum->ptr_head = 0;
        *dum->ptr_tail = 0;

        *dum->choked = 0;

        *dum->api = getpid();

        dum->fd = shm_fd;

        return dum;
}

struct shm_du_map * shm_du_map_open()
{
        struct shm_du_map * dum;
        int                 shm_fd;
        uint8_t *           shm_base;

        dum = malloc(sizeof *dum);
        if (dum == NULL) {
                LOG_DBGF("Could not allocate struct.");
                return NULL;
        }

        shm_fd = shm_open(SHM_DU_MAP_FILENAME, O_RDWR, 0666);
        if (shm_fd == -1) {
                LOG_DBGF("Failed opening shared memory.");
                return NULL;
        }

        shm_base = mmap(NULL,
                        SHM_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);
        if (shm_base == MAP_FAILED) {
                LOG_DBGF("Failed to map shared memory.");
                if (close(shm_fd) == -1)
                        LOG_DBGF("Failed to close invalid shm.");

                if (shm_unlink(SHM_DU_MAP_FILENAME) == -1)
                        LOG_DBGF("Failed to unlink invalid shm.");

                return NULL;
        }

        dum->shm_base = shm_base;
        dum->ptr_head = (size_t *)
                ((uint8_t *) dum->shm_base + SHM_BLOCKS_SIZE);
        dum->ptr_tail = dum->ptr_head + 1;
        dum->shm_mutex = (pthread_mutex_t *) (dum->ptr_tail + 1);
        dum->choked = (size_t *) (dum->shm_mutex + 1);
        dum->healthy = (pthread_cond_t *) (dum->choked + 1);
        dum->full = dum->healthy + 1;
        dum->api = (pid_t *) (dum->full + 1);

        dum->fd = shm_fd;

        return dum;
}

pid_t shm_du_map_owner(struct shm_du_map * dum)
{
        if (dum == NULL)
                return 0;

        return *dum->api;
}

void * shm_du_map_sanitize(void * o)
{
        struct shm_du_map * dum = (struct shm_du_map *) o;
        struct timespec intv
                = {SHM_DU_TIMEOUT_MICROS / MILLION,
                   (SHM_DU_TIMEOUT_MICROS % MILLION) * 1000};

        pid_t   api;

        if (dum == NULL)
                return (void *) -1;
        if (pthread_mutex_lock(dum->shm_mutex) == EOWNERDEAD) {
                LOG_WARN("Recovering dead mutex.");
                pthread_mutex_consistent(dum->shm_mutex);
        }

        pthread_cleanup_push((void (*)(void *)) pthread_mutex_unlock,
                             (void *) dum->shm_mutex);

        while (true) {
                int ret = 0;
                struct timespec now;
                struct timespec dl;

                if (pthread_cond_wait(dum->full, dum->shm_mutex)
                        == EOWNERDEAD) {
                        LOG_WARN("Recovering dead mutex.");
                        pthread_mutex_consistent(dum->shm_mutex);
                }

                *dum->choked = 1;

                garbage_collect(dum);

                if (shm_map_empty(dum))
                        continue;

                api = get_tail_ptr(dum)->dst_api;

                if (kill(api, 0)) {
                        LOG_DBGF("Dead process %d left stale sdu.", api);
                        clean_sdus(dum, api);
                        continue;
                }

                clock_gettime(CLOCK_REALTIME, &now);
                ts_add(&now, &intv, &dl);
                while (*dum->choked) {
                        ret = pthread_cond_timedwait(dum->healthy,
                                                     dum->shm_mutex,
                                                     &dl);
                        if (!ret)
                                continue;

                        if (ret == EOWNERDEAD) {
                                LOG_WARN("Recovering dead mutex.");
                                pthread_mutex_consistent(dum->shm_mutex);
                        }

                        if (ret == ETIMEDOUT) {
                                LOG_DBGF("SDU timed out.");
                                clean_sdus(dum, api);
                        }
                }
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

void shm_du_map_close(struct shm_du_map * dum)
{
        if (dum == NULL) {
                LOG_DBGF("Bogus input. Bugging out.");
                return;
        }

        if (close(dum->fd) < 0)
                LOG_DBGF("Couldn't close shared memory.");

        if (munmap(dum->shm_base, SHM_FILE_SIZE) == -1)
                LOG_DBGF("Couldn't unmap shared memory.");

        free(dum);
}

void shm_du_map_destroy(struct shm_du_map * dum)
{
        if (dum == NULL) {
                LOG_DBGF("Bogus input. Bugging out.");
                return;
        }

        if (close(dum->fd) < 0)
                LOG_DBGF("Couldn't close shared memory.");

        if (munmap(dum->shm_base, SHM_FILE_SIZE) == -1)
                LOG_DBGF("Couldn't unmap shared memory.");

        if (shm_unlink(SHM_DU_MAP_FILENAME) == -1)
                LOG_DBGF("Failed to unlink shm.");

        free(dum);
}

ssize_t shm_du_map_write(struct shm_du_map * dum,
                         pid_t               dst_api,
                         size_t              headspace,
                         size_t              tailspace,
                         uint8_t *           data,
                         size_t              len)
{
        struct shm_du_buff * sdb;
        size_t               size = headspace + len + tailspace;
#ifdef SHM_DU_MAP_MULTI_BLOCK
        long                 blocks = 0;
        long                 padblocks = 0;
        int                  sz = headspace + len + sizeof *sdb;
        int                  sz2 = sz + tailspace;
#endif
        uint8_t *            write_pos;
        ssize_t              index = -1;

        if (dum == NULL || data == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -1;
        }

#ifndef SHM_DU_MAP_MULTI_BLOCK
        if (size + sizeof *sdb > SHM_DU_BUFF_BLOCK_SIZE) {
                LOG_DBGF("Multi-block SDU's disabled. Dropping.");
                return -1;
        }
#endif
        if (pthread_mutex_lock(dum->shm_mutex) == EOWNERDEAD) {
                LOG_DBGF("Recovering dead mutex.");
                pthread_mutex_consistent(dum->shm_mutex);
        }
#ifdef SHM_DU_MAP_MULTI_BLOCK
        while (sz2 > 0) {
                sz2 -= SHM_DU_BUFF_BLOCK_SIZE;
                sz -= SHM_DU_BUFF_BLOCK_SIZE;
                if (sz < 0 && sz2 > 0) {
                        pthread_mutex_unlock(dum->shm_mutex);
                        LOG_DBG("Can't handle this packet now.");
                        return -EAGAIN;
                }
                ++blocks;
        }

        if (blocks + *dum->ptr_head > SHM_BLOCKS_IN_MAP - 1)
                padblocks = SHM_BLOCKS_IN_MAP - *dum->ptr_head;

        if (!shm_map_free(dum, (blocks + padblocks))) {
#else
        if (!shm_map_free(dum, 1)) {
#endif
                pthread_cond_signal(dum->full);
                pthread_mutex_unlock(dum->shm_mutex);
                return -1;
        }

#ifdef SHM_DU_MAP_MULTI_BLOCK
        if (padblocks) {
                sdb = get_head_ptr(dum);
                sdb->size    = 0;
                sdb->blocks  = padblocks;
                sdb->dst_api = 0;
                sdb->du_head = 0;
                sdb->du_tail = 0;

                *dum->ptr_head = 0;
        }
#endif
        sdb          = get_head_ptr(dum);
        sdb->size    = size;
        sdb->dst_api = dst_api;
        sdb->du_head = headspace;
        sdb->du_tail = sdb->du_head + len;
#ifdef  SHM_DU_MAP_MULTI_BLOCK
        sdb->blocks  = blocks;
#endif
        write_pos = ((uint8_t *) sdb) + sizeof *sdb + headspace;

        memcpy(write_pos, data, len);

        index = *dum->ptr_head;
#ifdef SHM_DU_MAP_MULTI_BLOCK
        *dum->ptr_head = (*dum->ptr_head + blocks) & (SHM_BLOCKS_IN_MAP - 1);
#else
        *dum->ptr_head = (*dum->ptr_head + 1) & (SHM_BLOCKS_IN_MAP - 1);
#endif
        pthread_mutex_unlock(dum->shm_mutex);

        return index;
}

int shm_du_map_read(uint8_t **          dst,
                    struct shm_du_map * dum,
                    ssize_t             idx)
{
        size_t len = 0;
        struct shm_du_buff * sdb;

        if (idx > SHM_BLOCKS_IN_MAP)
                return -1;

        if (pthread_mutex_lock(dum->shm_mutex) == EOWNERDEAD) {
                LOG_DBGF("Recovering dead mutex.");
                pthread_mutex_consistent(dum->shm_mutex);
        }

        if (shm_map_empty(dum)) {
                pthread_mutex_unlock(dum->shm_mutex);
                return -1;
        }

        sdb = idx_to_du_buff_ptr(dum, idx);
        len = sdb->du_tail - sdb->du_head;
        *dst = ((uint8_t *) sdb) + sizeof(struct shm_du_buff) + sdb->du_head;

        pthread_mutex_unlock(dum->shm_mutex);

        return len;
}

int shm_du_map_remove(struct shm_du_map * dum, ssize_t idx)
{
        if (idx > SHM_BLOCKS_IN_MAP)
                return -1;

        if (pthread_mutex_lock(dum->shm_mutex) == EOWNERDEAD) {
                LOG_DBGF("Recovering dead mutex.");
                pthread_mutex_consistent(dum->shm_mutex);
        }

        if (shm_map_empty(dum)) {
                pthread_mutex_unlock(dum->shm_mutex);
                return -1;
        }

        idx_to_du_buff_ptr(dum, idx)->dst_api = 0;

        if (idx != *dum->ptr_tail) {
                pthread_mutex_unlock(dum->shm_mutex);
                return 0;
        }

        garbage_collect(dum);

        *dum->choked = 0;
        pthread_cond_signal(dum->healthy);

        pthread_mutex_unlock(dum->shm_mutex);

        return 0;
}

uint8_t * shm_du_buff_head_alloc(struct shm_du_buff * sdb,
                                 size_t size)
{
        if (sdb == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return NULL;
        }

        if ((long) (sdb->du_head - size) < 0) {
                LOG_DBGF("Failed to allocate PCI headspace.");
                return NULL;
        }

        sdb->du_head -= size;

        return (uint8_t *) sdb + sizeof *sdb + sdb->du_head;
}

uint8_t * shm_du_buff_tail_alloc(struct shm_du_buff * sdb,
                                 size_t               size)
{
        if (sdb == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return NULL;
        }

        if (sdb->du_tail + size >= sdb->size) {
                LOG_DBGF("Failed to allocate PCI tailspace.");
                return NULL;
        }

        sdb->du_tail += size;

        return (uint8_t *) sdb + sizeof *sdb + sdb->du_tail;
}

int shm_du_buff_head_release(struct shm_du_buff * sdb,
                             size_t               size)
{
        if (sdb == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -EINVAL;
        }

        if (size > sdb->du_tail - sdb->du_head) {
                LOG_DBGF("Tried to release beyond sdu boundary.");
                return -EOVERFLOW;
        }

        sdb->du_head += size;

        return sdb->du_head;
}

int shm_du_buff_tail_release(struct shm_du_buff * sdb,
                             size_t               size)
{
        if (sdb == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -EINVAL;
        }

        if (size > sdb->du_tail - sdb->du_head) {
                LOG_DBGF("Tried to release beyond sdu boundary.");
                return -EOVERFLOW;
        }

        sdb->du_tail -= size;

        return sdb->du_tail;
}
