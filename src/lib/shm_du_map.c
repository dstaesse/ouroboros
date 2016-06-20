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
#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define OUROBOROS_PREFIX "shm_du_map"

#include <ouroboros/logs.h>

#define SHM_BLOCKS_SIZE (SHM_BLOCKS_IN_MAP * SHM_DU_BUFF_BLOCK_SIZE)
#define SHM_FILE_SIZE (SHM_BLOCKS_SIZE + 2 * sizeof (size_t)                   \
                       + sizeof(pthread_mutex_t) + sizeof(pthread_cond_t)      \
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

#define sdu_size(dum, idx) (idx_to_du_buff_ptr(dum, idx)->du_tail -            \
                            idx_to_du_buff_ptr(dum, idx)->du_head)

#define MIN(a,b)(a < b ? a : b)

struct shm_du_buff {
        size_t size;
        size_t du_head;
        size_t du_tail;
        size_t garbage;
};

struct shm_du_map {
        uint8_t *         shm_base;    /* start of blocks */
        size_t *          ptr_head;    /* start of ringbuffer head */
        size_t *          ptr_tail;    /* start of ringbuffer tail */
        pthread_mutex_t * shm_mutex;   /* lock all free space in shm */
        pthread_cond_t *  sanitize;    /* run sanitizer when buffer full */
        pid_t *           pid;         /* pid of the irmd owner */
        int               fd;
};

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
        dum->sanitize = (pthread_cond_t *) (dum->shm_mutex + 1);
        dum->pid = (pid_t *) (dum->sanitize + 1);

        pthread_mutexattr_init(&mattr);
        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
        pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
        pthread_mutex_init(dum->shm_mutex, &mattr);

        pthread_condattr_init(&cattr);
        pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
        pthread_cond_init(dum->sanitize, &cattr);

        *dum->ptr_head = 0;
        *dum->ptr_tail = 0;

        *dum->pid = getpid();

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
        dum->sanitize = (pthread_cond_t *) (dum->shm_mutex + 1);
        dum->pid = (pid_t *) (dum->sanitize + 1);

        dum->fd = shm_fd;

        return dum;
}

pid_t shm_du_map_owner(struct shm_du_map * dum)
{
        return *dum->pid;
}

void * shm_du_map_sanitize(void * o)
{
        LOG_MISSING;
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

ssize_t shm_create_du_buff(struct shm_du_map * dum,
                           size_t              size,
                           size_t              headspace,
                           uint8_t *           data,
                           size_t              len)
{
        struct shm_du_buff * sdb;
#ifndef SHM_MAP_SINGLE_BLOCK
        long                 blocks = 0;
        int                  sz = size + sizeof *sdb;
        int                  sz2 = headspace + len + sizeof *sdb;
        size_t               copy_len;
#endif
        uint8_t *            write_pos;
        ssize_t              index;

        if (dum == NULL || data == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -1;
        }

#ifdef SHM_MAP_SINGLE_BLOCK
        if (size + sizeof *sdb > SHM_DU_BUFF_BLOCK_SIZE) {
                LOG_DBGF("Multi-block SDU's disabled. Dropping.");
                return -1;
        }
#endif

        if (headspace >= size) {
                LOG_DBGF("Index out of bounds.");
                return -1;
        }

        if (headspace + len > size) {
                LOG_DBGF("Buffer too small for data.");
                return -1;
        }

        pthread_mutex_lock(dum->shm_mutex);

#ifndef SHM_MAP_SINGLE_BLOCK
        while (sz > 0) {
                sz -= SHM_DU_BUFF_BLOCK_SIZE;
                sz2 -= SHM_DU_BUFF_BLOCK_SIZE;
                if (sz2 < 0 && sz > 0) {
                        pthread_mutex_unlock(dum->shm_mutex);
                        LOG_DBG("Can't handle this packet now");
                        return -1;
                }
                ++blocks;
        }

        if (!shm_map_free(dum, blocks)) {
                pthread_mutex_unlock(dum->shm_mutex);
                pthread_cond_signal(dum->sanitize);
                return -1;
        }
#else
        if (!shm_map_free(dum, 1)) {
                pthread_mutex_unlock(dum->shm_mutex);
                ptrhead_cond_signal(dum->sanitize);
                return -1;
        }
#endif

        sdb = get_head_ptr(dum);
        sdb->size = size;
        sdb->garbage = 0;
        sdb->du_head = headspace;
        sdb->du_tail = sdb->du_head + len;

        write_pos = ((uint8_t *) sdb) + sizeof *sdb + headspace;

#ifndef SHM_MAP_SINGLE_BLOCK
        copy_len = MIN(len, SHM_DU_BUFF_BLOCK_SIZE - headspace - sizeof *sdb);
        while (blocks > 0) {
                memcpy(write_pos, data, copy_len);
                *(dum->ptr_head) = (*dum->ptr_head + 1)
                        & (SHM_BLOCKS_IN_MAP - 1);
                len -= copy_len;
                copy_len = MIN(len, SHM_DU_BUFF_BLOCK_SIZE);
                write_pos = (uint8_t *) get_head_ptr(dum);
                --blocks;
        }

        index = (*dum->ptr_head - 1 + SHM_BLOCKS_IN_MAP)
                & (SHM_BLOCKS_IN_MAP - 1);
#else
        memcpy(write_pos, data, len);
        index = *dum->ptr_head;
        *(dum->ptr_head) = (*dum->ptr_head + 1) & (SHM_BLOCKS_IN_MAP - 1);
#endif
        pthread_mutex_unlock(dum->shm_mutex);

        return index;
}

/* FIXME: this cannot handle packets stretching beyond the ringbuffer border */
int shm_du_map_read_sdu(uint8_t **          dst,
                        struct shm_du_map * dum,
                        ssize_t             idx)
{
        size_t len = 0;

        if (idx > SHM_BLOCKS_IN_MAP)
                return -1;

        pthread_mutex_lock(dum->shm_mutex);

        if (*dum->ptr_head == *dum->ptr_tail) {
                pthread_mutex_unlock(dum->shm_mutex);
                return -1;
        }

        *dst = ((uint8_t *) idx_to_du_buff_ptr(dum, idx)) +
                sizeof(struct shm_du_buff) +
                idx_to_du_buff_ptr(dum, idx)->du_head;
        len = sdu_size(dum, idx);

        pthread_mutex_unlock(dum->shm_mutex);

        return len;
}

int shm_release_du_buff(struct shm_du_map * dum, ssize_t idx)
{
#ifndef SHM_MAP_SINGLE_BLOCK
        long sz;
        long blocks = 0;
#endif
        if (idx > SHM_BLOCKS_IN_MAP)
                return -1;

        pthread_mutex_lock(dum->shm_mutex);

        if (*dum->ptr_head == *dum->ptr_tail) {
                pthread_mutex_unlock(dum->shm_mutex);
                return -1;
        }

        idx_to_du_buff_ptr(dum, idx)->garbage = 1;

        if (idx != *dum->ptr_tail) {
                pthread_mutex_unlock(dum->shm_mutex);
                return 0;
        }

        while (get_tail_ptr(dum)->garbage == 1 &&
               *dum->ptr_tail != *dum->ptr_head) {
#ifndef SHM_MAP_SINGLE_BLOCK
                sz = get_tail_ptr(dum)->size;
                while (sz + (long) sizeof(struct shm_du_buff) > 0) {
                        sz -= SHM_DU_BUFF_BLOCK_SIZE;
                        ++blocks;
                }

                *(dum->ptr_tail) =
                        (*dum->ptr_tail + blocks) & (SHM_BLOCKS_IN_MAP - 1);

                blocks = 0;
#else
                *(dum->ptr_tail) =
                        (*dum->ptr_tail + 1) & (SHM_BLOCKS_IN_MAP - 1);
#endif
        }

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
