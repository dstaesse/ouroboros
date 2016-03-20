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

#ifndef SHM_DU_MAP_C
#define SHM_DU_MAP_C

#include <ouroboros/shm_du_map.h>

#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <malloc.h>
#include <string.h>


#define SHM_DU_BLOCK_DATA_SIZE (SHM_DU_BUFF_BLOCK_SIZE -                       \
                                sizeof(struct shm_block))
#define SHM_BLOCKS_IN_MAP (1 << SHM_DU_MAP_SIZE)
#define SHM_BLOCKS_SIZE (SHM_DU_BUFF_BLOCK_SIZE * SHM_BLOCKS_IN_MAP)
#define SHM_BUFFS_SIZE (SHM_BLOCKS_IN_MAP * sizeof (struct shm_du_buff))
#define SHM_FILE_SIZE (SHM_BLOCKS_IN_MAP * (SHM_DU_BUFF_BLOCK_SIZE             \
                                            + sizeof(struct shm_du_buff)       \
                                            + sizeof(uint8_t))                 \
                       + 2 * sizeof (size_t)                                   \
                       + sizeof(pthread_mutex_t))

#define idx_to_block_ptr(dum, i) ((struct shm_block *)                         \
                                  (dum->shm_base + i * SHM_DU_BUFF_BLOCK_SIZE))
#define idx_to_du_buff_ptr(dum, i) (dum->ptr_du_buff + i)
#define du_buff_ptr_to_idx(dum, sdb) ((sdb - dum->ptr_du_buff) / sizeof *sdb)
#define block_ptr_to_idx(dum, sdb) (((uint8_t *)sdb - dum->shm_base)           \
                                    / SHM_DU_BUFF_BLOCK_SIZE)

#define shm_map_used(dum) ((*(dum->ptr_head) + SHM_BLOCKS_IN_MAP -             \
                            *(dum->ptr_tail)) & (SHM_BLOCKS_IN_MAP - 1))

#define shm_map_free(dum, i)(shm_map_used(dum) + i + 1 < SHM_BLOCKS_IN_MAP)

struct shm_block {
        size_t size;
        long   next;
        long   prev;
};

struct shm_du_buff {
        size_t            size;
        size_t            du_head;
        size_t            du_tail;
};

struct shm_du_map {
        uint8_t            * shm_base;    /* start of blocks */
        struct shm_du_buff * ptr_du_buff; /* start of du_buff structs */
        size_t             * ptr_head;    /* start of ringbuffer head */
        size_t             * ptr_tail;    /* start of ringbuffer tail */
        pthread_mutex_t    * shm_mutex;   /* lock all free space in shm */
        int                  fd;
};

struct shm_du_map * shm_du_map_create()
{
        struct shm_du_map * dum;
        int                 shm_fd;
        uint8_t           * shm_base;
        pthread_mutexattr_t attr;

        dum = malloc(sizeof *dum);
        if (dum == NULL) {
                LOG_ERR("Could not allocate struct.");
                return NULL;
        }

        shm_fd = shm_open(SHM_DU_MAP_FILENAME, O_CREAT | O_EXCL | O_RDWR, 0666);
        if (shm_fd == -1) {
                LOG_ERR("Failed creating shared memory map.");
                free(dum);
                return NULL;
        }

        if (lseek (shm_fd,SHM_FILE_SIZE - 1, SEEK_SET) < 0) {
                LOG_ERR("Failed to extend shared memory map.");
                free(dum);
                return NULL;
        }

        if (write (shm_fd, "", 1) != 1) {
                LOG_ERR("Failed to finalise extension of shared memory map.");
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
                LOG_ERR("Failed to map shared memory.");

                if (shm_unlink(SHM_DU_MAP_FILENAME) == -1)
                        LOG_ERR("Failed to remove invalid shm.");

                free(dum);
                return NULL;
        }
#ifdef CONFIG_OUROBOROS_DEBUG
        memset(shm_base, 0, SHM_FILE_SIZE);
#endif
        dum->shm_base = shm_base;
        dum->ptr_du_buff = (struct shm_du_buff *)
                ((uint8_t *) dum->shm_base + SHM_BLOCKS_SIZE);
        dum->ptr_head = (size_t *)
                ((uint8_t *) dum->ptr_du_buff + SHM_BUFFS_SIZE);
        dum->ptr_tail = (size_t *)
                ((uint8_t *) dum->ptr_head + sizeof(size_t));
        dum->shm_mutex = (pthread_mutex_t *)
                ((uint8_t *) dum->ptr_tail + sizeof(size_t));

        pthread_mutexattr_init(&attr);
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(dum->shm_mutex, &attr);

        *dum->ptr_head = 0;
        *dum->ptr_tail = 0;

        dum->fd = shm_fd;

        return dum;
}

struct shm_du_map * shm_du_map_open()
{
        struct shm_du_map * dum;
        int                 shm_fd;
        uint8_t           * shm_base;

        shm_fd = shm_open(SHM_DU_MAP_FILENAME, O_RDWR, 0666);
        if (shm_fd == -1) {
                LOG_ERR("Failed opening shared memory for du_buff.");
                return NULL;
        }

        shm_base = mmap(NULL,
                        SHM_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);
        if (shm_base == MAP_FAILED) {
                LOG_ERR("Failed to map shared memory.");

                if (shm_unlink(SHM_DU_MAP_FILENAME) == -1)
                        LOG_ERR("Failed to unlink invalid shm.");

                return NULL;
        }

        dum = malloc(sizeof *dum);
        if (dum == NULL) {
                LOG_ERR("Could not allocate struct.");
                return NULL;
        }

        dum->shm_base = shm_base;
        dum->ptr_du_buff = (struct shm_du_buff *)
                ((uint8_t *) dum->shm_base + SHM_BLOCKS_SIZE);
        dum->ptr_head = (size_t *)
                ((uint8_t *) dum->ptr_du_buff + SHM_BUFFS_SIZE);
        dum->ptr_tail = (size_t *)
                ((uint8_t *) dum->ptr_head + sizeof(size_t));
        dum->shm_mutex = (pthread_mutex_t *)
                ((uint8_t *) dum->ptr_tail + sizeof(size_t));

        return dum;
}

void shm_du_map_close(struct shm_du_map * dum)
{
        if (dum == NULL) {
                LOG_DBGF("Bogus input. Bugging out.");
                return;
        }

        if (munmap(dum->shm_base, SHM_FILE_SIZE) == -1)
                LOG_DBGF("Couldn't unmap shared memory.");

        if (shm_unlink(SHM_DU_MAP_FILENAME) == -1)
                LOG_DBGF("Failed to unlink shm.");

        free(dum);
}

struct shm_du_buff * shm_create_du_buff(struct shm_du_map * dum,
                                        size_t              size,
                                        size_t              headspace,
                                        uint8_t           * data,
                                        size_t              len)
{
        struct shm_du_buff * sdb;
        long                 prev_index = -1;
        size_t               remaining = size;
        size_t               ts = size - (headspace + len);
        uint8_t            * read_pos = data;
        size_t               blocks = 0;
        int                  sz = size;

        if (dum == NULL || data == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return NULL;
        }

        if (headspace >= size) {
                LOG_DBGF("Index out of bounds.");
                return NULL;
        }

        if (headspace + len > size) {
                LOG_DBGF("Buffer too small for data.");
                return NULL;
        }

        if (headspace > SHM_DU_BLOCK_DATA_SIZE || ts > SHM_DU_BLOCK_DATA_SIZE) {
                LOG_ERR("Illegal du_buff: Cannot fit PCI in DU_BUFF_BLOCK.");
                return NULL;
        }

        pthread_mutex_lock(dum->shm_mutex);

        while (sz > 0) {
                sz -= SHM_DU_BLOCK_DATA_SIZE;
                blocks++;
        }

        if (!shm_map_free(dum, blocks)) {
                pthread_mutex_unlock(dum->shm_mutex);
                LOG_DBGF("Allocation failed, Out of Memory.");
                return NULL;
        }

        sdb = dum->ptr_du_buff + *dum->ptr_head;

        sdb->size = size;
        sdb->du_head = headspace;
        sdb->du_tail = sdb->du_head + len;

        while (remaining > 0) {
                struct shm_block * shm_buf;
                long               bytes_to_copy = len;
                uint8_t          * write_pos;

                shm_buf = idx_to_block_ptr(dum, *(dum->ptr_head));

                write_pos = (uint8_t *) shm_buf + sizeof *shm_buf;

                shm_buf->size = remaining < SHM_DU_BLOCK_DATA_SIZE ?
                        remaining : SHM_DU_BLOCK_DATA_SIZE;

                bytes_to_copy = shm_buf->size;

                if (remaining <= SHM_DU_BLOCK_DATA_SIZE)
                        bytes_to_copy -= ts;
                else if (remaining - ts <= SHM_DU_BLOCK_DATA_SIZE)
                        shm_buf->size = remaining - ts;

                remaining -= shm_buf->size;

                if (prev_index == -1) {
#ifdef CONFIG_OUROBOROS_DEBUG
                        memset(write_pos, 0, sdb->du_head);
#endif
                        write_pos += sdb->du_head;
                        bytes_to_copy -= sdb->du_head;
                }

                if (prev_index != -1)
                        idx_to_block_ptr(dum, prev_index)->next =
                                *(dum->ptr_head);

                if (len > 0) {
                        memcpy(write_pos, read_pos, bytes_to_copy);
                }
                read_pos += bytes_to_copy;
#ifdef CONFIG_OUROBOROS_DEBUG
                if (remaining == 0) {
                        write_pos + = bytes_to_copy;
                        memset(write_pos, 0, ts);
                }
#endif
                shm_buf->next = -1;
                shm_buf->prev = prev_index;

                prev_index = *dum->ptr_head;

                *(dum->ptr_head) = (*dum->ptr_head + 1)
                        & (SHM_BLOCKS_IN_MAP - 1);
        }

        pthread_mutex_unlock(dum->shm_mutex);

        return sdb;
}

int shm_release_du_buff(struct shm_du_map * dum)
{
        int released = 0;

        pthread_mutex_lock(dum->shm_mutex);

        if (*dum->ptr_head == *dum->ptr_tail) {
                LOG_DBGF("Attempt to free empty ringbuffer. Nothing to do.");
                pthread_mutex_unlock(dum->shm_mutex);
                return -1;
        }

        while (idx_to_block_ptr(dum, *dum->ptr_tail)->next != -1) {
                *(dum->ptr_tail) = (*dum->ptr_tail + 1)
                        & (SHM_BLOCKS_IN_MAP -1);
                released++;
        }

        *(dum->ptr_tail) = (*dum->ptr_tail + 1) & (SHM_BLOCKS_IN_MAP - 1);

        pthread_mutex_unlock(dum->shm_mutex);

        return 0;
}

uint8_t * shm_du_buff_head_alloc(struct shm_du_map * dum,
                                 struct shm_du_buff * sdb,
                                 size_t size)
{
        uint8_t * ret;

        if (sdb == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return NULL;
        }

        if ((long) (sdb->du_head - size) < 0) {
                LOG_DBGF("Failed to allocate PCI headspace.");
                return NULL;
        }

        sdb->du_head -= size;

        ret = (uint8_t *) idx_to_block_ptr(dum, du_buff_ptr_to_idx(dum,sdb));

        return ret + sizeof(struct shm_block) + sdb->du_head;
}

uint8_t * shm_du_buff_tail_alloc(struct shm_du_map * dum,
                                 struct shm_du_buff * sdb,
                                 size_t size)
{
        uint8_t * ret;

        if (sdb == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return NULL;
        }

        if (sdb->du_tail + size >= sdb->size) {
                LOG_DBGF("Failed to allocate PCI tailspace.");
                return NULL;
        }

        sdb->du_tail += size;

        ret = (uint8_t *) idx_to_block_ptr(dum, du_buff_ptr_to_idx(dum,sdb));

        return ret + sizeof(struct shm_block) + sdb->du_tail;
}

int shm_du_buff_head_release(struct shm_du_buff * sdb,
                             size_t size)
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
                             size_t size)
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

#endif
