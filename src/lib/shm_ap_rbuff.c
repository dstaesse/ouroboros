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

#include <ouroboros/shm_ap_rbuff.h>
#define OUROBOROS_PREFIX "shm_ap_rbuff"

#include <ouroboros/logs.h>

#include <pthread.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <errno.h>

#define SHM_RBUFF_FILE_SIZE (SHM_RBUFF_SIZE * sizeof(struct rb_entry)          \
                             + 2 * sizeof(size_t) + sizeof(pthread_mutex_t))

#define shm_rbuff_used(rb)((*rb->ptr_head + SHM_RBUFF_SIZE - *rb->ptr_tail)\
                          & (SHM_RBUFF_SIZE - 1))
#define shm_rbuff_free(rb)(shm_rbuff_used(rb) + 1 < SHM_RBUFF_SIZE)

struct shm_ap_rbuff {
        struct rb_entry * shm_base;    /* start of entry */
        size_t *          ptr_head;    /* start of ringbuffer head */
        size_t *          ptr_tail;    /* start of ringbuffer tail */
        pthread_mutex_t * shm_mutex;   /* lock all free space in shm */
        pid_t             pid;         /* pid to which this rb belongs */
        int               fd;
};

struct shm_ap_rbuff * shm_ap_rbuff_create()
{
        struct shm_ap_rbuff * rb;
        int                   shm_fd;
        struct rb_entry *     shm_base;
        pthread_mutexattr_t   attr;
        char                  fn[25];

        sprintf(fn, SHM_AP_RBUFF_PREFIX "%d", getpid());

        rb = malloc(sizeof(*rb));
        if (rb == NULL) {
                LOG_DBGF("Could not allocate struct.");
                return NULL;
        }

        shm_fd = shm_open(fn, O_CREAT | O_EXCL | O_RDWR, 0666);
        if (shm_fd == -1) {
                LOG_DBGF("Failed creating ring buffer.");
                free(rb);
                return NULL;
        }

        if (lseek(shm_fd, SHM_RBUFF_FILE_SIZE - 1, SEEK_SET) < 0) {
                LOG_DBGF("Failed to extend ringbuffer.");
                free(rb);
                return NULL;
        }

        if (write(shm_fd, "", 1) != 1) {
                LOG_DBGF("Failed to finalise extension of ringbuffer.");
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
                LOG_DBGF("Failed to map shared memory.");
                if (close(shm_fd) == -1)
                        LOG_DBGF("Failed to close invalid shm.");

                if (shm_unlink(fn) == -1)
                        LOG_DBGF("Failed to remove invalid shm.");

                free(rb);
                return NULL;
        }

        rb->shm_base = shm_base;
        rb->ptr_head = (size_t *) (rb->shm_base + SHM_RBUFF_SIZE);
        rb->ptr_tail = (size_t *)
                ((uint8_t *) rb->ptr_head + sizeof(size_t));
        rb->shm_mutex = (pthread_mutex_t *)
                ((uint8_t *) rb->ptr_tail + sizeof(size_t));

        pthread_mutexattr_init(&attr);
        pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(rb->shm_mutex, &attr);

        *rb->ptr_head = 0;
        *rb->ptr_tail = 0;

        rb->fd  = shm_fd;
        rb->pid = getpid();

        return rb;
}

struct shm_ap_rbuff * shm_ap_rbuff_open(pid_t pid)
{
        struct shm_ap_rbuff * rb;
        int                   shm_fd;
        struct rb_entry *     shm_base;
        char                  fn[25];

        sprintf(fn, SHM_AP_RBUFF_PREFIX "%d", pid);

        rb = malloc(sizeof(*rb));
        if (rb == NULL) {
                LOG_DBGF("Could not allocate struct.");
                return NULL;
        }

        shm_fd = shm_open(fn, O_RDWR, 0666);
        if (shm_fd == -1) {
                LOG_DBGF("Failed opening shared memory %s.", fn);
                return NULL;
        }

        shm_base = mmap(NULL,
                        SHM_RBUFF_FILE_SIZE,
                        PROT_READ | PROT_WRITE,
                        MAP_SHARED,
                        shm_fd,
                        0);

        if (shm_base == MAP_FAILED) {
                LOG_DBGF("Failed to map shared memory.");
                if (close(shm_fd) == -1)
                        LOG_DBGF("Failed to close invalid shm.");

                if (shm_unlink(fn) == -1)
                        LOG_DBGF("Failed to remove invalid shm.");

                free(rb);
                return NULL;
        }

        rb->shm_base = shm_base;
        rb->ptr_head = (size_t *) (rb->shm_base + SHM_RBUFF_SIZE);
        rb->ptr_tail = (size_t *)
                ((uint8_t *) rb->ptr_head + sizeof(size_t));
        rb->shm_mutex = (pthread_mutex_t *)
                ((uint8_t *) rb->ptr_tail + sizeof(size_t));

        rb->fd = shm_fd;
        rb->pid = pid;

        return rb;
}
void shm_ap_rbuff_close(struct shm_ap_rbuff * rb)
{
        char fn[25];

        if (rb == NULL) {
                LOG_DBGF("Bogus input. Bugging out.");
                return;
        }

        sprintf(fn, SHM_AP_RBUFF_PREFIX "%d", rb->pid);

        if (munmap(rb->shm_base, SHM_RBUFF_FILE_SIZE) == -1)
                LOG_DBGF("Couldn't unmap shared memory.");

        free(rb);
}

void shm_ap_rbuff_destroy(struct shm_ap_rbuff * rb)
{
        char fn[25];


        if (rb == NULL) {
                LOG_DBGF("Bogus input. Bugging out.");
                return;
        }

        if (rb->pid != getpid()) {
                LOG_ERR("Tried to destroy other AP's rbuff.");
                return;
        }

        sprintf(fn, SHM_AP_RBUFF_PREFIX "%d", rb->pid);

        if (munmap(rb->shm_base, SHM_RBUFF_FILE_SIZE) == -1)
                LOG_DBGF("Couldn't unmap shared memory.");

        if (shm_unlink(fn) == -1)
                LOG_DBGF("Failed to unlink shm.");

        free(rb);
}

int shm_ap_rbuff_write(struct shm_ap_rbuff * rb, struct rb_entry * e)
{
        struct rb_entry * pos;

        if (rb == NULL || e == NULL)
                return -1;

        pthread_mutex_lock(rb->shm_mutex);

        if (!shm_rbuff_free(rb)) {
                pthread_mutex_unlock(rb->shm_mutex);
                return -1;
        }

        pos = rb->shm_base + *rb->ptr_head;
        *pos = *e;
        *rb->ptr_head = (*rb->ptr_head + 1) & (SHM_RBUFF_SIZE -1);

        pthread_mutex_unlock(rb->shm_mutex);

        return 0;
}
struct rb_entry * shm_ap_rbuff_read(struct shm_ap_rbuff * rb)
{
        struct rb_entry * e = NULL;

        if (rb == NULL)
                return NULL;

        e = malloc(sizeof(*e));
        if (e == NULL)
                return NULL;

        pthread_mutex_lock(rb->shm_mutex);

        if (shm_rbuff_used(rb) == 0) {
                pthread_mutex_unlock(rb->shm_mutex);
                free(e);
                return NULL;
        }

        *e = *(rb->shm_base + *rb->ptr_tail);

        *rb->ptr_tail = (*rb->ptr_tail + 1) & (SHM_RBUFF_SIZE -1);

        pthread_mutex_unlock(rb->shm_mutex);

        return e;
}
