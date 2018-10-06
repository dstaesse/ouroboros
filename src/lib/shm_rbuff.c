/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Ring buffer implementations for incoming packets
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <ouroboros/shm_rbuff.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/errno.h>
#include <ouroboros/fccntl.h>

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

#define SHM_RB_FILE_SIZE ((SHM_BUFFER_SIZE) * sizeof(ssize_t)           \
                          + 3 * sizeof(size_t)                          \
                          + sizeof(pthread_mutex_t)                     \
                          + 2 * sizeof (pthread_cond_t))

#define shm_rbuff_used(rb) ((*rb->head + (SHM_BUFFER_SIZE) - *rb->tail)   \
                            & ((SHM_BUFFER_SIZE) - 1))
#define shm_rbuff_free(rb) (shm_rbuff_used(rb) + 1 < (SHM_BUFFER_SIZE))
#define shm_rbuff_empty(rb) (*rb->head == *rb->tail)
#define head_el_ptr(rb) (rb->shm_base + *rb->head)
#define tail_el_ptr(rb) (rb->shm_base + *rb->tail)

struct shm_rbuff {
        ssize_t *         shm_base; /* start of entry                */
        size_t *          head;     /* start of ringbuffer head      */
        size_t *          tail;     /* start of ringbuffer tail      */
        size_t *          acl;      /* access control                */
        pthread_mutex_t * lock;     /* lock all free space in shm    */
        pthread_cond_t *  add;      /* packet arrived                */
        pthread_cond_t *  del;      /* packet removed                */
        pid_t             pid;      /* pid of the owner              */
        int               flow_id;  /* flow_id of the flow           */
};

void shm_rbuff_close(struct shm_rbuff * rb)
{
        assert(rb);

        munmap(rb->shm_base, SHM_RB_FILE_SIZE);

        free(rb);
}

#define MM_FLAGS (PROT_READ | PROT_WRITE)

struct shm_rbuff * rbuff_create(pid_t pid,
                                int   flow_id,
                                int   flags)
{
        struct shm_rbuff * rb;
        int                fd;
        ssize_t *          shm_base;
        char               fn[FN_MAX_CHARS];

        sprintf(fn, SHM_RBUFF_PREFIX "%d.%d", pid, flow_id);

        rb = malloc(sizeof(*rb));
        if (rb == NULL)
                goto fail_malloc;

        fd = shm_open(fn, flags, 0666);
        if (fd == -1)
                goto fail_open;

        if ((flags & O_CREAT) && ftruncate(fd, SHM_RB_FILE_SIZE - 1) < 0)
                goto fail_truncate;

        shm_base = mmap(NULL, SHM_RB_FILE_SIZE, MM_FLAGS, MAP_SHARED, fd, 0);
        if (shm_base == MAP_FAILED)
                goto fail_truncate;

        close(fd);

        rb->shm_base = shm_base;
        rb->head     = (size_t *) (rb->shm_base + (SHM_BUFFER_SIZE));
        rb->tail     = rb->head + 1;
        rb->acl      = rb->tail + 1;
        rb->lock     = (pthread_mutex_t *) (rb->acl + 1);
        rb->add      = (pthread_cond_t *) (rb->lock + 1);
        rb->del      = rb->add + 1;
        rb->pid      = pid;
        rb->flow_id  = flow_id;

        return rb;

 fail_truncate:
        close(fd);
        if (flags & O_CREAT)
                shm_unlink(fn);
 fail_open:
        free(rb);
 fail_malloc:
        return NULL;
}

struct shm_rbuff * shm_rbuff_create(pid_t pid,
                                    int   flow_id)
{
        struct shm_rbuff *  rb;
        pthread_mutexattr_t mattr;
        pthread_condattr_t  cattr;
        mode_t              mask;

        mask = umask(0);

        rb = rbuff_create(pid, flow_id, O_CREAT | O_EXCL | O_RDWR);

        umask(mask);

        if (rb == NULL)
                goto fail_rb;

        if (pthread_mutexattr_init(&mattr))
                goto fail_mattr;

        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
#ifdef HAVE_ROBUST_MUTEX
        pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
#endif
        if (pthread_mutex_init(rb->lock, &mattr))
                goto fail_mutex;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;

        pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(rb->add, &cattr))
                goto fail_add;

        if (pthread_cond_init(rb->del, &cattr))
                goto fail_del;

        *rb->acl  = ACL_RDWR;
        *rb->head = 0;
        *rb->tail = 0;

        rb->pid = pid;
        rb->flow_id = flow_id;

        pthread_mutexattr_destroy(&mattr);
        pthread_condattr_destroy(&cattr);

        return rb;

 fail_del:
        pthread_cond_destroy(rb->add);
 fail_add:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(rb->lock);
 fail_mutex:
        pthread_mutexattr_destroy(&mattr);
 fail_mattr:
        shm_rbuff_destroy(rb);
 fail_rb:
        return NULL;
}

struct shm_rbuff * shm_rbuff_open(pid_t pid,
                                  int   flow_id)
{
        return rbuff_create(pid, flow_id, O_RDWR);
}

#if (defined(SHM_RBUFF_LOCKLESS) &&                            \
     (defined(__GNUC__) || defined (__clang__)))
#include "shm_rbuff_ll.c"
#else
#include "shm_rbuff_pthr.c"
#endif
