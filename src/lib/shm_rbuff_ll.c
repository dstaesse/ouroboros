/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Lockless ring buffer for incoming packets
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

#define RB_HEAD __sync_fetch_and_add(rb->head, 0)
#define RB_TAIL __sync_fetch_and_add(rb->tail, 0)

void shm_rbuff_destroy(struct shm_rbuff * rb)
{
        char fn[FN_MAX_CHARS];

        assert(rb);

        sprintf(fn, SHM_RBUFF_PREFIX "%d.%d", rb->pid, rb->flow_id);

        shm_rbuff_close(rb);

        shm_unlink(fn);
}

int shm_rbuff_write(struct shm_rbuff * rb,
                    size_t             idx)
{
        size_t ohead;
        size_t nhead;
        bool   was_empty = false;

        assert(rb);
        assert(idx < SHM_BUFFER_SIZE);

        if (__sync_fetch_and_add(rb->acl, 0) != ACL_RDWR) {
                if (__sync_fetch_and_add(rb->acl, 0) & ACL_FLOWDOWN)
                        return -EFLOWDOWN;
                else if (__sync_fetch_and_add(rb->acl, 0) & ACL_RDONLY)
                        return -ENOTALLOC;
        }

        if (!shm_rbuff_free(rb))
                return -EAGAIN;

        if (shm_rbuff_empty(rb))
                was_empty = true;

        nhead = RB_HEAD;

        *(rb->shm_base + nhead) = (ssize_t) idx;

        do {
                ohead = nhead;
                nhead = (ohead + 1) & ((SHM_BUFFER_SIZE) - 1);
                nhead = __sync_val_compare_and_swap(rb->head, ohead, nhead);
        } while (nhead != ohead);

        if (was_empty)
                pthread_cond_broadcast(rb->add);

        return 0;
}

ssize_t shm_rbuff_read(struct shm_rbuff * rb)
{
        size_t otail;
        size_t ntail;

        assert(rb);

        if (shm_rbuff_empty(rb))
                return __sync_fetch_and_add(rb->acl, 0) & ACL_FLOWDOWN ?
                        -EFLOWDOWN : -EAGAIN;

        ntail = RB_TAIL;

        do {
                otail = ntail;
                ntail = (otail + 1) & ((SHM_BUFFER_SIZE) - 1);
                ntail = __sync_val_compare_and_swap(rb->tail, otail, ntail);
        } while (ntail != otail);

        pthread_cond_broadcast(rb->del);

        return *(rb->shm_base + ntail);
}

ssize_t shm_rbuff_read_b(struct shm_rbuff *      rb,
                         const struct timespec * abstime)
{
        ssize_t idx = -1;

        assert(rb);

        /* try a non-blocking read first */
        idx = shm_rbuff_read(rb);
        if (idx != -EAGAIN)
                return idx;

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rb->lock);
#endif
        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) rb->lock);

        while (shm_rbuff_empty(rb) && (idx != -ETIMEDOUT)) {
                if (abstime != NULL)
                        idx = -pthread_cond_timedwait(rb->add,
                                                      rb->lock,
                                                      abstime);
                else
                        idx = -pthread_cond_wait(rb->add, rb->lock);
#ifdef HAVE_ROBUST_MUTEX
                if (idx == -EOWNERDEAD)
                        pthread_mutex_consistent(rb->lock);
#endif
        }

        if (idx != -ETIMEDOUT) {
                /* do a nonblocking read */
                idx = shm_rbuff_read(rb);

                assert(idx >= 0);
        }

        pthread_cleanup_pop(true);

        return idx;
}

void shm_rbuff_set_acl(struct shm_rbuff * rb,
                       uint32_t           flags)
{
        assert(rb);

        __sync_bool_compare_and_swap(rb->acl, *rb->acl, flags);
}

uint32_t shm_rbuff_get_acl(struct shm_rbuff * rb)
{
        assert(rb);

        return __sync_fetch_and_add(rb->acl, 0);
}

void shm_rbuff_fini(struct shm_rbuff * rb)
{
        assert(rb);

        if (shm_rbuff_empty(rb))
                return;

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rb->lock);
#endif

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) rb->lock);

        while (!shm_rbuff_empty(rb))
#ifndef HAVE_ROBUST_MUTEX
                pthread_cond_wait(rb->del, rb->lock);
#else
                if (pthread_cond_wait(rb->del, rb->lock) == EOWNERDEAD)
                        pthread_mutex_consistent(rb->lock);
#endif
        pthread_cleanup_pop(true);
}

size_t shm_rbuff_queued(struct shm_rbuff * rb)
{
        assert(rb);

        return shm_rbuff_used(rb);
}
