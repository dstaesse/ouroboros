/*
 * Ouroboros - Copyright (C) 2016 - 2019
 *
 * Ring buffer for incoming packets
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

void shm_rbuff_destroy(struct shm_rbuff * rb)
{
        char fn[FN_MAX_CHARS];

        assert(rb);

#ifdef CONFIG_OUROBOROS_DEBUG
        pthread_mutex_lock(rb->lock);

        assert(shm_rbuff_empty(rb));

        pthread_mutex_unlock(rb->lock);
#endif
        sprintf(fn, SHM_RBUFF_PREFIX "%d.%d", rb->pid, rb->flow_id);

        shm_rbuff_close(rb);

        shm_unlink(fn);
}

int shm_rbuff_write(struct shm_rbuff * rb,
                    size_t             idx)
{
        int ret = 0;

        assert(rb);
        assert(idx < SHM_BUFFER_SIZE);

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rb->lock);
#endif

        if (*rb->acl != ACL_RDWR) {
                if (*rb->acl & ACL_FLOWDOWN)
                        ret = -EFLOWDOWN;
                else if (*rb->acl & ACL_RDONLY)
                        ret = -ENOTALLOC;
                goto err;
        }

        if (!shm_rbuff_free(rb)) {
                ret = -EAGAIN;
                goto err;
        }

        if (shm_rbuff_empty(rb))
                pthread_cond_broadcast(rb->add);

        *head_el_ptr(rb) = (ssize_t) idx;
        *rb->head = (*rb->head + 1) & ((SHM_RBUFF_SIZE) - 1);

        pthread_mutex_unlock(rb->lock);

        return 0;
 err:
        pthread_mutex_unlock(rb->lock);
        return ret;
}

int shm_rbuff_write_b(struct shm_rbuff *      rb,
                      size_t                  idx,
                      const struct timespec * abstime)
{
        int ret = 0;

        assert(rb);
        assert(idx < SHM_BUFFER_SIZE);

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rb->lock);
#endif

        if (*rb->acl != ACL_RDWR) {
                if (*rb->acl & ACL_FLOWDOWN)
                        ret = -EFLOWDOWN;
                else if (*rb->acl & ACL_RDONLY)
                        ret = -ENOTALLOC;
                goto err;
        }

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) rb->lock);

        while (!shm_rbuff_free(rb) && ret != -ETIMEDOUT) {
                if (abstime != NULL)
                        ret = -pthread_cond_timedwait(rb->add,
                                                      rb->lock,
                                                      abstime);
                else
                        ret = -pthread_cond_wait(rb->add, rb->lock);
#ifdef HAVE_ROBUST_MUTEX
                if (ret == -EOWNERDEAD)
                        pthread_mutex_consistent(rb->lock);
#endif
        }

        if (shm_rbuff_empty(rb))
                pthread_cond_broadcast(rb->add);

        if (ret != -ETIMEDOUT) {
                *head_el_ptr(rb) = (ssize_t) idx;
                *rb->head = (*rb->head + 1) & ((SHM_RBUFF_SIZE) - 1);
        }

        pthread_cleanup_pop(true);

        return ret;
 err:
        pthread_mutex_unlock(rb->lock);
        return ret;
}

ssize_t shm_rbuff_read(struct shm_rbuff * rb)
{
        ssize_t ret = 0;

        assert(rb);

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rb->lock);
#endif

        if (shm_rbuff_empty(rb)) {
                ret = *rb->acl & ACL_FLOWDOWN ? -EFLOWDOWN : -EAGAIN;
                pthread_mutex_unlock(rb->lock);
                return ret;
        }

        ret = *tail_el_ptr(rb);
        *rb->tail = (*rb->tail + 1) & ((SHM_RBUFF_SIZE) - 1);
        pthread_cond_broadcast(rb->del);

        pthread_mutex_unlock(rb->lock);

        return ret;
}

ssize_t shm_rbuff_read_b(struct shm_rbuff *      rb,
                         const struct timespec * abstime)
{
        ssize_t idx = -1;

        assert(rb);

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rb->lock);
#endif

        if (shm_rbuff_empty(rb) && (*rb->acl & ACL_FLOWDOWN)) {
                pthread_mutex_unlock(rb->lock);
                return -EFLOWDOWN;
        }

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
                idx = *tail_el_ptr(rb);
                *rb->tail = (*rb->tail + 1) & ((SHM_RBUFF_SIZE) - 1);
                pthread_cond_broadcast(rb->del);
        }

        pthread_cleanup_pop(true);

        return idx;
}

void shm_rbuff_set_acl(struct shm_rbuff * rb,
                       uint32_t           flags)
{
        assert(rb);

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rb->lock);
#endif
        *rb->acl = (size_t) flags;

        pthread_mutex_unlock(rb->lock);
}

uint32_t shm_rbuff_get_acl(struct shm_rbuff * rb)
{
        uint32_t flags;

        assert(rb);

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rb->lock);
#endif
        flags = (uint32_t) *rb->acl;

        pthread_mutex_unlock(rb->lock);

        return flags;
}

void shm_rbuff_fini(struct shm_rbuff * rb)
{
        assert(rb);

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
        size_t ret;

        assert(rb);

#ifndef HAVE_ROBUST_MUTEX
        pthread_mutex_lock(rb->lock);
#else
        if (pthread_mutex_lock(rb->lock) == EOWNERDEAD)
                pthread_mutex_consistent(rb->lock);
#endif

        ret = shm_rbuff_used(rb);

        pthread_mutex_unlock(rb->lock);

        return ret;
}
