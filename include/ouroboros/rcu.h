/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Read-mostly pointer publication (RCU, with a locked fallback)
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

#ifndef OUROBOROS_LIB_RCU_H
#define OUROBOROS_LIB_RCU_H

/*
 * Lock-free reads of published pointers via liburcu (urcu-bp) when
 * available; a per-object rwlock fallback otherwise.
 * Include config.h before this header so HAVE_LIBURCU is defined.
 *
 * Embed a struct rcu_guard in the object. A reader brackets its access
 * with rcu_rdlock/rcu_rdunlock and reads published pointers via rcu_deref.
 * A writer serialises with rcu_wrlock/rcu_wrunlock and publishes via
 * rcu_assign; after unlock it reclaims a now-unreachable object with
 * rcu_reclaim (waits out live readers) before freeing it. rcu_drain waits
 * out all readers at teardown.
 */

#include <ouroboros/pthread.h>

#ifdef HAVE_LIBURCU

#include <urcu-bp.h>

struct rcu_guard {
        pthread_mutex_t w; /* serialises writers; readers use RCU */
};

#define rcu_guard_init(g)   pthread_mutex_init(&(g)->w, NULL)
#define rcu_guard_fini(g)   pthread_mutex_destroy(&(g)->w)
#define rcu_rdlock(g)       ((void) (g), rcu_read_lock())
#define rcu_rdunlock(g)     ((void) (g), rcu_read_unlock())
#define rcu_wrlock(g)       pthread_mutex_lock(&(g)->w)
#define rcu_wrunlock(g)     pthread_mutex_unlock(&(g)->w)
#define rcu_deref(p)        rcu_dereference(p)
#define rcu_assign(p, v)    rcu_assign_pointer(p, v)
#define rcu_reclaim(g)      ((void) (g), synchronize_rcu())
#define rcu_drain(g)        ((void) (g), synchronize_rcu())

/* TSan can miss the publish/consume barrier under urcu. */
#if defined(__SANITIZE_THREAD__)
#define RCU_TSAN_ANNOTATE
#endif
#if defined(__has_feature)
#if __has_feature(thread_sanitizer)
#define RCU_TSAN_ANNOTATE
#endif
#endif

/*
 * Publish/consume annotations re-expose liburcu's rcu_assign/rcu_deref edge to
 * TSan, which cannot see liburcu's barriers. Call rcu_publish(p) before
 * publishing p with rcu_assign, and rcu_consume(p) after reading it with
 * rcu_deref. No-op without liburcu (the rwlock fallback already gives TSan the
 * edge) or without TSan.
 */
#ifdef RCU_TSAN_ANNOTATE
#include <sanitizer/tsan_interface.h>
#define rcu_publish(p)   __tsan_release(p)
#define rcu_consume(p)   __tsan_acquire(p)
#else
#define rcu_publish(p)   ((void) (p))
#define rcu_consume(p)   ((void) (p))
#endif

#else /* !HAVE_LIBURCU : per-object rwlock fallback */

struct rcu_guard {
        pthread_rwlock_t rw;   /* readers rd, writers wr */
};

#define rcu_guard_init(g)   pthread_rwlock_init(&(g)->rw, NULL)
#define rcu_guard_fini(g)   pthread_rwlock_destroy(&(g)->rw)
#define rcu_rdlock(g)       pthread_rwlock_rdlock(&(g)->rw)
#define rcu_rdunlock(g)     pthread_rwlock_unlock(&(g)->rw)
#define rcu_wrlock(g)       pthread_rwlock_wrlock(&(g)->rw)
#define rcu_wrunlock(g)     pthread_rwlock_unlock(&(g)->rw)
#define rcu_deref(p)        (p)
#define rcu_assign(p, v)    ((p) = (v))
#define rcu_reclaim(g)      ((void) (g))  /* wrlock already excluded readers */
#define rcu_drain(g)        (pthread_rwlock_wrlock(&(g)->rw),  \
                             pthread_rwlock_unlock(&(g)->rw))

/* rwlock already gives TSan the publish/consume edge; no annotation. */
#define rcu_publish(p)      ((void) (p))
#define rcu_consume(p)      ((void) (p))

#endif /* HAVE_LIBURCU */

#endif /* OUROBOROS_LIB_RCU_H */
