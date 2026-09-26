/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Ring buffer implementations for incoming packets
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

#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "ssm.h"

#include <ouroboros/ssm_rbuff.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/atomics.h>
#include <ouroboros/errno.h>
#include <ouroboros/fccntl.h>
#include <ouroboros/pthread.h>
#include <ouroboros/time.h>

#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define FN_MAX_CHARS 255

#define SSM_RBUFF_FILESIZE ((SSM_RBUFF_SIZE) * sizeof(ssize_t)                 \
                          + 3 * sizeof(size_t)                                 \
                          + sizeof(pthread_mutex_t)                            \
                          + 2 * sizeof(pthread_cond_t))

#define MODB(x)           ((x) & (SSM_RBUFF_SIZE - 1))

#define HEAD(rb)       (rb->shm_base[LOAD_RELAXED(rb->head)])
#define TAIL(rb)       (rb->shm_base[LOAD_RELAXED(rb->tail)])
#define HEAD_IDX(rb)   (LOAD_ACQUIRE(rb->head))
#define TAIL_IDX(rb)   (LOAD_ACQUIRE(rb->tail))
#define ADVANCE_HEAD(rb)                                                       \
        (STORE_RELEASE(rb->head, MODB(LOAD_RELAXED(rb->head) + 1)))
#define ADVANCE_TAIL(rb)                                                       \
        (STORE_RELEASE(rb->tail, MODB(LOAD_RELAXED(rb->tail) + 1)))
#define QUEUED(rb)     (MODB(HEAD_IDX(rb) - TAIL_IDX(rb)))
#define IS_EMPTY(rb)   (HEAD_IDX(rb) == TAIL_IDX(rb))


/* Delay-bound the TX queue delay at rate * target. */
#define TXQ_MIN_SLOTS   4              /* floor: jitter margin       */
#define TXQ_INIT_SLOTS  64             /* ceiling until measured     */
#define TXQ_EWMA_N      4              /* EWMA weight 1/4            */
#define TXQ_SPW_SHIFT   3              /* aim: 8 samples per window  */
#define TXQ_PERIOD_INIT 16             /* writes between samples     */
#define TXQ_PERIOD_MIN  4
#define TXQ_PERIOD_MAX  64
#define TXQ_MIN_DT_NS   1000LL         /* shorter windows are noise  */
#define TXQ_MAX_RATE    BILLION        /* keeps rate * target in s64 */
#define TXQ_UNLIMITED   (SSM_RBUFF_SIZE - 1)
#define TXQ_DATA_MAX    (TXQ_UNLIMITED - SSM_RBUFF_TXQ_RESERVE)

struct ssm_rbuff {
        ssize_t *         shm_base;     /* start of shared memory   */
        size_t *          head;         /* start of ringbuffer      */
        size_t *          tail;
        size_t *          flags;        /* out-of-band flags (RB_*) */
        pthread_mutex_t * mtx;          /* lock for cond vars only  */
        pthread_cond_t *  add;          /* signal when new data     */
        pthread_cond_t *  del;          /* signal when data removed */
        pid_t             pid;          /* pid of the owner         */
        int               flow_id;      /* flow_id of the flow      */
        size_t            n_users;      /* in-flight users          */
        struct {
                uint64_t target;        /* target queue delay, ns   */
                uint64_t rate;          /* EWMA drain rate, slots/s */
                uint64_t ns;            /* window start, 0 = unset  */
                size_t   limit;         /* current occupancy limit  */
                size_t   wr;            /* writes this window       */
                size_t   due;           /* sample when wr hits this */
                size_t   period;        /* writes between samples   */
                size_t   q0;            /* queued at window start   */
                bool     idle;          /* ring ran empty this one  */
                bool     measured;      /* rate holds a measurement */
        } txq;                          /* tx delay limiter state   */
};

#define MM_FLAGS (PROT_READ | PROT_WRITE)

static struct ssm_rbuff * rbuff_create(pid_t pid,
                                       int   flow_id,
                                       int   flags)
{
        struct ssm_rbuff * rb;
        int                fd;
        ssize_t *          shm_base;
        char               fn[FN_MAX_CHARS];

        sprintf(fn, SSM_RBUFF_PREFIX "%d.%d", pid, flow_id);

        rb = malloc(sizeof(*rb));
        if (rb == NULL)
                goto fail_malloc;

        fd = shm_open(fn, flags, 0666);
        if (fd == -1)
                goto fail_open;

        if ((flags & O_CREAT) && ftruncate(fd, SSM_RBUFF_FILESIZE) < 0)
                goto fail_truncate;

        shm_base = mmap(NULL, SSM_RBUFF_FILESIZE, MM_FLAGS, MAP_SHARED, fd, 0);

        close(fd);

        rb->shm_base = shm_base;
        rb->head     = (size_t *) (rb->shm_base + (SSM_RBUFF_SIZE));
        rb->tail     = (size_t *) (rb->head + 1);
        rb->flags    = (size_t *) (rb->tail + 1);
        rb->mtx      = (pthread_mutex_t *) (rb->flags + 1);
        rb->add      = (pthread_cond_t *) (rb->mtx + 1);
        rb->del      = rb->add + 1;
        rb->pid      = pid;
        rb->flow_id  = flow_id;
        rb->n_users  = 0;
        rb->txq.target = 0;
        rb->txq.rate   = 0;
        rb->txq.ns     = 0;
        rb->txq.limit  = TXQ_INIT_SLOTS;
        rb->txq.wr     = 0;
        rb->txq.due    = TXQ_PERIOD_INIT;
        rb->txq.period = TXQ_PERIOD_INIT;
        rb->txq.q0     = 0;
        rb->txq.idle   = false;
        rb->txq.measured = false;

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

static void rbuff_destroy(struct ssm_rbuff * rb)
{
        munmap(rb->shm_base, SSM_RBUFF_FILESIZE);

        free(rb);
}

struct ssm_rbuff * ssm_rbuff_create(pid_t pid,
                                    int   flow_id)
{
        struct ssm_rbuff *  rb;
        pthread_mutexattr_t mattr;
        pthread_condattr_t  cattr;
        mode_t              mask;

        mask = umask(0);

        rb = rbuff_create(pid, flow_id, O_CREAT | O_EXCL | O_RDWR);

        umask(mask);

        if (rb == NULL)
                goto fail_rb;

        if (pthread_mutexattr_init(&mattr) != 0)
                goto fail_mattr;

        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
#ifdef HAVE_ROBUST_MUTEX
        pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
#endif
        if (pthread_mutex_init(rb->mtx, &mattr) != 0)
                goto fail_mutex;

        if (pthread_condattr_init(&cattr) != 0)
                goto fail_cattr;

        pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(rb->add, &cattr) != 0)
                goto fail_add;

        if (pthread_cond_init(rb->del, &cattr) != 0)
                goto fail_del;

        *rb->flags  = RB_RDWR;
        *rb->head = 0;
        *rb->tail = 0;

        rb->pid     = pid;
        rb->flow_id = flow_id;

        pthread_mutexattr_destroy(&mattr);
        pthread_condattr_destroy(&cattr);

        return rb;

 fail_del:
        pthread_cond_destroy(rb->add);
 fail_add:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(rb->mtx);
 fail_mutex:
        pthread_mutexattr_destroy(&mattr);
 fail_mattr:
        ssm_rbuff_destroy(rb);
 fail_rb:
        return NULL;
}

void ssm_rbuff_destroy(struct ssm_rbuff * rb)
{
        char fn[FN_MAX_CHARS];

        assert(rb != NULL);

        sprintf(fn, SSM_RBUFF_PREFIX "%d.%d", rb->pid, rb->flow_id);

        ssm_rbuff_close(rb);

        shm_unlink(fn);
}

struct ssm_rbuff * ssm_rbuff_open(pid_t pid,
                                  int   flow_id)
{
        return rbuff_create(pid, flow_id, O_RDWR);
}

void ssm_rbuff_close(struct ssm_rbuff * rb)
{
        assert(rb);

        while (LOAD(&rb->n_users) > 0) {
                struct timespec tic = TIMESPEC_INIT_US(100);

                nanosleep(&tic, NULL);
        }

        rbuff_destroy(rb);
}

/* Cancel cleanup for a blocked reader: unlock mtx AND drop the n_users ref. */
static void __cleanup_rbuff_reader(void * o)
{
        struct ssm_rbuff * rb = (struct ssm_rbuff *) o;

        pthread_mutex_unlock(rb->mtx);
        FETCH_SUB(&rb->n_users, 1);
}

static bool txq_is_on(struct ssm_rbuff * rb)
{
        return LOAD_RELAXED(&rb->txq.target) != 0;
}

/* Occupancy that holds the delay at the target; rate 0 gets the floor. */
static size_t rbuff_txq_slots(uint64_t rate,
                              uint64_t target)
{
        uint64_t slots;

        slots = rate * target / BILLION;
        if (slots < TXQ_MIN_SLOTS)
                return TXQ_MIN_SLOTS;

        return slots > TXQ_UNLIMITED ? TXQ_UNLIMITED : (size_t) slots;
}

/* Ceiling for one write (taking into account priority). */
static size_t rbuff_txq_ceiling(struct ssm_rbuff * rb,
                                bool               prio)
{
        size_t lim;
        size_t max;

        if (!txq_is_on(rb))
                return TXQ_UNLIMITED;

        if (!rb->txq.measured)
                lim = TXQ_INIT_SLOTS;
        else
                lim = LOAD_RELAXED(&rb->txq.limit);

        max = TXQ_DATA_MAX;

        if (prio) {
                lim *= SSM_RBUFF_TXQ_PRIO_MUL;
                max  = TXQ_UNLIMITED;
        }

        return lim > max ? max : lim;
}

/* Opens a measurement window at now_ns. Caller holds rb->mtx. */
static void rbuff_txq_anchor(struct ssm_rbuff * rb,
                             uint64_t           now_ns,
                             size_t             queued)
{
        rb->txq.ns   = now_ns;
        rb->txq.q0   = queued;
        rb->txq.wr   = 0;
        rb->txq.due  = rb->txq.period;
        rb->txq.idle = false;
}

/* Enough dequeues to resolve a rate? */
static bool txq_is_blind(struct ssm_rbuff * rb,
                         int64_t            drained,
                         int64_t            dt_ns)
{
        int64_t target = (int64_t) LOAD_RELAXED(&rb->txq.target);

        if (drained * 2 >= (int64_t) rb->txq.period)
                return false;

        return dt_ns < (target >> TXQ_SPW_SHIFT);
}

/* Leaves the window open and retries a period later. */
static void rbuff_txq_defer(struct ssm_rbuff * rb)
{
        rb->txq.due = rb->txq.wr + rb->txq.period;
}

/* Aims the sample period at 1 << TXQ_SPW_SHIFT per target window. */
static size_t rbuff_txq_retune(size_t  period,
                               int64_t dt_ns,
                               int64_t target)
{
        if (dt_ns > (target >> TXQ_SPW_SHIFT)) {
                period /= 2;
                return period < TXQ_PERIOD_MIN ? TXQ_PERIOD_MIN : period;
        }

        if (dt_ns < (target >> (TXQ_SPW_SHIFT + 1))) {
                period *= 2;
                return period > TXQ_PERIOD_MAX ? TXQ_PERIOD_MAX : period;
        }

        return period;
}

/* Only raise the estimate if the window ran empty. Call holding rb->mtx. */
static void rbuff_txq_sample(struct ssm_rbuff * rb,
                             size_t             queued)
{
        struct timespec now;
        uint64_t        now_ns;
        int64_t         dt_ns;
        int64_t         target;
        int64_t         drained;
        int64_t         sample;
        int64_t         rate;
        size_t          limit;
        size_t          was;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        now_ns = TS_TO_UINT64(now);

        dt_ns  = (int64_t) (now_ns - rb->txq.ns);
        if (rb->txq.ns == 0 || dt_ns < 0) {
                rbuff_txq_anchor(rb, now_ns, queued);
                return;
        }

        if (dt_ns < TXQ_MIN_DT_NS) {
                rbuff_txq_defer(rb);
                return;
        }

        target  = (int64_t) LOAD_RELAXED(&rb->txq.target);
        drained = (int64_t) rb->txq.wr + (int64_t) rb->txq.q0
                - (int64_t) queued;
        assert(drained >= 0);

        sample  = drained * BILLION / dt_ns;
        rate    = (int64_t) rb->txq.rate;
        if (sample > rate && txq_is_blind(rb, drained, dt_ns)) {
                rbuff_txq_defer(rb);
                return;
        }

        if (!rb->txq.measured)
                rate = sample;
        else if (rb->txq.idle && queued <= TXQ_MIN_SLOTS)
                rate = sample > rate ? sample : rate;
        else
                rate = (rate * (TXQ_EWMA_N - 1) + sample) / TXQ_EWMA_N;

        if (rate > TXQ_MAX_RATE)
                rate = TXQ_MAX_RATE;

        limit = rbuff_txq_slots((uint64_t) rate, (uint64_t) target);
        was   = rbuff_txq_ceiling(rb, false);

        rb->txq.rate   = (uint64_t) rate;
        rb->txq.period = rbuff_txq_retune(rb->txq.period, dt_ns, target);

        STORE_RELAXED(&rb->txq.limit, limit);
        STORE_RELAXED(&rb->txq.measured, true);

        if (rbuff_txq_ceiling(rb, false) > was)
                pthread_cond_broadcast(rb->del);

        rbuff_txq_anchor(rb, now_ns, queued);
}

/*
 * Counts one enqueue. A prio write triggers no sample: it is the only
 * traffic left in a stall, and would shrink the ceiling it needs.
 */
static void rbuff_txq_touch(struct ssm_rbuff * rb,
                            bool               was_empty,
                            bool               prio)
{
        ++rb->txq.wr;

        if (was_empty)
                rb->txq.idle = true;

        if (prio)
                return;

        if (rb->txq.wr >= rb->txq.due)
                rbuff_txq_sample(rb, QUEUED(rb));
}

/* prio outranks new data up to its own, higher, ceiling. */
static int rbuff_write_nb(struct ssm_rbuff * rb,
                          size_t             off,
                          bool               prio)
{
        size_t flags;
        bool   was_empty;
        int    ret = 0;

        assert(rb != NULL);

        FETCH_ADD(&rb->n_users, 1);

        flags = LOAD(rb->flags);
        if (flags != RB_RDWR) {
                if (flags & RB_FLOWDOWN) {
                        ret = -EFLOWDOWN;
                        goto fail_flags;
                }

                if (!(flags & RB_WR)) {
                        ret = -ENOTALLOC;
                        goto fail_flags;
                }
        }

        robust_mutex_lock(rb->mtx);

        if (QUEUED(rb) >= rbuff_txq_ceiling(rb, prio)) {
                ret = -EAGAIN;
                goto fail_mutex;
        }

        was_empty = IS_EMPTY(rb);

        HEAD(rb) = (ssize_t) off;

        ADVANCE_HEAD(rb);

        if (was_empty)
                pthread_cond_broadcast(rb->add);

        if (txq_is_on(rb))
                rbuff_txq_touch(rb, was_empty, prio);

        pthread_mutex_unlock(rb->mtx);

        FETCH_SUB(&rb->n_users, 1);

        return 0;

 fail_mutex:
        pthread_mutex_unlock(rb->mtx);
 fail_flags:
        FETCH_SUB(&rb->n_users, 1);
        return ret;
}

int ssm_rbuff_write(struct ssm_rbuff * rb,
                    size_t             off)
{
        return rbuff_write_nb(rb, off, false);
}

/* For a packet the peer is already waiting on; skips the limit. */
int ssm_rbuff_write_prio(struct ssm_rbuff * rb,
                         size_t             off)
{
        return rbuff_write_nb(rb, off, true);
}

int ssm_rbuff_write_b(struct ssm_rbuff *      rb,
                      size_t                  off,
                      const struct timespec * abstime)
{
        size_t flags;
        int    ret = 0;
        int    err;
        bool   was_empty;

        assert(rb != NULL);

        FETCH_ADD(&rb->n_users, 1);

        flags = LOAD(rb->flags);
        if (flags != RB_RDWR) {
                if (flags & RB_FLOWDOWN) {
                        ret = -EFLOWDOWN;
                        goto fail_flags;
                }

                if (!(flags & RB_WR)) {
                        ret = -ENOTALLOC;
                        goto fail_flags;
                }
        }

        robust_mutex_lock(rb->mtx);

        pthread_cleanup_push(__cleanup_rbuff_reader, rb);

        while (QUEUED(rb) >= rbuff_txq_ceiling(rb, false)) {
                flags = LOAD(rb->flags);
                if (flags & RB_FLOWDOWN) {
                        ret = -EFLOWDOWN;
                        break;
                }

                err = robust_wait(rb->del, rb->mtx, abstime);
                if (err == EOWNERDEAD)
                        continue;

                if (err != 0) {
                        ret = -err;
                        break;
                }
        }

        pthread_cleanup_pop(false);

        if (ret == 0) {
                was_empty = IS_EMPTY(rb);
                HEAD(rb) = (ssize_t) off;

                ADVANCE_HEAD(rb);

                if (was_empty)
                        pthread_cond_broadcast(rb->add);

                if (txq_is_on(rb))
                        rbuff_txq_touch(rb, was_empty, false);
        }

        pthread_mutex_unlock(rb->mtx);

 fail_flags:
        FETCH_SUB(&rb->n_users, 1);
        return ret;
}

static int check_rb_flags(struct ssm_rbuff * rb)
{
        size_t flags;

        assert(rb != NULL);

        flags = LOAD(rb->flags);
        if (flags & RB_FLOWDOWN)
                return -EFLOWDOWN;

        if (flags & RB_FLOWPEER)
                return -EFLOWPEER;

        if (!(flags & RB_RD))
                return -ENOTALLOC;

        return -EAGAIN;
}

ssize_t ssm_rbuff_read(struct ssm_rbuff * rb)
{
        ssize_t ret;

        assert(rb != NULL);

        FETCH_ADD(&rb->n_users, 1);

        if (IS_EMPTY(rb)) {
                ret = check_rb_flags(rb);
                goto out;
        }

        robust_mutex_lock(rb->mtx);

        if (IS_EMPTY(rb)) {
                pthread_mutex_unlock(rb->mtx);

                ret = check_rb_flags(rb);
                goto out;
        }

        ret = TAIL(rb);

        ADVANCE_TAIL(rb);

        pthread_cond_broadcast(rb->del);

        pthread_mutex_unlock(rb->mtx);

 out:
        FETCH_SUB(&rb->n_users, 1);

        return ret;
}

ssize_t ssm_rbuff_read_b(struct ssm_rbuff *      rb,
                         const struct timespec * abstime)
{
        ssize_t idx = -1;
        size_t  flags;

        assert(rb != NULL);

        FETCH_ADD(&rb->n_users, 1);

        flags = LOAD(rb->flags);
        if (IS_EMPTY(rb) && (flags & RB_FLOWDOWN)) {
                idx = -EFLOWDOWN;
                goto out;
        }

        robust_mutex_lock(rb->mtx);

        pthread_cleanup_push(__cleanup_rbuff_reader, rb);

        while (IS_EMPTY(rb)) {
                if (idx == -ETIMEDOUT)
                        break;

                if (check_rb_flags(rb) != -EAGAIN)
                        break;

                idx = -robust_wait(rb->add, rb->mtx, abstime);
        }

        pthread_cleanup_pop(false);

        if (!IS_EMPTY(rb)) {
                idx = TAIL(rb);

                ADVANCE_TAIL(rb);
                pthread_cond_broadcast(rb->del);
        } else if (idx != -ETIMEDOUT) {
                idx = check_rb_flags(rb);
        }

        pthread_mutex_unlock(rb->mtx);

        assert(idx != -EAGAIN);

 out:
        FETCH_SUB(&rb->n_users, 1);
        return idx;
}

void ssm_rbuff_set_flags(struct ssm_rbuff * rb,
                         uint32_t           flags)
{
        assert(rb != NULL);

        robust_mutex_lock(rb->mtx);

        FETCH_OR(rb->flags, (size_t) flags);
        pthread_cond_broadcast(rb->add);
        pthread_cond_broadcast(rb->del);

        pthread_mutex_unlock(rb->mtx);
}

void ssm_rbuff_clr_flags(struct ssm_rbuff * rb,
                         uint32_t           flags)
{
        assert(rb != NULL);

        robust_mutex_lock(rb->mtx);

        FETCH_AND(rb->flags, ~(size_t) flags);
        pthread_cond_broadcast(rb->add);
        pthread_cond_broadcast(rb->del);

        pthread_mutex_unlock(rb->mtx);
}

uint32_t ssm_rbuff_get_flags(struct ssm_rbuff * rb)
{
        assert(rb != NULL);

        return (uint32_t) LOAD(rb->flags);
}

/* Current occupancy limit; SSM_RBUFF_SIZE - 1 when unlimited. */
size_t ssm_rbuff_get_limit(struct ssm_rbuff * rb)
{
        assert(rb != NULL);

        return rbuff_txq_ceiling(rb, false);
}

/* Wakes up writers because target may have changed. */
void ssm_rbuff_set_txq_target(struct ssm_rbuff *      rb,
                              const struct timespec * ts)
{
        uint64_t target;
        size_t   limit;

        assert(rb != NULL);
        assert(ts != NULL);
        assert(ts->tv_sec >= 0);
        assert(ts->tv_nsec >= 0);
        assert(ts->tv_nsec < BILLION);

        target = TS_TO_UINT64(*ts);

        assert(target <= SSM_RBUFF_TXQ_MAX_DELAY);

        robust_mutex_lock(rb->mtx);

        limit = rbuff_txq_slots(rb->txq.rate, target);

        rb->txq.period = TXQ_PERIOD_INIT;

        rbuff_txq_anchor(rb, 0, QUEUED(rb));

        STORE_RELAXED(&rb->txq.limit, limit);
        STORE_RELAXED(&rb->txq.target, target);

        pthread_cond_broadcast(rb->del);

        pthread_mutex_unlock(rb->mtx);
}

/* Current target queueing delay for the tx occupancy limiter. */
void ssm_rbuff_get_txq_target(struct ssm_rbuff * rb,
                              struct timespec *  ts)
{
        assert(rb != NULL);
        assert(ts != NULL);

        UINT64_TO_TS(LOAD_RELAXED(&rb->txq.target), ts);
}

int ssm_rbuff_drain(struct ssm_rbuff *      rb,
                    const struct timespec * abstime)
{
        int ret = 0;
        int err;

        assert(rb != NULL);

        FETCH_ADD(&rb->n_users, 1);

        robust_mutex_lock(rb->mtx);

        pthread_cleanup_push(__cleanup_rbuff_reader, rb);

        while (!IS_EMPTY(rb)) {
                if (LOAD(rb->flags) & RB_FLOWDOWN) {
                        ret = -EFLOWDOWN;
                        break;
                }

                err = robust_wait(rb->del, rb->mtx, abstime);
                if (err == EOWNERDEAD)
                        continue;

                if (err != 0) {
                        ret = -err;
                        break;
                }
        }

        pthread_cleanup_pop(false);

        pthread_mutex_unlock(rb->mtx);

        FETCH_SUB(&rb->n_users, 1);

        return ret;
}

size_t ssm_rbuff_queued(struct ssm_rbuff * rb)
{
        assert(rb != NULL);

        return QUEUED(rb);
}

int ssm_rbuff_mlock(struct ssm_rbuff * rb)
{
        assert(rb != NULL);

        return mlock(rb->shm_base, SSM_RBUFF_FILESIZE);
}
