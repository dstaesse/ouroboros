/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Secure Shared Memory Infrastructure (SSMI) Packet Buffer
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

#include <ouroboros/errno.h>
#include <ouroboros/pthread.h>
#include <ouroboros/ssm_pool.h>

#include "ssm.h"

#include <assert.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

/* Global Shared Packet Pool (GSPP) configuration */
static const struct ssm_size_class_cfg ssm_gspp_cfg[SSM_POOL_MAX_CLASSES] = {
        { (1 << 8),  SSM_GSPP_256_BLOCKS  },
        { (1 << 9),  SSM_GSPP_512_BLOCKS  },
        { (1 << 10), SSM_GSPP_1K_BLOCKS   },
        { (1 << 11), SSM_GSPP_2K_BLOCKS   },
        { (1 << 12), SSM_GSPP_4K_BLOCKS   },
        { (1 << 14), SSM_GSPP_16K_BLOCKS  },
        { (1 << 16), SSM_GSPP_64K_BLOCKS  },
        { (1 << 18), SSM_GSPP_256K_BLOCKS },
        { (1 << 20), SSM_GSPP_1M_BLOCKS   },
};

/* Per-User Pool (PUP) configuration */
static const struct ssm_size_class_cfg ssm_pup_cfg[SSM_POOL_MAX_CLASSES] = {
        { (1 << 8),  SSM_PUP_256_BLOCKS  },
        { (1 << 9),  SSM_PUP_512_BLOCKS  },
        { (1 << 10), SSM_PUP_1K_BLOCKS   },
        { (1 << 11), SSM_PUP_2K_BLOCKS   },
        { (1 << 12), SSM_PUP_4K_BLOCKS   },
        { (1 << 14), SSM_PUP_16K_BLOCKS  },
        { (1 << 16), SSM_PUP_64K_BLOCKS  },
        { (1 << 18), SSM_PUP_256K_BLOCKS },
        { (1 << 20), SSM_PUP_1M_BLOCKS   },
};

#define PTR_TO_OFFSET(pool_base, ptr)                                          \
        ((uintptr_t)(ptr) - (uintptr_t)(pool_base))

#define OFFSET_TO_PTR(pool_base, offset)                                       \
        ((offset == 0) ? NULL : (void *)((uintptr_t)(pool_base) + offset))

#define GET_SHARD_FOR_PID(pid) ((int)((pid) % SSM_POOL_SHARDS))

#define LOAD_RELAXED(ptr)                                                      \
        (__atomic_load_n(ptr, __ATOMIC_RELAXED))

#define LOAD_ACQUIRE(ptr)                                                      \
        (__atomic_load_n(ptr, __ATOMIC_ACQUIRE))

#define STORE_RELEASE(ptr, val)                                                \
        (__atomic_store_n(ptr, val, __ATOMIC_RELEASE))

#define LOAD(ptr)                                                              \
        (__atomic_load_n(ptr, __ATOMIC_SEQ_CST))

#define STORE(ptr, val)                                                        \
        (__atomic_store_n(ptr, val, __ATOMIC_SEQ_CST))

#define FETCH_ADD(ptr, val)                                                    \
        (__atomic_fetch_add(ptr, val, __ATOMIC_SEQ_CST))

#define FETCH_SUB(ptr, val)                                                    \
        (__atomic_fetch_sub(ptr, val, __ATOMIC_SEQ_CST))

#define SSM_FILE_SIZE (SSM_POOL_TOTAL_SIZE + sizeof(struct _ssm_pool_hdr))
#define SSM_GSPP_FILE_SIZE (SSM_GSPP_TOTAL_SIZE + sizeof(struct _ssm_pool_hdr))
#define SSM_PUP_FILE_SIZE (SSM_PUP_TOTAL_SIZE + sizeof(struct _ssm_pool_hdr))

#define IS_GSPP(uid)             ((uid) == SSM_GSPP_UID)
#define GET_POOL_TOTAL_SIZE(uid) (IS_GSPP(uid) ? SSM_GSPP_TOTAL_SIZE          \
                                               : SSM_PUP_TOTAL_SIZE)
#define GET_POOL_FILE_SIZE(uid)  (IS_GSPP(uid) ? SSM_GSPP_FILE_SIZE           \
                                               : SSM_PUP_FILE_SIZE)
#define GET_POOL_CFG(uid)        (IS_GSPP(uid) ? ssm_gspp_cfg : ssm_pup_cfg)

struct ssm_pool {
        uint8_t *               shm_base;   /* start of blocks           */
        struct _ssm_pool_hdr *  hdr;        /* shared memory header      */
        void *                  pool_base;  /* base of the memory pool   */
        uid_t                   uid;        /* user owner (0 = GSPP)     */
        size_t                  total_size; /* total data size           */
};

static __inline__
struct ssm_pk_buff * list_remove_head(struct _ssm_list_head * head,
                                      void *                  base)
{
        uint32_t             off;
        uint32_t             next_off;
        struct ssm_pk_buff * blk;

        assert(head != NULL);
        assert(base != NULL);

        off = LOAD(&head->head_offset);
        if (off == 0)
                return NULL;

        /* Validate offset is within pool bounds */
        if (off >= SSM_POOL_TOTAL_SIZE)
                return NULL;

        blk = OFFSET_TO_PTR(base, off);
        next_off = LOAD(&blk->next_offset);



        STORE(&head->head_offset, next_off);
        STORE(&head->count, LOAD(&head->count) - 1);

        return blk;
}
static __inline__ void list_add_head(struct _ssm_list_head * head,
                                     struct ssm_pk_buff *    blk,
                                     void *                  base)
{
        uint32_t off;
        uint32_t old;

        assert(head != NULL);
        assert(blk != NULL);
        assert(base != NULL);

        off = (uint32_t) PTR_TO_OFFSET(base, blk);
        old = LOAD(&head->head_offset);

        STORE(&blk->next_offset, old);
        STORE(&head->head_offset, off);
        STORE(&head->count, LOAD(&head->count) + 1);
}

static __inline__ int select_size_class(struct ssm_pool * pool,
                                        size_t            len)
{
        size_t sz;
        int    i;

        assert(pool != NULL);

        /* Total space needed: header + headspace + data + tailspace */
        sz = sizeof(struct ssm_pk_buff) + SSM_PK_BUFF_HEADSPACE + len
             + SSM_PK_BUFF_TAILSPACE;

        for (i = 0; i < SSM_POOL_MAX_CLASSES; i++) {
                struct _ssm_size_class * sc;

                sc = &pool->hdr->size_classes[i];
                if (sc->object_size > 0 && sz <= sc->object_size)
                        return i;
        }

        return -1;
}

static __inline__ int find_size_class_for_offset(struct ssm_pool * pool,
                                                 size_t            offset)
{
        int c;

        assert(pool != NULL);

        for (c = 0; c < SSM_POOL_MAX_CLASSES; c++) {
                struct _ssm_size_class * sc = &pool->hdr->size_classes[c];

                if (sc->object_size == 0)
                        continue;

                if (offset >= sc->pool_start &&
                    offset < sc->pool_start + sc->pool_size)
                        return c;
        }

        return -1;
}

static void init_size_classes(struct ssm_pool * pool)
{
        const struct ssm_size_class_cfg * cfg;
        struct _ssm_size_class *          sc;
        struct _ssm_shard *               shard;
        pthread_mutexattr_t               mattr;
        pthread_condattr_t                cattr;
        uint8_t *                         region;
        size_t                            offset;
        int                               c; /* class iterator */
        int                               s; /* shard iterator */
        size_t                            i;

        assert(pool != NULL);

        /* Check if already initialized */
        if (LOAD(&pool->hdr->initialized) != 0)
                return;

        cfg = GET_POOL_CFG(pool->uid);

        pthread_mutexattr_init(&mattr);
        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
#ifdef HAVE_ROBUST_MUTEX
        pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
#endif
        pthread_mutexattr_setprotocol(&mattr, PTHREAD_PRIO_INHERIT);

        pthread_condattr_init(&cattr);
        pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        offset = 0;

        for (c = 0; c < SSM_POOL_MAX_CLASSES; c++) {
                if (cfg[c].blocks == 0)
                        continue;

                sc = &pool->hdr->size_classes[c];

                sc->object_size  = cfg[c].size;
                sc->pool_start   = offset;
                sc->pool_size    = cfg[c].size * cfg[c].blocks;
                sc->object_count = cfg[c].blocks;

                /* Initialize all shards */
                for (s = 0; s < SSM_POOL_SHARDS; s++) {
                        shard = &sc->shards[s];

                        STORE(&shard->free_list.head_offset, 0);
                        STORE(&shard->free_list.count, 0);
                        STORE(&shard->free_count, 0);

                        pthread_mutex_init(&shard->mtx, &mattr);
                        pthread_cond_init(&shard->cond, &cattr);
                }

                /* Lazy distribution: put all blocks in shard 0 initially */
                region = pool->shm_base + offset;

                for (i = 0; i < sc->object_count; ++i) {
                        struct ssm_pk_buff * blk;

                        blk = (struct ssm_pk_buff *)
                              (region + i * sc->object_size);

                        STORE(&blk->refcount, 0);
                        blk->allocator_pid = 0;
                        STORE(&blk->next_offset, 0);

                        list_add_head(&sc->shards[0].free_list, blk,
                                      pool->pool_base);
                        FETCH_ADD(&sc->shards[0].free_count, 1);
                }

                offset += sc->pool_size;
        }

        /* Mark as initialized - acts as memory barrier */
        STORE(&pool->hdr->initialized, 1);

        pthread_mutexattr_destroy(&mattr);
        pthread_condattr_destroy(&cattr);
}

/*
 * Reclaim all blocks allocated by a specific pid in a size class.
 * Called with shard mutex held.
 */
static size_t reclaim_pid_from_sc(struct _ssm_size_class * sc,
                                  struct _ssm_shard *      shard,
                                  void *                   pool_base,
                                  pid_t                    pid)
{
        uint8_t *            region;
        size_t               i;
        size_t               recovered = 0;
        struct ssm_pk_buff * blk;

        region = (uint8_t *) pool_base + sc->pool_start;

        for (i = 0; i < sc->object_count; ++i) {
                blk = (struct ssm_pk_buff *)(region + i * sc->object_size);

                if (blk->allocator_pid == pid && LOAD(&blk->refcount) > 0) {
                        STORE(&blk->refcount, 0);
                        blk->allocator_pid = 0;
                        list_add_head(&shard->free_list, blk, pool_base);
                        FETCH_ADD(&shard->free_count, 1);
                        recovered++;
                }
        }

        return recovered;
}

void ssm_pool_reclaim_orphans(struct ssm_pool * pool,
                              pid_t             pid)
{
        size_t sc_idx;

        if (pool == NULL || pid <= 0)
                return;

        for (sc_idx = 0; sc_idx < SSM_POOL_MAX_CLASSES; sc_idx++) {
                struct _ssm_size_class * sc;
                struct _ssm_shard *      shard;

                sc = &pool->hdr->size_classes[sc_idx];
                if (sc->object_count == 0)
                        continue;

                /* Reclaim to shard 0 for simplicity */
                shard = &sc->shards[0];
                robust_mutex_lock(&shard->mtx);
                reclaim_pid_from_sc(sc, shard, pool->pool_base, pid);
                pthread_mutex_unlock(&shard->mtx);
        }
}

static __inline__
struct ssm_pk_buff * try_alloc_from_shard(struct _ssm_shard * shard,
                                          void *              base)
{
        struct ssm_pk_buff * blk;

        robust_mutex_lock(&shard->mtx);

        if (LOAD(&shard->free_count) > 0) {
                blk = list_remove_head(&shard->free_list, base);
                if (blk != NULL) {
                        FETCH_SUB(&shard->free_count, 1);
                        return blk; /* Caller must unlock */
                }
                FETCH_SUB(&shard->free_count, 1);
        }

        pthread_mutex_unlock(&shard->mtx);
        return NULL;
}

static __inline__ ssize_t init_block(struct ssm_pool *        pool,
                                     struct _ssm_size_class * sc,
                                     struct _ssm_shard *      shard,
                                     struct ssm_pk_buff *     blk,
                                     size_t                   len,
                                     uint8_t **               ptr,
                                     struct ssm_pk_buff **    spb)
{
        STORE(&blk->refcount, 1);
        blk->allocator_pid = getpid();
        blk->size          = (uint32_t) (sc->object_size -
                                         sizeof(struct ssm_pk_buff));
        blk->pk_head       = SSM_PK_BUFF_HEADSPACE;
        blk->pk_tail       = blk->pk_head + (uint32_t) len;
        blk->off           = (uint32_t) PTR_TO_OFFSET(pool->pool_base, blk);

        pthread_mutex_unlock(&shard->mtx);

        *spb = blk;
        if (ptr != NULL)
                *ptr = blk->data + blk->pk_head;

        return blk->off;
}

/* Non-blocking allocation from size class */
static ssize_t alloc_from_sc(struct ssm_pool *     pool,
                             int                   idx,
                             size_t                len,
                             uint8_t **            ptr,
                             struct ssm_pk_buff ** spb)
{
        struct _ssm_size_class * sc;
        struct ssm_pk_buff *     blk;
        int                      local;
        int                      s;

        assert(pool != NULL);
        assert(idx >= 0 && idx < SSM_POOL_MAX_CLASSES);
        assert(spb != NULL);

        sc = &pool->hdr->size_classes[idx];
        local = GET_SHARD_FOR_PID(getpid());

        for (s = 0; s < SSM_POOL_SHARDS; s++) {
                struct _ssm_shard * shard;
                int                 idx;

                idx = (local + s) % SSM_POOL_SHARDS;
                shard = &sc->shards[idx];

                blk = try_alloc_from_shard(shard, pool->pool_base);
                if (blk != NULL)
                        return init_block(pool, sc, shard, blk, len, ptr, spb);
        }

        return -EAGAIN;
}

/* Blocking allocation from size class */
static ssize_t alloc_from_sc_b(struct ssm_pool *       pool,
                               int                     idx,
                               size_t                  len,
                               uint8_t **              ptr,
                               struct ssm_pk_buff **   spb,
                               const struct timespec * abstime)
{
        struct _ssm_size_class * sc;
        struct _ssm_shard *      shard;
        struct ssm_pk_buff *     blk = NULL;
        int                      local;
        int                      s;
        int                      ret = 0;

        assert(pool != NULL);
        assert(idx >= 0 && idx < SSM_POOL_MAX_CLASSES);
        assert(spb != NULL);

        sc = &pool->hdr->size_classes[idx];
        local = GET_SHARD_FOR_PID(getpid());

        while (blk == NULL && ret != ETIMEDOUT) {
                /* Try non-blocking allocation from any shard */
                for (s = 0; s < SSM_POOL_SHARDS && blk == NULL; s++) {
                        shard = &sc->shards[(local + s) % SSM_POOL_SHARDS];
                        blk = try_alloc_from_shard(shard, pool->pool_base);
                }

                if (blk != NULL)
                        break;

                /* Nothing available, wait for signal */
                shard = &sc->shards[local];
                robust_mutex_lock(&shard->mtx);
                ret = robust_wait(&shard->cond, &shard->mtx, abstime);
                pthread_mutex_unlock(&shard->mtx);
        }

        if (ret == ETIMEDOUT)
                return -ETIMEDOUT;

        return init_block(pool, sc, shard, blk, len, ptr, spb);
}

/* Generate pool filename: uid=0 for GSPP, uid>0 for PUP */
static char * pool_filename(uid_t uid)
{
        char   base[64];

        if (IS_GSPP(uid))
                snprintf(base, sizeof(base), "%s", SSM_GSPP_NAME);
        else
                snprintf(base, sizeof(base), SSM_PUP_NAME_FMT, (int) uid);

        return strdup(base);
}

void ssm_pool_close(struct ssm_pool * pool)
{
        size_t file_size;

        assert(pool != NULL);

        file_size = GET_POOL_FILE_SIZE(pool->uid);

        munmap(pool->shm_base, file_size);
        free(pool);
}

void ssm_pool_destroy(struct ssm_pool * pool)
{
        char * fn;

        assert(pool != NULL);

        if (getpid() != pool->hdr->pid && kill(pool->hdr->pid, 0) == 0) {
                ssm_pool_close(pool);
                free(pool);
                return;
        }

        fn = pool_filename(pool->uid);
        if (fn == NULL) {
                ssm_pool_close(pool);
                free(pool);
                return;
        }

        ssm_pool_close(pool);

        shm_unlink(fn);
        free(fn);
}

#define MM_FLAGS (PROT_READ | PROT_WRITE)
static struct ssm_pool * __pool_create(const char * name,
                                       int          flags,
                                       uid_t        uid,
                                       gid_t        gid,
                                       mode_t       mode)
{
        struct ssm_pool * pool;
        int               fd;
        uint8_t *         shm_base;
        size_t            file_size;
        size_t            total_size;

        file_size  = GET_POOL_FILE_SIZE(uid);
        total_size = GET_POOL_TOTAL_SIZE(uid);

        pool = malloc(sizeof(*pool));
        if (pool == NULL)
                goto fail_pool;

        fd = shm_open(name, flags, mode);
        if (fd == -1)
                goto fail_open;

        if (flags & O_CREAT) {
                if (ftruncate(fd, (off_t) file_size) < 0)
                        goto fail_truncate;
                if (uid != geteuid() && fchown(fd, uid, gid) < 0)
                        goto fail_truncate;
        }

        shm_base = mmap(NULL, file_size, MM_FLAGS, MAP_SHARED, fd, 0);
        if (shm_base == MAP_FAILED)
                goto fail_truncate;

        pool->shm_base   = shm_base;
        pool->pool_base  = shm_base;
        pool->hdr        = (struct _ssm_pool_hdr *) (shm_base + total_size);
        pool->uid        = uid;
        pool->total_size = total_size;

        if (flags & O_CREAT)
                pool->hdr->mapped_addr = shm_base;

        close(fd);

        return pool;

 fail_truncate:
        close(fd);
        if (flags & O_CREAT)
                shm_unlink(name);
 fail_open:
        free(pool);
 fail_pool:
        return NULL;
}

struct ssm_pool * ssm_pool_create(uid_t uid,
                                  gid_t gid)
{
        struct ssm_pool *   pool;
        char *              fn;
        mode_t              mask;
        mode_t              mode;
        pthread_mutexattr_t mattr;
        pthread_condattr_t  cattr;

        fn = pool_filename(uid);
        if (fn == NULL)
                goto fail_fn;

        mode = IS_GSPP(uid) ? 0660 : 0600;
        mask = umask(0);

        pool = __pool_create(fn, O_CREAT | O_EXCL | O_RDWR, uid, gid, mode);

        umask(mask);

        if (pool == NULL)
                goto fail_pool;

        if (pthread_mutexattr_init(&mattr))
                goto fail_mattr;

        pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
#ifdef HAVE_ROBUST_MUTEX
        pthread_mutexattr_setrobust(&mattr, PTHREAD_MUTEX_ROBUST);
#endif
        if (pthread_mutex_init(&pool->hdr->mtx, &mattr))
                goto fail_mutex;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;

        pthread_condattr_setpshared(&cattr, PTHREAD_PROCESS_SHARED);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&pool->hdr->healthy, &cattr))
                goto fail_healthy;

        pool->hdr->pid = getpid();
        STORE(&pool->hdr->initialized, 0);

        init_size_classes(pool);

        pthread_mutexattr_destroy(&mattr);
        pthread_condattr_destroy(&cattr);
        free(fn);

        return pool;

 fail_healthy:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(&pool->hdr->mtx);
 fail_mutex:
        pthread_mutexattr_destroy(&mattr);
 fail_mattr:
        ssm_pool_close(pool);
        shm_unlink(fn);
 fail_pool:
        free(fn);
 fail_fn:
        return NULL;
}

struct ssm_pool * ssm_pool_open(uid_t uid)
{
        struct ssm_pool * pool;
        char *            fn;

        fn = pool_filename(uid);
        if (fn == NULL)
                return NULL;

        pool = __pool_create(fn, O_RDWR, uid, 0, 0);
        if (pool != NULL)
                init_size_classes(pool);

        free(fn);

        return pool;
}

void ssm_pool_gspp_purge(void)
{
        char * fn;

        fn = pool_filename(SSM_GSPP_UID);
        if (fn == NULL)
                return;

        shm_unlink(fn);
        free(fn);
}

int ssm_pool_mlock(struct ssm_pool * pool)
{
        size_t file_size;

        assert(pool != NULL);

        file_size = GET_POOL_FILE_SIZE(pool->uid);

        return mlock(pool->shm_base, file_size);
}

ssize_t ssm_pool_alloc(struct ssm_pool *     pool,
                       size_t                count,
                       uint8_t **            ptr,
                       struct ssm_pk_buff ** spb)
{
        int idx;

        assert(pool != NULL);
        assert(spb != NULL);

        idx = select_size_class(pool, count);
        if (idx >= 0)
                return alloc_from_sc(pool, idx, count, ptr, spb);

        return -EMSGSIZE;
}

ssize_t ssm_pool_alloc_b(struct ssm_pool *       pool,
                         size_t                  count,
                         uint8_t **              ptr,
                         struct ssm_pk_buff **   spb,
                         const struct timespec * abstime)
{
        int idx;

        assert(pool != NULL);
        assert(spb != NULL);

        idx = select_size_class(pool, count);
        if (idx >= 0)
                return alloc_from_sc_b(pool, idx, count, ptr, spb, abstime);

        return -EMSGSIZE;
}

ssize_t ssm_pool_read(uint8_t **        dst,
                      struct ssm_pool * pool,
                      size_t            off)
{
        struct ssm_pk_buff * blk;

        assert(dst != NULL);
        assert(pool != NULL);

        blk = OFFSET_TO_PTR(pool->pool_base, off);
        if (blk == NULL)
                return -EINVAL;

        *dst = blk->data + blk->pk_head;

        return (ssize_t) (blk->pk_tail - blk->pk_head);
}

struct ssm_pk_buff * ssm_pool_get(struct ssm_pool * pool,
                                     size_t            off)
{
        struct ssm_pk_buff * blk;

        assert(pool != NULL);

        if (off == 0 || off >= pool->total_size)
                return NULL;

        blk = OFFSET_TO_PTR(pool->pool_base, off);
        if (blk == NULL)
                return NULL;

        if (LOAD(&blk->refcount) == 0)
                return NULL;

        return blk;
}

int ssm_pool_remove(struct ssm_pool * pool,
                    size_t            off)
{
        struct ssm_pk_buff *     blk;
        struct _ssm_size_class * sc;
        struct _ssm_shard *      shard;
        int                      sc_idx;
        int                      shard_idx;
        uint16_t                 old_ref;

        assert(pool != NULL);

        if (off == 0 || off >= pool->total_size)
                return -EINVAL;

        blk = OFFSET_TO_PTR(pool->pool_base, off);
        if (blk == NULL)
                return -EINVAL;

        sc_idx = find_size_class_for_offset(pool, off);
        if (sc_idx < 0)
                return -EINVAL;

        sc = &pool->hdr->size_classes[sc_idx];

        /* Free to allocator's shard (lazy distribution in action) */
        shard_idx = GET_SHARD_FOR_PID(blk->allocator_pid);
        shard = &sc->shards[shard_idx];

        robust_mutex_lock(&shard->mtx);

        old_ref = FETCH_SUB(&blk->refcount, 1);
        if (old_ref > 1) {
                /* Still referenced */
                pthread_mutex_unlock(&shard->mtx);
                return 0;
        }

        blk->allocator_pid = 0;
#ifdef CONFIG_OUROBOROS_DEBUG
        if (old_ref == 0) {
                /* Underflow - double free attempt */
                pthread_mutex_unlock(&shard->mtx);
                abort();
        }

        /* Poison fields to detect use-after-free */
        blk->pk_head = 0xDEAD;
        blk->pk_tail = 0xBEEF;
#endif
        list_add_head(&shard->free_list, blk, pool->pool_base);
        FETCH_ADD(&shard->free_count, 1);

        pthread_cond_signal(&shard->cond);

        pthread_mutex_unlock(&shard->mtx);

        return 0;
}

size_t ssm_pk_buff_get_idx(struct ssm_pk_buff * spb)
{
        assert(spb != NULL);

        return spb->off;
}

uint8_t * ssm_pk_buff_head(struct ssm_pk_buff * spb)
{
        assert(spb != NULL);

        return spb->data + spb->pk_head;
}

uint8_t * ssm_pk_buff_tail(struct ssm_pk_buff * spb)
{
        assert(spb != NULL);

        return spb->data + spb->pk_tail;
}

size_t ssm_pk_buff_len(struct ssm_pk_buff * spb)
{
        assert(spb != NULL);

        return spb->pk_tail - spb->pk_head;
}

uint8_t * ssm_pk_buff_head_alloc(struct ssm_pk_buff * spb,
                                 size_t               size)
{
        assert(spb != NULL);

        if (spb->pk_head < size)
                return NULL;

        spb->pk_head -= size;

        return spb->data + spb->pk_head;
}

uint8_t * ssm_pk_buff_tail_alloc(struct ssm_pk_buff * spb,
                                 size_t               size)
{
        uint8_t * buf;

        assert(spb != NULL);

        if (spb->pk_tail + size >= spb->size)
                return NULL;

        buf = spb->data + spb->pk_tail;

        spb->pk_tail += size;

        return buf;
}

uint8_t * ssm_pk_buff_head_release(struct ssm_pk_buff * spb,
                                   size_t               size)
{
        uint8_t * buf;

        assert(spb != NULL);
        assert(!(size > spb->pk_tail - spb->pk_head));

        buf = spb->data + spb->pk_head;

        spb->pk_head += size;

        return buf;
}

uint8_t * ssm_pk_buff_tail_release(struct ssm_pk_buff * spb,
                                   size_t               size)
{
        assert(spb != NULL);
        assert(!(size > spb->pk_tail - spb->pk_head));

        spb->pk_tail -= size;

        return spb->data + spb->pk_tail;
}

void ssm_pk_buff_truncate(struct ssm_pk_buff * spb,
                          size_t               len)
{
        assert(spb != NULL);
        assert(len <= spb->size);

        spb->pk_tail = spb->pk_head + len;
}

int ssm_pk_buff_wait_ack(struct ssm_pk_buff * spb)
{
        assert(spb != NULL);

        FETCH_ADD(&spb->refcount, 1);

        return 0;
}

int ssm_pk_buff_ack(struct ssm_pk_buff * spb)
{
        assert(spb != NULL);

        FETCH_SUB(&spb->refcount, 1);

        return 0;
}
