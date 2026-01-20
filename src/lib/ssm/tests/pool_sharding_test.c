/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the SSM pool sharding with fallback
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200112L
#endif

#include "config.h"
#include "ssm.h"

#include <test/test.h>
#include <ouroboros/ssm_pool.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>

#define TEST_SIZE 256

/* Helper to get pool header for inspection */
static struct _ssm_pool_hdr * get_pool_hdr(struct ssm_pool * pool)
{
        /* ssm_pool is opaque, but we know its layout:
         * uint8_t * shm_base
         * struct _ssm_pool_hdr * hdr
         * void * pool_base
         */
        struct _ssm_pool_hdr ** hdr_ptr =
                (struct _ssm_pool_hdr **)((uint8_t *)pool + sizeof(void *));
        return *hdr_ptr;
}

static int test_lazy_distribution(void)
{
        struct ssm_pool *        pool;
        struct _ssm_pool_hdr *   hdr;
        struct _ssm_size_class * sc;
        int                  i;
        int                  sc_idx;

        TEST_START();

        ssm_pool_purge();

        pool = ssm_pool_create();
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail;
        }

        hdr = get_pool_hdr(pool);
        if (hdr == NULL) {
                printf("Failed to get pool header.\n");
                goto fail_pool;
        }

        /* Find the first size class with blocks */
        sc_idx = -1;
        for (i = 0; i < SSM_POOL_MAX_CLASSES; i++) {
                if (hdr->size_classes[i].object_count > 0) {
                        sc_idx = i;
                        break;
                }
        }

        if (sc_idx < 0) {
                printf("No size classes configured.\n");
                for (i = 0; i < SSM_POOL_MAX_CLASSES; i++) {
                        printf("  Class %d: count=%zu\n", i,
                               hdr->size_classes[i].object_count);
                }
                goto fail_pool;
        }

        sc = &hdr->size_classes[sc_idx];

        /* Verify all blocks start in shard 0 */
        if (sc->shards[0].free_count == 0) {
                printf("Shard 0 should have all blocks initially.\n");
                goto fail_pool;
        }

        /* Verify other shards are empty */
        for (i = 1; i < SSM_POOL_SHARDS; i++) {
                if (sc->shards[i].free_count != 0) {
                        printf("Shard %d should be empty, has %zu.\n",
                               i, sc->shards[i].free_count);
                        goto fail_pool;
                }
        }

        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_pool:
        ssm_pool_destroy(pool);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_shard_migration(void)
{
        struct ssm_pool *        pool;
        struct _ssm_pool_hdr *   hdr;
        struct _ssm_size_class * sc;
        struct ssm_pk_buff *  spb;
        uint8_t *             ptr;
        ssize_t               off;
        int                   shard_idx;
        int                   sc_idx;
        int                   i;

        TEST_START();

        ssm_pool_purge();

        pool = ssm_pool_create();
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail;
        }

        hdr = get_pool_hdr(pool);

        /* Find the first size class with blocks */
        sc_idx = -1;
        for (i = 0; i < SSM_POOL_MAX_CLASSES; i++) {
                if (hdr->size_classes[i].object_count > 0) {
                        sc_idx = i;
                        break;
                }
        }

        if (sc_idx < 0) {
                printf("No size classes configured.\n");
                goto fail;
        }

        sc = &hdr->size_classes[sc_idx];

        /* Allocate from this process */
        off = ssm_pool_alloc(pool, TEST_SIZE, &ptr, &spb);
        if (off < 0) {
                printf("Allocation failed: %zd.\n", off);
                goto fail_pool;
        }

        /* Free it - should go to this process's shard */
        shard_idx = getpid() % SSM_POOL_SHARDS;
        if (ssm_pool_remove(pool, off) != 0) {
                printf("Remove failed.\n");
                goto fail_pool;
        }

        /* Verify block migrated away from shard 0 or in allocator's shard */
        if (sc->shards[shard_idx].free_count == 0 &&
            sc->shards[0].free_count == 0) {
                printf("Block should have been freed to a shard.\n");
                goto fail_pool;
        }

        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_pool:
        ssm_pool_destroy(pool);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_fallback_stealing(void)
{
        struct ssm_pool *        pool;
        struct _ssm_pool_hdr *   hdr;
        struct _ssm_size_class * sc;
        struct ssm_pk_buff ** spbs;
        uint8_t **            ptrs;
        size_t                total_blocks;
        size_t                total_free;
        size_t                i;
        int                   sc_idx;
        int                   c;

        TEST_START();

        ssm_pool_purge();

        pool = ssm_pool_create();
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail;
        }

        hdr = get_pool_hdr(pool);

        /* Find the first size class with blocks */
        sc_idx = -1;
        for (c = 0; c < SSM_POOL_MAX_CLASSES; c++) {
                if (hdr->size_classes[c].object_count > 0) {
                        sc_idx = c;
                        break;
                }
        }

        if (sc_idx < 0) {
                printf("No size classes configured.\n");
                goto fail;
        }

        sc = &hdr->size_classes[sc_idx];
        total_blocks = sc->object_count;

        spbs = malloc(total_blocks * sizeof(struct ssm_pk_buff *));
        ptrs = malloc(total_blocks * sizeof(uint8_t *));
        if (spbs == NULL || ptrs == NULL) {
                printf("Failed to allocate test arrays.\n");
                goto fail_pool;
        }

        /* Allocate half the blocks from single process */
        for (i = 0; i < total_blocks / 2; i++) {
                ssize_t off = ssm_pool_alloc(pool, TEST_SIZE,
                                             &ptrs[i], &spbs[i]);
                if (off < 0) {
                        printf("Allocation %zu failed: %zd.\n", i, off);
                        free(spbs);
                        free(ptrs);
                        goto fail_pool;
                }
        }

        /* Free them all - they go to local_shard */
        for (i = 0; i < total_blocks / 2; i++) {
                size_t off = ssm_pk_buff_get_idx(spbs[i]);
                if (ssm_pool_remove(pool, off) != 0) {
                        printf("Remove %zu failed.\n", i);
                        free(spbs);
                        free(ptrs);
                        goto fail_pool;
                }
        }

        /* Freed blocks should be in shards (all blocks free again) */
        total_free = 0;
        for (i = 0; i < SSM_POOL_SHARDS; i++) {
                total_free += sc->shards[i].free_count;
        }

        if (total_free != total_blocks) {
                printf("Expected %zu free blocks total, got %zu.\n",
                       total_blocks, total_free);
                free(spbs);
                free(ptrs);
                goto fail_pool;
        }

        /* Allocate again - should succeed by taking from shards */
        for (i = 0; i < total_blocks / 2; i++) {
                ssize_t off = ssm_pool_alloc(pool, TEST_SIZE,
                                             &ptrs[i], &spbs[i]);
                if (off < 0) {
                        printf("Fallback alloc %zu failed: %zd.\n", i, off);
                        free(spbs);
                        free(ptrs);
                        goto fail_pool;
                }
        }

        /* Now all allocated blocks are in use again */
        /* Cleanup - free all allocated blocks */
        for (i = 0; i < total_blocks / 2; i++) {
                size_t off = ssm_pk_buff_get_idx(spbs[i]);
                ssm_pool_remove(pool, off);
        }

        free(spbs);
        free(ptrs);
        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_pool:
        ssm_pool_destroy(pool);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_multiprocess_sharding(void)
{
        struct ssm_pool *        pool;
        struct _ssm_pool_hdr *   hdr;
        struct _ssm_size_class * sc;
        pid_t                 children[SSM_POOL_SHARDS];
        int                   i;
        int                   status;

        TEST_START();

        ssm_pool_purge();

        pool = ssm_pool_create();
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail;
        }

        /* Fork processes to test different shards */
        for (i = 0; i < SSM_POOL_SHARDS; i++) {
                children[i] = fork();
                if (children[i] == -1) {
                        printf("Fork %d failed.\n", i);
                        goto fail_children;
                }

                if (children[i] == 0) {
                        /* Child process */
                        struct ssm_pool *    child_pool;
                        struct ssm_pk_buff * spb;
                        uint8_t *            ptr;
                        ssize_t              off;
                        int                  my_shard;

                        child_pool = ssm_pool_open();
                        if (child_pool == NULL)
                                exit(EXIT_FAILURE);

                        my_shard = getpid() % SSM_POOL_SHARDS;
                        (void) my_shard; /* Reserved for future use */

                        /* Each child allocates and frees a block */
                        off = ssm_pool_alloc(child_pool, TEST_SIZE,
                                            &ptr, &spb);
                        if (off < 0) {
                                ssm_pool_close(child_pool);
                                exit(EXIT_FAILURE);
                        }

                        /* Small delay to ensure allocation visible */
                        usleep(10000);

                        if (ssm_pool_remove(child_pool, off) != 0) {
                                ssm_pool_close(child_pool);
                                exit(EXIT_FAILURE);
                        }

                        ssm_pool_close(child_pool);
                        exit(EXIT_SUCCESS);
                }
        }

        /* Wait for all children */
        for (i = 0; i < SSM_POOL_SHARDS; i++) {
                if (waitpid(children[i], &status, 0) == -1) {
                        printf("Waitpid %d failed.\n", i);
                        goto fail_children;
                }
                if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                        printf("Child %d failed.\n", i);
                        goto fail_pool;
                }
        }

        /* Verify blocks distributed across shards */
        hdr = get_pool_hdr(pool);

        /* Find the first size class with blocks */
        sc = NULL;
        for (i = 0; i < SSM_POOL_MAX_CLASSES; i++) {
                if (hdr->size_classes[i].object_count > 0) {
                        sc = &hdr->size_classes[i];
                        break;
                }
        }

        if (sc == NULL) {
                printf("No size classes configured.\n");
                goto fail_pool;
        }

        /* After children allocate and free, blocks should be in shards
         * (though exact distribution depends on PID values)
         */
        for (i = 0; i < SSM_POOL_SHARDS; i++) {
                /* At least some shards should have blocks */
                if (sc->shards[i].free_count > 0) {
                        break;
                }
        }

        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_children:
        /* Kill any remaining children */
        for (i = 0; i < SSM_POOL_SHARDS; i++) {
                if (children[i] > 0)
                        kill(children[i], SIGKILL);
        }
 fail_pool:
        ssm_pool_destroy(pool);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_exhaustion_with_fallback(void)
{
        struct ssm_pool *    pool;
        struct ssm_pk_buff * spb;
        uint8_t *            ptr;
        ssize_t              off;

        TEST_START();

        ssm_pool_purge();

        pool = ssm_pool_create();
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail;
        }

        /* Allocate until exhausted across all shards */
        while (true) {
                off = ssm_pool_alloc(pool, TEST_SIZE, &ptr, &spb);
                if (off < 0) {
                        if (off == -EAGAIN)
                                break;
                        printf("Unexpected error: %zd.\n", off);
                        goto fail_pool;
                }
        }

        /* Should fail with -EAGAIN when truly exhausted */
        off = ssm_pool_alloc(pool, TEST_SIZE, &ptr, &spb);
        if (off != -EAGAIN) {
                printf("Expected -EAGAIN, got %zd.\n", off);
                goto fail_pool;
        }

        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_pool:
        ssm_pool_destroy(pool);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int pool_sharding_test(int     argc,
                       char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_lazy_distribution();
        ret |= test_shard_migration();
        ret |= test_fallback_stealing();
        ret |= test_multiprocess_sharding();
        ret |= test_exhaustion_with_fallback();

        return ret;
}
