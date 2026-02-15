/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the Secure Shared Memory (SSM) system
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

#define _POSIX_C_SOURCE 200809L

#include "config.h"
#include "ssm.h"

#include <test/test.h>
#include <ouroboros/ssm_pool.h>
#include <ouroboros/ssm_rbuff.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <signal.h>
#include <time.h>

#define POOL_256  256
#define POOL_512  512
#define POOL_1K   1024
#define POOL_2K   2048
#define POOL_4K   4096
#define POOL_16K  16384
#define POOL_64K  65536
#define POOL_256K 262144
#define POOL_1M   1048576
#define POOL_2M   (2 * 1024 * 1024)

static int test_ssm_pool_basic_allocation(void)
{
        struct ssm_pool *    pool;
        uint8_t *            ptr;
        struct ssm_pk_buff * spb;
        ssize_t              ret;

        TEST_START();

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }
        ret = ssm_pool_alloc(pool, POOL_256, &ptr, &spb);
        if (ret < 0) {
                printf("Alloc failed: %zd.\n", ret);
                goto fail_alloc;
        }

        if (spb == NULL) {
                printf("Spb is NULL.\n");
                goto fail_alloc;
        }

        if (ptr == NULL) {
                printf("Ptr is NULL.\n");
                goto fail_alloc;
        }

        if (ssm_pk_buff_len(spb) != POOL_256) {
                printf("Bad length: %zu.\n", ssm_pk_buff_len(spb));
                goto fail_alloc;
        }

        ret = ssm_pool_remove(pool, ret);
        if (ret != 0) {
                printf("Remove failed: %zd.\n", ret);
                goto fail_alloc;
        }

        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_alloc:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pool_multiple_allocations(void)
{
        struct ssm_pool *    pool;
        uint8_t *            ptr1;
        uint8_t *            ptr2;
        uint8_t *            ptr3;
        struct ssm_pk_buff * spb1;
        struct ssm_pk_buff * spb2;
        struct ssm_pk_buff * spb3;
        ssize_t              ret1;
        ssize_t              ret2;
        ssize_t              ret3;

        TEST_START();

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        ret1 = ssm_pool_alloc(pool, POOL_256, &ptr1, &spb1);
        ret2 = ssm_pool_alloc(pool, POOL_256, &ptr2, &spb2);
        ret3 = ssm_pool_alloc(pool, POOL_256, &ptr3, &spb3);
        if (ret1 < 0 || ret2 < 0 || ret3 < 0) {
                printf("Allocs failed: %zd, %zd, %zd.\n", ret1, ret2, ret3);
                goto fail_alloc;
        }

        if (spb1 == NULL) {
                printf("Spb1 is NULL.\n");
                goto fail_alloc;
        }

        if (ptr1 == NULL) {
                printf("Ptr1 is NULL.\n");
                goto fail_alloc;
        }

        if (spb2 == NULL) {
                printf("Spb2 is NULL.\n");
                goto fail_alloc;
        }

        if (ptr2 == NULL) {
                printf("Ptr2 is NULL.\n");
                goto fail_alloc;
        }

        if (spb3 == NULL) {
                printf("Spb3 is NULL.\n");
                goto fail_alloc;
        }

        if (ptr3 == NULL) {
                printf("Ptr3 is NULL.\n");
                goto fail_alloc;
        }

        if (ssm_pk_buff_len(spb1) != POOL_256) {
                printf("Bad length spb1: %zu.\n", ssm_pk_buff_len(spb1));
                goto fail_alloc;
        }

        if (ssm_pk_buff_len(spb2) != POOL_256) {
                printf("Bad length spb2: %zu.\n", ssm_pk_buff_len(spb2));
                goto fail_alloc;
        }

        if (ssm_pk_buff_len(spb3) != POOL_256) {
                printf("Bad length spb3: %zu.\n", ssm_pk_buff_len(spb3));
                goto fail_alloc;
        }

        if (ssm_pool_remove(pool, ret2) != 0) {
                printf("Remove ret2 failed.\n");
                goto fail_alloc;
        }

        if (ssm_pool_remove(pool, ret1) != 0) {
                printf("Remove ret1 failed.\n");
                goto fail_alloc;
        }

        if (ssm_pool_remove(pool, ret3) != 0) {
                printf("Remove ret3 failed.\n");
                goto fail_alloc;
        }

        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_alloc:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pool_no_fallback_for_large(void)
{
        struct ssm_pool *    pool;
        uint8_t *            ptr;
        struct ssm_pk_buff * spb;
        ssize_t              ret;

        TEST_START();

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        ret = ssm_pool_alloc(pool, POOL_2M, &ptr, &spb);
        if (ret >= 0) {
                printf("Oversized alloc succeeded: %zd.\n", ret);
                goto fail_alloc;
        }

        if (ret != -EMSGSIZE) {
                printf("Wrong error: %zd.\n", ret);
                goto fail_alloc;
        }

        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_alloc:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pool_blocking_vs_nonblocking(void)
{
        struct ssm_pool *    pool;
        uint8_t *            ptr;
        struct ssm_pk_buff * spb;
        ssize_t              ret;

        TEST_START();

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        ret = ssm_pool_alloc(pool, POOL_2M, &ptr, &spb);
        if (ret != -EMSGSIZE) {
                printf("Nonblocking oversized: %zd.\n", ret);
                goto fail_alloc;
        }

        ret = ssm_pool_alloc_b(pool, POOL_2M, &ptr, &spb, NULL);
        if (ret != -EMSGSIZE) {
                printf("Blocking oversized: %zd.\n", ret);
                goto fail_alloc;
        }

        ret = ssm_pool_alloc(pool, POOL_256, &ptr, &spb);
        if (ret < 0) {
                printf("Valid alloc failed: %zd.\n", ret);
                goto fail_alloc;
        }

        ssm_pool_remove(pool, ret);
        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_alloc:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pool_stress_test(void)
{
        struct ssm_pool *    pool;
        uint8_t *            ptr;
        struct ssm_pk_buff * spb;
        ssize_t *            indices = NULL;
        ssize_t              ret;
        size_t               count   = 0;
        size_t               i;

        TEST_START();

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        indices = malloc(100 * sizeof(*indices));
        if (indices == NULL) {
                printf("Malloc failed.\n");
                goto fail_alloc;
        }

        for (i = 0; i < 50; i++) {
                size_t j;
                size_t num;
                size_t size;

                num = (i % 50) + 1;

                for (j = 0; j < num && count < 50; j++) {
                        switch (i % 4) {
                        case 0:
                                /* FALLTHRU */
                        case 1:
                                size = POOL_256;
                                break;
                        case 2:
                                /* FALLTHRU */
                        case 3:
                                size = POOL_1K;
                                break;
                        default:
                                size = POOL_256;
                                break;
                        }

                        ret = ssm_pool_alloc(pool, size, &ptr, &spb);
                        if (ret < 0) {
                                printf("Alloc at iter %zu: %zd.\n", i, ret);
                                goto fail_test;
                        }
                        indices[count++] = ret;
                }

                for (j = 0; j < count / 2; j++) {
                        size_t idx = j * 2;
                        if (idx < count) {
                                ret = ssm_pool_remove(pool, indices[idx]);
                                if (ret != 0) {
                                        printf("Remove at iter %zu: %zd.\n",
                                               i, ret);
                                        goto fail_test;
                                }
                                memmove(&indices[idx], &indices[idx + 1],
                                        (count - idx - 1) * sizeof(*indices));
                                count--;
                        }
                }

                if (i % 10 == 0) {
                        ret = ssm_pool_alloc(pool, POOL_256, &ptr, &spb);
                        if (ret < 0) {
                                printf("Periodic alloc at %zu: %zd.\n", i, ret);
                                goto fail_test;
                        }
                        ssm_pool_remove(pool, ret);
                }
        }

        for (i = 0; i < count; i++)
                ssm_pool_remove(pool, indices[i]);

        free(indices);
        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_test:
        for (i = 0; i < count; i++)
                ssm_pool_remove(pool, indices[i]);
        free(indices);
 fail_alloc:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pool_open_initializes_ssm(void)
{
        struct ssm_pool *    creator;
        struct ssm_pool *    opener;
        uint8_t *            ptr;
        struct ssm_pk_buff * spb;
        ssize_t              ret;

        TEST_START();

        creator = ssm_pool_create(getuid(), getgid());
        if (creator == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        ret = ssm_pool_alloc(creator, POOL_256, &ptr, &spb);
        if (ret < 0) {
                printf("Creator alloc failed: %zd.\n", ret);
                goto fail_creator;
        }
        ssm_pool_remove(creator, ret);

        opener = ssm_pool_open(getuid());
        if (opener == NULL) {
                printf("Open failed.\n");
                goto fail_creator;
        }

        ret = ssm_pool_alloc(opener, POOL_256, &ptr, &spb);
        if (ret < 0) {
                printf("Opener alloc failed: %zd.\n", ret);
                goto fail_opener;
        }

        ssm_pool_remove(opener, ret);
        ssm_pool_close(opener);
        ssm_pool_destroy(creator);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_opener:
        ssm_pool_close(opener);
 fail_creator:
        ssm_pool_destroy(creator);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pool_bounds_checking(void)
{
        struct ssm_pool *    pool;
        struct ssm_pk_buff * spb;
        ssize_t              ret;

        TEST_START();

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        ret = ssm_pool_alloc(pool, POOL_256, NULL, &spb);
        if (ret < 0) {
                printf("alloc failed: %zd.\n", ret);
                goto fail_alloc;
        }

        spb = ssm_pool_get(pool, 0);
        if (spb != NULL) {
                printf("Get at offset 0.\n");
                goto fail_alloc;
        }

        spb = ssm_pool_get(pool, 100000000UL);
        if (spb != NULL) {
                printf("Get beyond pool.\n");
                goto fail_alloc;
        }

        ret = ssm_pool_remove(pool, 0);
        if (ret != -EINVAL) {
                printf("Remove at offset 0: %zd.\n", ret);
                goto fail_alloc;
        }

        ret = ssm_pool_remove(pool, 100000000UL);
        if (ret != -EINVAL) {
                printf("Remove beyond pool: %zd.\n", ret);
                goto fail_alloc;
        }

        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_alloc:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pool_inter_process_communication(void)
{
        struct ssm_pool *    pool;
        struct ssm_rbuff *   rb;
        struct ssm_pk_buff * spb;
        uint8_t *            ptr;
        uint8_t *            data;
        const char *         msg = "inter-process test";
        size_t               len;
        ssize_t              idx;
        pid_t                pid;
        int                  status;

        TEST_START();

        len = strlen(msg) + 1;

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        rb = ssm_rbuff_create(getpid(), 1);
        if (rb == NULL) {
                printf("Rbuff create failed.\n");
                goto fail_pool;
        }

        pid = fork();
        if (pid < 0) {
                printf("Fork failed.\n");
                goto fail_rbuff;
        }

        if (pid == 0) {
                idx = ssm_rbuff_read_b(rb, NULL);
                if (idx < 0) {
                        printf("Child: rbuff read: %zd.\n", idx);
                        exit(1);
                }

                spb = ssm_pool_get(pool, idx);
                if (spb == NULL) {
                        printf("Child: pool get failed.\n");
                        exit(1);
                }

                data = ssm_pk_buff_head(spb);
                if (data == NULL) {
                        printf("Child: data is NULL.\n");
                        ssm_pool_remove(pool, idx);
                        exit(1);
                }

                if (strcmp((char *)data, msg) != 0) {
                        printf("Child: data mismatch.\n");
                        ssm_pool_remove(pool, idx);
                        exit(1);
                }

                ssm_pool_remove(pool, idx);
                exit(0);
        }

        idx = ssm_pool_alloc(pool, len, &ptr, &spb);
        if (idx < 0) {
                printf("Parent: pool alloc: %zd.\n", idx);
                goto fail_child;
        }

        memcpy(ptr, msg, len);

        if (ssm_rbuff_write(rb, idx) < 0) {
                printf("Parent: rbuff write failed.\n");
                ssm_pool_remove(pool, idx);
                goto fail_child;
        }

        if (waitpid(pid, &status, 0) < 0) {
                printf("Parent: waitpid failed.\n");
                ssm_pool_remove(pool, idx);
                goto fail_rbuff;
        }

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
                printf("Child failed.\n");
                ssm_pool_remove(pool, idx);
                goto fail_rbuff;
        }

        ssm_rbuff_destroy(rb);
        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_child:
        waitpid(pid, &status, 0);
 fail_rbuff:
        ssm_rbuff_destroy(rb);
 fail_pool:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pool_read_operation(void)
{
        struct ssm_pool *    pool;
        struct ssm_pk_buff * spb;
        uint8_t *            wptr;
        uint8_t *            rptr;
        const char *         data = "ssm_pool_read test";
        size_t               len;
        ssize_t              idx;
        ssize_t              ret;

        TEST_START();

        len = strlen(data) + 1;

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        idx = ssm_pool_alloc(pool, len, &wptr, &spb);
        if (idx < 0) {
                printf("alloc failed: %zd.\n", idx);
                goto fail_alloc;
        }

        memcpy(wptr, data, len);

        ret = ssm_pool_read(&rptr, pool, idx);
        if (ret < 0) {
                printf("Read failed: %zd.\n", ret);
                goto fail_read;
        }

        if (rptr == NULL) {
                printf("NULL pointer.\n");
                goto fail_read;
        }

        if (strcmp((char *)rptr, data) != 0) {
                printf("Data mismatch.\n");
                goto fail_read;
        }

        ssm_pool_remove(pool, idx);
        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_read:
        ssm_pool_remove(pool, idx);
 fail_alloc:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pool_mlock_operation(void)
{
        struct ssm_pool * pool;
        int               ret;

        TEST_START();

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        ret = ssm_pool_mlock(pool);
        if (ret < 0)
                printf("Mlock failed: %d (may need privileges).\n", ret);

        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pk_buff_operations(void)
{
        struct ssm_pool *    pool;
        struct ssm_pk_buff * spb;
        uint8_t *            ptr;
        uint8_t *            head;
        uint8_t *            tail;
        const char *         data = "packet buffer test";
        size_t               dlen;
        size_t               len;
        ssize_t              idx;

        TEST_START();

        dlen = strlen(data);

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        idx = ssm_pool_alloc(pool, POOL_256, &ptr, &spb);
        if (idx < 0) {
                printf("alloc failed: %zd.\n", idx);
                goto fail_alloc;
        }

        head = ssm_pk_buff_head(spb);
        if (head != ptr) {
                printf("Head mismatch.\n");
                goto fail_ops;
        }

        len = ssm_pk_buff_len(spb);
        if (len != POOL_256) {
                printf("Bad length: %zu.\n", len);
                goto fail_ops;
        }

        tail = ssm_pk_buff_tail(spb);
        if (tail != ptr + len) {
                printf("Tail mismatch.\n");
                goto fail_ops;
        }

        memcpy(head, data, dlen);

        tail = ssm_pk_buff_tail_alloc(spb, 32);
        if (tail == NULL) {
                printf("Tail_alloc failed.\n");
                goto fail_ops;
        }

        if (ssm_pk_buff_len(spb) != POOL_256 + 32) {
                printf("Length after tail_alloc: %zu.\n",
                       ssm_pk_buff_len(spb));
                goto fail_ops;
        }

        if (memcmp(head, data, dlen) != 0) {
                printf("Data corrupted.\n");
                goto fail_ops;
        }

        tail = ssm_pk_buff_tail_release(spb, 32);
        if (tail == NULL) {
                printf("Tail_release failed.\n");
                goto fail_ops;
        }

        if (ssm_pk_buff_len(spb) != POOL_256) {
                printf("Length after tail_release: %zu.\n",
                       ssm_pk_buff_len(spb));
                goto fail_ops;
        }

        ssm_pool_remove(pool, idx);
        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_ops:
        ssm_pool_remove(pool, idx);
 fail_alloc:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

#define OVERHEAD (offsetof(struct ssm_pk_buff, data) + \
        SSM_PK_BUFF_HEADSPACE + SSM_PK_BUFF_TAILSPACE)
static int test_ssm_pool_size_class_boundaries(void)
{
        struct ssm_pool *    pool;
        struct ssm_pk_buff * spb;
        uint8_t *            ptr;
        size_t               sizes[] = {
                POOL_512 - OVERHEAD,
                POOL_512 - OVERHEAD + 1,
                POOL_1K - OVERHEAD,
                POOL_1K - OVERHEAD + 1,
                POOL_2K - OVERHEAD,
                POOL_2K - OVERHEAD + 1,
                POOL_4K - OVERHEAD,
                POOL_4K - OVERHEAD + 1,
                POOL_16K - OVERHEAD,
                POOL_16K - OVERHEAD + 1,
                POOL_64K - OVERHEAD,
                POOL_64K - OVERHEAD + 1,
                POOL_256K - OVERHEAD,
        };
        size_t               expected_classes[] = {
                512, 1024, 1024, 2048, 2048, 4096, 4096, 16384,
                16384, 65536, 65536, 262144, 262144
        };
        size_t               i;
        ssize_t              idx;

        TEST_START();

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        for (i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
                struct ssm_pk_buff * hdr;
                size_t               actual_class;

                idx = ssm_pool_alloc(pool, sizes[i], &ptr, &spb);
                if (idx < 0) {
                        printf("Alloc at %zu failed: %zd.\n", sizes[i], idx);
                        goto fail_alloc;
                }

                if (ssm_pk_buff_len(spb) != sizes[i]) {
                        printf("Length mismatch at %zu: %zu.\n",
                               sizes[i], ssm_pk_buff_len(spb));
                        ssm_pool_remove(pool, idx);
                        goto fail_alloc;
                }

                /* Verify correct size class was used
                 * hdr->size is the data array size (object_size - header) */
                hdr = spb;
                actual_class = hdr->size + offsetof(struct ssm_pk_buff, data);
                if (actual_class != expected_classes[i]) {
                        printf("Wrong class for len=%zu: want %zu, got %zu.\n",
                               sizes[i], expected_classes[i], actual_class);
                        ssm_pool_remove(pool, idx);
                        goto fail_alloc;
                }

                memset(ptr, i & 0xFF, sizes[i]);

                ssm_pool_remove(pool, idx);
        }

        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_alloc:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pool_exhaustion(void)
{
        struct ssm_pool *    pool;
        struct ssm_pk_buff * spb;
        uint8_t *            ptr;
        ssize_t *            indices;
        size_t               count = 0;
        size_t               i;
        ssize_t              ret;

        TEST_START();

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        indices = malloc(2048 * sizeof(*indices));
        if (indices == NULL) {
                printf("Malloc failed.\n");
                goto fail_alloc;
        }

        for (i = 0; i < 2048; i++) {
                ret = ssm_pool_alloc(pool, POOL_256, &ptr, &spb);
                if (ret < 0) {
                        if (ret == -EAGAIN)
                                break;
                        printf("Alloc error: %zd.\n", ret);
                        goto fail_test;
                }
                indices[count++] = ret;
        }

        if (count == 0) {
                printf("No allocs succeeded.\n");
                goto fail_test;
        }

        ret = ssm_pool_alloc(pool, POOL_256, &ptr, &spb);
        if (ret >= 0) {
                ssm_pool_remove(pool, ret);
        } else if (ret != -EAGAIN) {
                printf("Unexpected error: %zd.\n", ret);
                goto fail_test;
        }

        for (i = 0; i < count; i++)
                ssm_pool_remove(pool, indices[i]);

        ret = ssm_pool_alloc(pool, POOL_256, &ptr, &spb);
        if (ret < 0) {
                printf("Alloc after free failed: %zd.\n", ret);
                goto fail_test;
        }
        ssm_pool_remove(pool, ret);

        free(indices);
        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_test:
        for (i = 0; i < count; i++)
                ssm_pool_remove(pool, indices[i]);
        free(indices);
 fail_alloc:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_ssm_pool_reclaim_orphans(void)
{
        struct ssm_pool *    pool;
        uint8_t *            ptr1;
        uint8_t *            ptr2;
        uint8_t *            ptr3;
        struct ssm_pk_buff * spb1;
        struct ssm_pk_buff * spb2;
        struct ssm_pk_buff * spb3;
        ssize_t              ret1;
        ssize_t              ret2;
        ssize_t              ret3;
        pid_t                my_pid;
        pid_t                fake_pid = 99999;

        TEST_START();

        pool = ssm_pool_create(getuid(), getgid());
        if (pool == NULL) {
                printf("Failed to create pool.\n");
                goto fail_create;
        }

        my_pid = getpid();

        /* Allocate some blocks */
        ret1 = ssm_pool_alloc(pool, POOL_256, &ptr1, &spb1);
        ret2 = ssm_pool_alloc(pool, POOL_512, &ptr2, &spb2);
        ret3 = ssm_pool_alloc(pool, POOL_1K, &ptr3, &spb3);
        if (ret1 < 0 || ret2 < 0 || ret3 < 0) {
                printf("Allocs failed: %zd, %zd, %zd.\n", ret1, ret2, ret3);
                goto fail_alloc;
        }

        /* Simulate blocks from another process by changing allocator_pid */
        spb1->allocator_pid = fake_pid;
        spb2->allocator_pid = fake_pid;
        /* Keep spb3 with our pid */

        /* Reclaim orphans from fake_pid */
        ssm_pool_reclaim_orphans(pool, fake_pid);

        /* Verify spb1 and spb2 have refcount 0 (reclaimed) */
        if (spb1->refcount != 0) {
                printf("spb1 refcount should be 0, got %u.\n", spb1->refcount);
                goto fail_test;
        }

        if (spb2->refcount != 0) {
                printf("spb2 refcount should be 0, got %u.\n", spb2->refcount);
                goto fail_test;
        }

        /* Verify spb3 still has refcount 1 (not reclaimed) */
        if (spb3->refcount != 1) {
                printf("spb3 refcount should be 1, got %u.\n", spb3->refcount);
                goto fail_test;
        }

        /* Clean up */
        ssm_pool_remove(pool, ret3);

        /* Try allocating again - should get blocks from reclaimed pool */
        ret1 = ssm_pool_alloc(pool, POOL_256, &ptr1, &spb1);
        if (ret1 < 0) {
                printf("Alloc after reclaim failed: %zd.\n", ret1);
                goto fail_test;
        }

        /* Verify new allocation has our pid */
        if (spb1->allocator_pid != my_pid) {
                printf("New block has wrong pid: %d vs %d.\n",
                       spb1->allocator_pid, my_pid);
                goto fail_test;
        }

        ssm_pool_remove(pool, ret1);
        ssm_pool_destroy(pool);

        TEST_SUCCESS();
        return TEST_RC_SUCCESS;

 fail_test:
        ssm_pool_remove(pool, ret3);
 fail_alloc:
        ssm_pool_destroy(pool);
 fail_create:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

int pool_test(int     argc,
              char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_ssm_pool_basic_allocation();
        ret |= test_ssm_pool_multiple_allocations();
        ret |= test_ssm_pool_no_fallback_for_large();
        ret |= test_ssm_pool_blocking_vs_nonblocking();
        ret |= test_ssm_pool_stress_test();
        ret |= test_ssm_pool_open_initializes_ssm();
        ret |= test_ssm_pool_bounds_checking();
        ret |= test_ssm_pool_inter_process_communication();
        ret |= test_ssm_pool_read_operation();
        ret |= test_ssm_pool_mlock_operation();
        ret |= test_ssm_pk_buff_operations();
        ret |= test_ssm_pool_size_class_boundaries();
        ret |= test_ssm_pool_exhaustion();
        ret |= test_ssm_pool_reclaim_orphans();

        return ret;
}
