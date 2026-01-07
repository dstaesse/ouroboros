/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Unit tests of the DHT
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
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

#define __DHT_TEST__

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200112L
#endif

#include <test/test.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>

#include "dht.pb-c.h"

#include <assert.h>
#include <inttypes.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#define DHT_MAX_RAND_SIZE 64
#define DHT_TEST_KEY_LEN  32
#define DHT_TEST_ADDR     0x1234567890abcdefULL

/* forward declare for use in the dht code */
/* Packet sink for DHT tests */
struct {
        bool   enabled;

        struct list_head list;
        size_t len;
} sink;

struct message {
        struct   list_head next;
        void *   msg;
        uint64_t dst;
};

static int sink_send_msg(buffer_t * pkt,
                         uint64_t  addr)
{
        struct message *   m;

        assert(pkt  != NULL);
        assert(addr != 0);

        assert(!list_is_empty(&sink.list) || sink.len == 0);

        if (!sink.enabled)
                goto finish;

        m = malloc(sizeof(*m));
        if (m == NULL) {
                printf("Failed to malloc message.");
                goto fail_malloc;
        }

        m->msg = dht_msg__unpack(NULL, pkt->len, pkt->data);
        if (m->msg == NULL)
                goto fail_unpack;

        m->dst = addr;

        list_add_tail(&m->next, &sink.list);

        ++sink.len;
 finish:
        freebuf(*pkt);

        return 0;
 fail_unpack:
        free(m);
 fail_malloc:
        freebuf(*pkt);
        return -1;
}

#include "dht.c"

/* Test helpers */

static void sink_init(void)
{
        list_head_init(&sink.list);
        sink.len = 0;
        sink.enabled = true;
}

static void sink_clear(void)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &sink.list) {
                struct message * m = list_entry(p, struct message, next);
                list_del(&m->next);
                dht_msg__free_unpacked((dht_msg_t *) m->msg, NULL);
                free(m);
                --sink.len;
        }

        assert(list_is_empty(&sink.list));
}

static void sink_fini(void)
{
        sink_clear();

        assert(list_is_empty(&sink.list) || sink.len != 0);
}

static dht_msg_t * sink_read(void)
{
        struct message * m;
        dht_msg_t *      msg;

        assert(!list_is_empty(&sink.list) || sink.len == 0);

        if (list_is_empty(&sink.list))
                return NULL;

        m = list_first_entry(&sink.list, struct message, next);

        --sink.len;

        list_del(&m->next);

        msg = m->msg;

        free(m);

        return (dht_msg_t *) msg;
}

static const buffer_t test_val = {
        .data = (uint8_t *) "test_value",
        .len = 10
};

static const buffer_t test_val2 = {
        .data = (uint8_t *) "test_value_2",
        .len = 12
};

static int random_value_len(buffer_t * b)
{
        assert(b != NULL);
        assert(b->len > 0 && b->len <= DHT_MAX_RAND_SIZE);

        b->data = malloc(b->len);
        if (b->data == NULL)
                goto fail_malloc;

        random_buffer(b->data, b->len);

        return 0;

 fail_malloc:
        return -ENOMEM;
}

static int random_value(buffer_t * b)
{
        assert(b != NULL);

        b->len = rand() % DHT_MAX_RAND_SIZE + 1;

        return random_value_len(b);
}

static int fill_dht_with_contacts(size_t n)
{
        size_t    i;
        uint8_t * id;

        for (i = 0; i < n; i++) {
                uint64_t addr = generate_cookie();
                id = generate_id();
                if (id == NULL)
                        goto fail_id;

                if (dht_kv_update_contacts(id, addr) < 0)
                        goto fail_update;
                free(id);
        }

        return 0;

 fail_update:
        free(id);
 fail_id:
        return -1;
}

static int fill_store_with_random_values(const uint8_t * key,
                                         size_t          len,
                                         size_t          n_values)
{
        buffer_t        val;
        struct timespec now;
        size_t          i;
        uint8_t *       _key;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        for (i = 0; i < n_values; ++i) {
                if (key != NULL)
                        _key = (uint8_t *) key;
                else {
                        _key = generate_id();
                        if (_key == NULL)
                                goto fail_key;
                }

                if (len == 0)
                        val.len = rand() % DHT_MAX_RAND_SIZE + 1;
                else
                        val.len = len;

                if (random_value_len(&val) < 0)
                        goto fail_value;

                if (dht_kv_store(_key, val, now.tv_sec + 10) < 0)
                        goto fail_store;

                freebuf(val);
                if (key == NULL)
                        free(_key);
        }

        return 0;

 fail_store:
        freebuf(val);
 fail_value:
        free(_key);
 fail_key:
        return -1;
}

static int random_contact_list(dht_contact_msg_t *** contacts,
                               size_t                max)
{
        size_t i;

        assert(contacts != NULL);
        assert(max > 0);

        *contacts = malloc(max * sizeof(**contacts));
        if (*contacts == NULL)
                goto fail_malloc;

        for (i = 0; i < max; i++) {
                (*contacts)[i] = malloc(sizeof(*(*contacts)[i]));
                if ((*contacts)[i] == NULL)
                        goto fail_contacts;

                dht_contact_msg__init((*contacts)[i]);

                (*contacts)[i]->id.data = generate_id();
                if ((*contacts)[i]->id.data == NULL)
                        goto fail_contact;

                (*contacts)[i]->id.len = dht.id.len;
                (*contacts)[i]->addr = generate_cookie();
        }

        return 0;

 fail_contact:
        dht_contact_msg__free_unpacked((*contacts)[i], NULL);
 fail_contacts:
        while (i-- > 0)
                free((*contacts)[i]);
        free(*contacts);
 fail_malloc:
        return -ENOMEM;
}

static void clear_contacts(dht_contact_msg_t ** contacts,
                           size_t               len)
{
        size_t i;

        assert(contacts != NULL);
        if (*contacts == NULL)
                return;

        for (i = 0; i < len; ++i)
                dht_contact_msg__free_unpacked((contacts)[i], NULL);

        free(*contacts);
        *contacts = NULL;
}

/* Start of actual tests */
static struct dir_dht_config test_dht_config = {
        .params = {
                .alpha       = 3,
                .k           = 8,
                .t_expire    = 86400,
                .t_refresh   = 900,
                .t_replicate = 900
        }
};

static int test_dht_init_fini(void)
{
        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_start_stop(void)
{
        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        if (dht_start() < 0) {
                printf("Failed to start dht.\n");
                goto fail_start;
        }

        dht_stop();

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_start:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_val_entry_create_destroy(void)
{
        struct val_entry * e;
        struct timespec    now;

        TEST_START();

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        e = val_entry_create(test_val, now.tv_sec + 10);
        if (e == NULL) {
                printf("Failed to create val entry.\n");
                goto fail_entry;
        }

        val_entry_destroy(e);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_entry:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_entry_create_destroy(void)
{
        struct dht_entry * e;

        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        e = dht_entry_create(dht.id.data);
        if (e == NULL) {
                printf("Failed to create dht entry.\n");
                goto fail_entry;
        }

        dht_entry_destroy(e);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_entry:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_entry_update_get_val(void)
{
        struct dht_entry * e;
        struct val_entry * v;
        struct timespec    now;

        TEST_START();

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        e = dht_entry_create(dht.id.data);
        if (e == NULL) {
                printf("Failed to create dht entry.\n");
                goto fail_entry;
        }

        if (dht_entry_get_val(e, test_val) != NULL) {
                printf("Found value in empty dht entry.\n");
                goto fail_get;
        }

        if (dht_entry_update_val(e, test_val, now.tv_sec + 10) < 0) {
                printf("Failed to update dht entry value.\n");
                goto fail_get;
        }

        if (dht_entry_get_val(e, test_val2) != NULL) {
                printf("Found value in dht entry with different key.\n");
                goto fail_get;
        }

        v = dht_entry_get_val(e, test_val);
        if (v == NULL) {
                printf("Failed to get value from dht entry.\n");
                goto fail_get;
        }

        if (v->val.len != test_val.len) {
                printf("Length in dht entry does not match expected.\n");
                goto fail_get;
        }

        if(memcmp(v->val.data, test_val.data, test_val.len) != 0) {
                printf("Data in dht entry does not match expected.\n");
                goto fail_get;
        }

        if (dht_entry_update_val(e, test_val, now.tv_sec + 15) < 0) {
                printf("Failed to update exsting dht entry value.\n");
                goto fail_get;
        }

        if (v->t_exp != now.tv_sec + 15) {
                printf("Expiration time in dht entry value not updated.\n");
                goto fail_get;
        }

        if (dht_entry_update_val(e, test_val, now.tv_sec + 5) < 0) {
                printf("Failed to update existing dht entry value (5).\n");
                goto fail_get;
        }

        if (v->t_exp != now.tv_sec + 15) {
                printf("Expiration time in dht entry shortened.\n");
                goto fail_get;
        }

        if (dht_entry_get_val(e, test_val) != v) {
                printf("Wrong value in dht entry found after update.\n");
                goto fail_get;
        }

        dht_entry_destroy(e);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_get:
        dht_entry_destroy(e);
 fail_entry:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_entry_update_get_lval(void)
{
        struct dht_entry * e;
        struct val_entry * v;
        struct timespec    now;

        TEST_START();

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        e = dht_entry_create(dht.id.data);
        if (e == NULL) {
                printf("Failed to create dht entry.\n");
                goto fail_entry;
        }

        if (dht_entry_get_lval(e, test_val) != NULL) {
                printf("Found value in empty dht entry.\n");
                goto fail_get;
        }

        if (dht_entry_update_lval(e, test_val) < 0) {
                printf("Failed to update dht entry value.\n");
                goto fail_get;
        }

        v = dht_entry_get_lval(e, test_val);
        if (v== NULL) {
                printf("Failed to get value from dht entry.\n");
                goto fail_get;
        }

        if (dht_entry_get_lval(e, test_val2) != NULL) {
                printf("Found value in dht entry in vals.\n");
                goto fail_get;
        }

        if (v->val.len != test_val.len) {
                printf("Length in dht entry does not match expected.\n");
                goto fail_get;
        }

        if(memcmp(v->val.data, test_val.data, test_val.len) != 0) {
                printf("Data in dht entry does not match expected.\n");
                goto fail_get;
        }

        if (dht_entry_update_lval(e, test_val) < 0) {
                printf("Failed to update existing dht entry value.\n");
                goto fail_get;
        }

        if (dht_entry_get_lval(e, test_val) != v) {
                printf("Wrong value in dht entry found after update.\n");
                goto fail_get;
        }

        dht_entry_destroy(e);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_get:
        dht_entry_destroy(e);
 fail_entry:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_contact_create_destroy(void)
{
        struct contact * c;

        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        c = contact_create(dht.id.data, dht.addr);
        if (c == NULL) {
                printf("Failed to create contact.\n");
                goto fail_contact;
        }

        contact_destroy(c);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_contact:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_update_bucket(void)
{
        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        if (fill_dht_with_contacts(1000) < 0) {
                printf("Failed to fill bucket with contacts.\n");
                goto fail_update;
        }

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_update:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_contact_list(void)
{
        struct list_head cl;
        ssize_t          len;
        ssize_t          items;

        TEST_START();

        list_head_init(&cl);

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        items = 5;

        if (fill_dht_with_contacts(items) < 0) {
                printf("Failed to fill bucket with contacts.\n");
                goto fail_fill;
        }

        len = dht_kv_contact_list(dht.id.data, &cl, dht.k);
        if (len < 0) {
                printf("Failed to get contact list.\n");
                goto fail_fill;
        }

        if (len != items) {
                printf("Failed to get contacts (%zu != %zu).\n", len, items);
                goto fail_contact_list;
        }

        contact_list_destroy(&cl);

        items = 100;

        if (fill_dht_with_contacts(items) < 0) {
                printf("Failed to fill bucket with contacts.\n");
                goto fail_fill;
        }

        len = dht_kv_contact_list(dht.id.data, &cl, items);
        if (len < 0) {
                printf("Failed to get contact list.\n");
                goto fail_fill;
        }

        if ((size_t) len < dht.k) {
                printf("Failed to get contacts (%zu < %zu).\n", len, dht.k);
                goto fail_contact_list;
        }

        contact_list_destroy(&cl);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_contact_list:
        contact_list_destroy(&cl);
 fail_fill:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_get_values(void)
{
        buffer_t * vals;
        ssize_t    len;
        size_t     n = sizeof(uint64_t);

        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        if (fill_store_with_random_values(dht.id.data, n, 3) < 0) {
                printf("Failed to fill store with random values.\n");
                goto fail_fill;
        }

        len = dht_kv_retrieve(dht.id.data, &vals);
        if (len < 0) {
                printf("Failed to get values from store.\n");
                goto fail_fill;
        }

        if (len != 3) {
                printf("Failed to get %ld values (%zu).\n", 3L, len);
                goto fail_get_values;
        }

        freebufs(vals, len);

        if (fill_store_with_random_values(dht.id.data, n, 20) < 0) {
                printf("Failed to fill store with random values.\n");
                goto fail_fill;
        }

        len = dht_kv_retrieve(dht.id.data, &vals);
        if (len < 0) {
                printf("Failed to get values from store.\n");
                goto fail_fill;
        }

        if (len != DHT_MAX_VALS) {
                printf("Failed to get %d values.\n", DHT_MAX_VALS);
                goto fail_get_values;
        }

        freebufs(vals, len);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_get_values:
        freebufs(vals, len);
 fail_fill:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_find_node_req_msg(void)
{
        dht_msg_t * msg;
        dht_msg_t * upk;
        size_t      len;
        uint8_t *   buf;

        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        msg = dht_kv_find_node_req_msg(dht.id.data);
        if (msg == NULL) {
                printf("Failed to get find node request message.\n");
                goto fail_msg;
        }

        if (msg->code != DHT_FIND_NODE_REQ) {
                printf("Wrong code in find_node_req message (%s != %s).\n",
                        dht_code_str[msg->code],
                        dht_code_str[DHT_FIND_NODE_REQ]);
                goto fail_msg;
        }

        len = dht_msg__get_packed_size(msg);
        if (len == 0) {
                printf("Failed to get packed length of find_node_req.\n");
                goto fail_msg;
        }

        buf = malloc(len);
        if (buf == NULL) {
                printf("Failed to malloc find_node_req buf.\n");
                goto fail_msg;
        }

        if (dht_msg__pack(msg, buf) != len) {
                printf("Failed to pack find_node_req message.\n");
                goto fail_pack;
        }

        upk = dht_msg__unpack(NULL, len, buf);
        if (upk == NULL) {
                printf("Failed to unpack find_value_req message.\n");
                goto fail_unpack;
        }

        free(buf);
        dht_msg__free_unpacked(msg, NULL);
        dht_msg__free_unpacked(upk, NULL);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_unpack:
        dht_msg__free_unpacked(msg, NULL);
 fail_pack:
        free(buf);
 fail_msg:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_find_node_rsp_msg(void)
{
        dht_contact_msg_t ** contacts;
        dht_msg_t *          msg;
        dht_msg_t *          upk;
        size_t               len;
        uint8_t *            buf;

        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        msg = dht_kv_find_node_rsp_msg(dht.id.data, 0, &contacts, 0);
        if (msg == NULL) {
                printf("Failed to get find node response message.\n");
                goto fail_msg;
        }

        if (msg->code != DHT_FIND_NODE_RSP) {
                printf("Wrong code in find_node_rsp message (%s != %s).\n",
                       dht_code_str[msg->code],
                       dht_code_str[DHT_FIND_NODE_RSP]);
                goto fail_msg;
        }

        len = dht_msg__get_packed_size(msg);
        if (len == 0) {
                printf("Failed to get packed length of find_node_rsp.\n");
                goto fail_msg;
        }

        buf = malloc(len);
        if (buf == NULL) {
                printf("Failed to malloc find_node_rsp buf.\n");
                goto fail_msg;
        }

        if (dht_msg__pack(msg, buf) != len) {
                printf("Failed to pack find_node_rsp message.\n");
                goto fail_pack;
        }

        upk = dht_msg__unpack(NULL, len, buf);
        if (upk == NULL) {
                printf("Failed to unpack find_node_rsp message.\n");
                goto fail_unpack;
        }

        free(buf);
        dht_msg__free_unpacked(msg, NULL);
        dht_msg__free_unpacked(upk, NULL);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_unpack:
        dht_msg__free_unpacked(msg, NULL);
 fail_pack:
        free(buf);
 fail_msg:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_find_node_rsp_msg_contacts(void)
{
        dht_contact_msg_t ** contacts;
        dht_msg_t *          msg;
        dht_msg_t *          upk;
        uint8_t *            buf;
        size_t               len;
        ssize_t              n;

        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        if (fill_dht_with_contacts(100) < 0) {
                printf("Failed to fill bucket with contacts.\n");
                goto fail_fill;
        }

        n = dht_kv_get_contacts(dht.id.data, &contacts);
        if (n < 0) {
                printf("Failed to get contacts.\n");
                goto fail_fill;
        }

        if ((size_t) n < dht.k) {
                printf("Failed to get enough contacts (%zu < %zu).\n", n, dht.k);
                goto fail_fill;
        }

        msg = dht_kv_find_node_rsp_msg(dht.id.data, 0, &contacts, n);
        if (msg == NULL) {
                printf("Failed to build find node response message.\n");
                goto fail_msg;
        }

        len = dht_msg__get_packed_size(msg);
        if (len == 0) {
                printf("Failed to get packed length of find_node_rsp.\n");
                goto fail_msg;
        }

        buf = malloc(len);
        if (buf == NULL) {
                printf("Failed to malloc find_node_rsp buf.\n");
                goto fail_msg;
        }

        if (dht_msg__pack(msg, buf) != len) {
                printf("Failed to pack find_node_rsp message.\n");
                goto fail_pack;
        }

        upk = dht_msg__unpack(NULL, len, buf);
        if (upk == NULL) {
                printf("Failed to unpack find_node_rsp message.\n");
                goto fail_unpack;
        }

        free(buf);
        dht_msg__free_unpacked(msg, NULL);
        dht_msg__free_unpacked(upk, NULL);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_unpack:
        dht_msg__free_unpacked(msg, NULL);
 fail_pack:
        free(buf);
 fail_msg:
        clear_contacts(contacts, n);
 fail_fill:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_find_value_req_msg(void)
{
        dht_msg_t * msg;
        dht_msg_t * upk;
        size_t      len;
        uint8_t *   buf;

        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        msg = dht_kv_find_value_req_msg(dht.id.data);
        if (msg == NULL) {
                printf("Failed to build find value request message.\n");
                goto fail_msg;
        }

        if (msg->code != DHT_FIND_VALUE_REQ) {
                printf("Wrong code in find_value_req message (%s != %s).\n",
                       dht_code_str[msg->code],
                       dht_code_str[DHT_FIND_VALUE_REQ]);
                goto fail_msg;
        }

        len = dht_msg__get_packed_size(msg);
        if (len == 0) {
                printf("Failed to get packed length of find_value_req.\n");
                goto fail_msg;
        }

        buf = malloc(len);
        if (buf == NULL) {
                printf("Failed to malloc find_node_req buf.\n");
                goto fail_msg;
        }

        if (dht_msg__pack(msg, buf) != len) {
                printf("Failed to pack find_value_req message.\n");
                goto fail_pack;
        }

        upk = dht_msg__unpack(NULL, len, buf);
        if (upk == NULL) {
                printf("Failed to unpack find_value_req message.\n");
                goto fail_unpack;
        }

        free(buf);
        dht_msg__free_unpacked(msg, NULL);
        dht_msg__free_unpacked(upk, NULL);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_unpack:
        dht_msg__free_unpacked(msg, NULL);
 fail_pack:
        free(buf);
 fail_msg:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_find_value_rsp_msg(void)
{
        dht_msg_t * msg;
        dht_msg_t * upk;
        size_t      len;
        uint8_t *   buf;

        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        msg = dht_kv_find_value_rsp_msg(dht.id.data, 0, NULL, 0, NULL, 0);
        if (msg == NULL) {
                printf("Failed to build find value response message.\n");
                goto fail_msg;
        }

        if (msg->code != DHT_FIND_VALUE_RSP) {
                printf("Wrong code in find_value_rsp message (%s != %s).\n",
                       dht_code_str[msg->code],
                       dht_code_str[DHT_FIND_VALUE_RSP]);
                goto fail_msg;
        }

        len = dht_msg__get_packed_size(msg);
        if (len == 0) {
                printf("Failed to get packed length of find_value_rsp.\n");
                goto fail_msg;
        }

        buf = malloc(len);
        if (buf == NULL) {
                printf("Failed to malloc find_value_rsp buf.\n");
                goto fail_msg;
        }

        if (dht_msg__pack(msg, buf) != len) {
                printf("Failed to pack find_value_rsp message.\n");
                goto fail_pack;
        }

        upk = dht_msg__unpack(NULL, len, buf);
        if (upk == NULL) {
                printf("Failed to unpack find_value_rsp message.\n");
                goto fail_unpack;
        }

        free(buf);
        dht_msg__free_unpacked(msg, NULL);
        dht_msg__free_unpacked(upk, NULL);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_unpack:
        dht_msg__free_unpacked(msg, NULL);
 fail_pack:
        free(buf);
 fail_msg:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_find_value_rsp_msg_contacts(void)
{
        dht_msg_t *          msg;
        dht_msg_t *          upk;
        size_t               len;
        uint8_t *            buf;
        dht_contact_msg_t ** contacts;
        ssize_t              n;

        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        if (fill_dht_with_contacts(100) < 0) {
                printf("Failed to fill bucket with contacts.\n");
                goto fail_fill;
        }

        n = dht_kv_get_contacts(dht.id.data, &contacts);
        if (n < 0) {
                printf("Failed to get contacts.\n");
                goto fail_fill;
        }

        if ((size_t) n < dht.k) {
                printf("Failed to get enough contacts (%zu < %zu).\n", n, dht.k);
                goto fail_fill;
        }

        msg = dht_kv_find_value_rsp_msg(dht.id.data, 0, &contacts, n, NULL, 0);
        if (msg == NULL) {
                printf("Failed to build find value response message.\n");
                goto fail_msg;
        }

        len = dht_msg__get_packed_size(msg);
        if (len == 0) {
                printf("Failed to get packed length of find_value_rsp.\n");
                goto fail_msg;
        }

        buf = malloc(len);
        if (buf == NULL) {
                printf("Failed to malloc find_value_rsp buf.\n");
                goto fail_msg;
        }

        if (dht_msg__pack(msg, buf) != len) {
                printf("Failed to pack find_value_rsp message.\n");
                goto fail_pack;
        }

        upk = dht_msg__unpack(NULL, len, buf);
        if (upk == NULL) {
                printf("Failed to unpack find_value_rsp message.\n");
                goto fail_unpack;
        }

        free(buf);
        dht_msg__free_unpacked(msg, NULL);
        dht_msg__free_unpacked(upk, NULL);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_unpack:
        dht_msg__free_unpacked(msg, NULL);
 fail_pack:
        free(buf);
 fail_msg:
        clear_contacts(contacts, n);
 fail_fill:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_find_value_rsp_msg_values(void)
{
        dht_msg_t * msg;
        dht_msg_t * upk;
        size_t      len;
        uint8_t *   buf;
        buffer_t *  values;
        size_t      i;
        uint64_t    ck;

        TEST_START();

        ck = generate_cookie();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        values = malloc(sizeof(*values) * 8);
        if (values == NULL) {
                printf("Failed to malloc values.\n");
                goto fail_values;
        }

        for (i = 0; i < 8; i++) {
                if (random_value(&values[i]) < 0) {
                        printf("Failed to create random value.\n");
                        goto fail_fill;
                }
        }

        msg = dht_kv_find_value_rsp_msg(dht.id.data, ck, NULL, 0, &values, 8);
        if (msg == NULL) {
                printf("Failed to build find value response message.\n");
                goto fail_msg;
        }

        values = NULL; /* msg owns the values now */

        len = dht_msg__get_packed_size(msg);
        if (len == 0) {
                printf("Failed to get packed length of find_value_rsp.\n");
                goto fail_msg;
        }

        buf = malloc(len);
        if (buf == NULL) {
                printf("Failed to malloc find_value_rsp buf.\n");
                goto fail_msg;
        }

        if (dht_msg__pack(msg, buf) != len) {
                printf("Failed to pack find_value_rsp message.\n");
                goto fail_pack;
        }

        upk = dht_msg__unpack(NULL, len, buf);
        if (upk == NULL) {
                printf("Failed to unpack find_value_rsp message.\n");
                goto fail_unpack;
        }

        if (upk->code != DHT_FIND_VALUE_RSP) {
                printf("Wrong code in find_value_rsp message (%s != %s).\n",
                       dht_code_str[upk->code],
                       dht_code_str[DHT_FIND_VALUE_RSP]);
                goto fail_unpack;
        }

        if (upk->val == NULL) {
                printf("No values in find_value_rsp message.\n");
                goto fail_unpack;
        }

        if (upk->val->n_values != 8) {
                printf("Not enough values in find_value_rsp (%zu != %lu).\n",
                       upk->val->n_values, 8UL);
                goto fail_unpack;
        }

        free(buf);
        dht_msg__free_unpacked(msg, NULL);
        dht_msg__free_unpacked(upk, NULL);

        free(values);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_unpack:
        dht_msg__free_unpacked(msg, NULL);
 fail_pack:
        free(buf);
 fail_msg:
 fail_fill:
        while((i--) > 0)
                freebuf(values[i]);
        free(values);
 fail_values:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_store_msg(void)
{
        dht_msg_t *     msg;
        size_t          len;
        uint8_t *       buf;
        struct timespec now;

        TEST_START();

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        msg = dht_kv_store_msg(dht.id.data, test_val, now.tv_sec + 10);
        if (msg == NULL) {
                printf("Failed to get store message.\n");
                goto fail_msg;
        }

        if (msg->code != DHT_STORE) {
                printf("Wrong code in store message (%s != %s).\n",
                       dht_code_str[msg->code],
                       dht_code_str[DHT_STORE]);
                goto fail_store_msg;
        }

        if (dht_kv_validate_msg(msg) < 0) {
                printf("Failed to validate store message.\n");
                goto fail_store_msg;
        }

        len = dht_msg__get_packed_size(msg);
        if (len == 0) {
                printf("Failed to get packed msg length.\n");
                goto fail_msg;
        }

        buf = malloc(len);
        if (buf == NULL) {
                printf("Failed to malloc store msg buf.\n");
                goto fail_msg;
        }

        if (dht_msg__pack(msg, buf) != len) {
                printf("Failed to pack store message.\n");
                goto fail_pack;
        }

        free(buf);

        dht_msg__free_unpacked(msg, NULL);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_pack:
        free(buf);
 fail_store_msg:
        dht_msg__free_unpacked(msg, NULL);
 fail_msg:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_kv_query_contacts_req_rsp(void)
{
        dht_msg_t *          req;
        dht_msg_t *          rsp;
        dht_contact_msg_t ** contacts;
        size_t               len = 2;

        uint8_t * key;

        TEST_START();

        sink_init();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        if (fill_dht_with_contacts(1) < 0) {
                printf("Failed to fill bucket with contacts.\n");
                goto fail_prep;
        }

        key = generate_id();
        if (key == NULL) {
                printf("Failed to generate key.\n");
                goto fail_prep;
        }

        if (dht_kv_query_contacts(key, NULL) < 0) {
                printf("Failed to query contacts.\n");
                goto fail_query;
        }

        req = sink_read();
        if (req == NULL) {
                printf("Failed to read request from sink.\n");
                goto fail_query;
        }

        if (dht_kv_validate_msg(req) < 0) {
                printf("Failed to validate find node req.\n");
                goto fail_val_req;
        }

        if (random_contact_list(&contacts, len) < 0) {
                printf("Failed to create random contact.\n");
                goto fail_val_req;
        }

        rsp = dht_kv_find_node_rsp_msg(key, req->find->cookie, &contacts, len);
        if (rsp == NULL) {
                printf("Failed to create find node response message.\n");
                goto fail_rsp;
        }

        memcpy(rsp->src->id.data, dht.id.data, dht.id.len);
        rsp->src->addr = generate_cookie();

        if (dht_kv_validate_msg(rsp) < 0) {
                printf("Failed to validate find node response message.\n");
                goto fail_val_rsp;
        }

        do_dht_kv_find_node_rsp(rsp->node);

        /* dht_contact_msg__free_unpacked(contacts[0], NULL); set to NULL */

        free(contacts);

        dht_msg__free_unpacked(rsp, NULL);

        free(key);

        dht_msg__free_unpacked(req, NULL);

        sink_fini();

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_val_rsp:
        dht_msg__free_unpacked(rsp, NULL);
 fail_rsp:
        while (len-- > 0)
                dht_contact_msg__free_unpacked(contacts[len], NULL);
        free(contacts);
 fail_val_req:
        dht_msg__free_unpacked(req, NULL);
 fail_query:
        free(key);
 fail_prep:
        dht_fini();
 fail_init:
        sink_fini();
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_req_create_destroy(void)
{
        struct dht_req * req;

        TEST_START();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        req = dht_req_create(dht.id.data);
        if (req == NULL) {
                printf("Failed to create kad request.\n");
                goto fail_req;
        }

        dht_req_destroy(req);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_req:
        dht_fini();
 fail_init:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_reg_unreg(void)
{
        TEST_START();

        sink_init();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        if (dht_reg(dht.id.data) < 0) {
                printf("Failed to register own id.\n");
                goto fail_reg;
        }

        if (sink.len != 0) {
                printf("Packet sent without contacts!");
                goto fail_msg;
        }

        if (dht_unreg(dht.id.data) < 0) {
                printf("Failed to unregister own id.\n");
                goto fail_msg;
        }

        dht_fini();

        sink_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_msg:
        dht_unreg(dht.id.data);
 fail_reg:
        dht_fini();
 fail_init:
        sink_fini();
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_reg_unreg_contacts(void)
{
        dht_msg_t * msg;

        TEST_START();

        sink_init();

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        if (fill_dht_with_contacts(4) < 0) {
                printf("Failed to fill bucket with contacts.\n");
                goto fail_reg;
        }

        if (dht_reg(dht.id.data) < 0) {
                printf("Failed to register own id.\n");
                goto fail_reg;
        }

        if (sink.len != dht.alpha) {
                printf("Packet sent to too few contacts!\n");
                goto fail_msg;
        }

        msg = sink_read();
        if (msg == NULL) {
                printf("Failed to read message from sink.\n");
                goto fail_msg;
        }

        if (msg->code != DHT_STORE) {
                printf("Wrong code in dht reg message (%s != %s).\n",
                       dht_code_str[msg->code],
                       dht_code_str[DHT_STORE]);
                goto fail_validation;
        }

        if (dht_kv_validate_msg(msg) < 0) {
                printf("Failed to validate dht message.\n");
                goto fail_validation;
        }

        if (dht_unreg(dht.id.data) < 0) {
                printf("Failed to unregister own id.\n");
                goto fail_validation;
        }

        dht_msg__free_unpacked(msg, NULL);

        dht_fini();

        sink_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_validation:
        dht_msg__free_unpacked(msg, NULL);
 fail_msg:
        sink_clear();
        dht_unreg(dht.id.data);
 fail_reg:
        dht_fini();
 fail_init:
        sink_fini();
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_reg_query_local(void)
{
        struct timespec now;
        buffer_t test_addr;

        TEST_START();

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        if (addr_to_buf(1234321, &test_addr) < 0) {
                printf("Failed to convert test address to buffer.\n");
                goto fail_buf;
        }

        if (dht_init(&test_dht_config) < 0) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        if (dht_reg(dht.id.data) < 0) {
                printf("Failed to register own id.\n");
                goto fail_reg;
        }

        if (dht_query(dht.id.data) == dht.addr) {
                printf("Succeeded to query own id.\n");
                goto fail_get;
        }

        if (dht_kv_store(dht.id.data, test_addr, now.tv_sec + 5) < 0) {
                printf("Failed to publish value.\n");
                goto fail_get;
        }

        if (dht_query(dht.id.data) != 1234321) {
                printf("Failed to return remote addr.\n");
                goto fail_get;
        }

        if (dht_unreg(dht.id.data) < 0) {
                printf("Failed to unregister own id.\n");
                goto fail_get;
        }

        freebuf(test_addr);

        dht_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_get:
        dht_unreg(dht.id.data);
 fail_reg:
        dht_fini();
 fail_init:
        freebuf(test_addr);
 fail_buf:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_dht_query(void)
{
        uint8_t *             key;
        struct dir_dht_config cfg;

        TEST_START();

        sink_init();

        cfg = test_dht_config;
        cfg.peer = generate_cookie();

        if (dht_init(&cfg)) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        key = generate_id();
        if (key == NULL) {
                printf("Failed to generate key.\n");
                goto fail_key;
        }

        if (dht_query(key) != INVALID_ADDR) {
                printf("Succeeded to get address without contacts.\n");
                goto fail_get;
        }

        if (sink.len != 0) {
                printf("Packet sent without contacts!");
                goto fail_test;
        }

        free(key);

        dht_fini();

        sink_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail_test:
        sink_clear();
 fail_get:
        free(key);
 fail_key:
        dht_fini();
 fail_init:
        sink_fini();
        return TEST_RC_FAIL;
}

static int test_dht_query_contacts(void)
{
        dht_msg_t *           msg;
        uint8_t *             key;
        struct dir_dht_config cfg;


        TEST_START();

        sink_init();

        cfg = test_dht_config;
        cfg.peer = generate_cookie();

        if (dht_init(&cfg)) {
                printf("Failed to create dht.\n");
                goto fail_init;
        }

        if (fill_dht_with_contacts(10) < 0) {
                printf("Failed to fill with contacts!");
                goto fail_contacts;
        }

        key = generate_id();
        if (key == NULL) {
                printf("Failed to generate key.");
                goto fail_contacts;
        }

        if (dht_query(key) != INVALID_ADDR) {
                printf("Succeeded to get address for random id.\n");
                goto fail_query;
        }

        msg = sink_read();
        if (msg == NULL) {
                printf("Failed to read message.!\n");
                goto fail_read;
        }

        if (dht_kv_validate_msg(msg) < 0) {
                printf("Failed to validate dht message.\n");
                goto fail_msg;
        }

        if (msg->code != DHT_FIND_VALUE_REQ) {
                printf("Failed to validate dht message.\n");
                goto fail_msg;
        }

        dht_msg__free_unpacked(msg, NULL);

        free(key);

        sink_clear();

        dht_fini();

        sink_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_msg:
        dht_msg__free_unpacked(msg, NULL);
 fail_read:
        sink_clear();
 fail_query:
        free(key);
 fail_contacts:
        dht_fini();
 fail_init:
        sink_fini();
        return TEST_RC_FAIL;
}

int dht_test(int     argc,
             char ** argv)
{
        int rc = 0;

        (void) argc;
        (void) argv;

        rc |= test_dht_init_fini();
        rc |= test_dht_start_stop();
        rc |= test_val_entry_create_destroy();
        rc |= test_dht_entry_create_destroy();
        rc |= test_dht_entry_update_get_val();
        rc |= test_dht_entry_update_get_lval();
        rc |= test_dht_kv_contact_create_destroy();
        rc |= test_dht_kv_contact_list();
        rc |= test_dht_kv_update_bucket();
        rc |= test_dht_kv_get_values();
        rc |= test_dht_kv_find_node_req_msg();
        rc |= test_dht_kv_find_node_rsp_msg();
        rc |= test_dht_kv_find_node_rsp_msg_contacts();
        rc |= test_dht_kv_query_contacts_req_rsp();
        rc |= test_dht_kv_find_value_req_msg();
        rc |= test_dht_kv_find_value_rsp_msg();
        rc |= test_dht_kv_find_value_rsp_msg_contacts();
        rc |= test_dht_kv_find_value_rsp_msg_values();
        rc |= test_dht_kv_store_msg();
        rc |= test_dht_req_create_destroy();
        rc |= test_dht_reg_unreg();
        rc |= test_dht_reg_unreg_contacts();
        rc |= test_dht_reg_query_local();
        rc |= test_dht_query();
        rc |= test_dht_query_contacts();

        return rc;
}
