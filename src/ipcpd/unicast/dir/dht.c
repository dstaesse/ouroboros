/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Distributed Hash Table based on Kademlia
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
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

#if !defined (__DHT_TEST__)
  #if defined(__linux__) || defined(__CYGWIN__)
    #define _DEFAULT_SOURCE
  #else
    #define _POSIX_C_SOURCE 200112L
  #endif
#endif

#include "config.h"

#define DHT              "dht"
#define OUROBOROS_PREFIX DHT

#include <ouroboros/endian.h>
#include <ouroboros/hash.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/list.h>
#include <ouroboros/random.h>
#include <ouroboros/rib.h>
#include <ouroboros/time.h>
#include <ouroboros/tpm.h>
#include <ouroboros/utils.h>
#include <ouroboros/pthread.h>

#include "addr-auth.h"
#include "common/connmgr.h"
#include "dht.h"
#include "dt.h"
#include "ipcp.h"
#include "ops.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>
#include <limits.h>

#include "dht.pb-c.h"
typedef DhtMsg              dht_msg_t;
typedef DhtContactMsg       dht_contact_msg_t;
typedef DhtStoreMsg         dht_store_msg_t;
typedef DhtFindReqMsg       dht_find_req_msg_t;
typedef DhtFindNodeRspMsg   dht_find_node_rsp_msg_t;
typedef DhtFindValueRspMsg  dht_find_value_rsp_msg_t;
typedef ProtobufCBinaryData binary_data_t;

#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#endif

#define DHT_MAX_REQS  128  /* KAD recommends rnd(), bmp can be changed.    */
#define DHT_WARN_REQS 100  /* Warn if number of requests exceeds this.     */
#define DHT_MAX_VALS  8    /* Max number of values to return for a key.    */
#define DHT_T_CACHE   60   /* Max cache time for values (s)                */
#define DHT_T_RESP    2    /* Response time to wait for a response (s).    */
#define DHT_N_REPUB   5    /* Republish if expiry within n replications.   */
#define DHT_R_PING    2    /* Ping retries before declaring peer dead.     */
#define DHT_QUEER     15   /* Time to declare peer questionable.           */
#define DHT_BETA      8    /* Bucket split factor, must be 1, 2, 4 or 8.   */
#define DHT_RESP_RETR 6    /* Number of retries on sending a response.     */
#define HANDLE_TIMEO  1000 /* Timeout for dht_handle_packet tpm check (ms) */
#define DHT_INVALID   0    /* Invalid cookie value.                        */

#define KEY_FMT "K<" HASH_FMT64 ">"
#define KEY_VAL(key) HASH_VAL64(key)

#define VAL_FMT "V<" HASH_FMT64 ">"
#define VAL_VAL(val) HASH_VAL64((val).data)

#define KV_FMT "<" HASH_FMT64 ", " HASH_FMT64 ">"
#define KV_VAL(key, val) HASH_VAL64(key), HASH_VAL64((val).data)

#define PEER_FMT "[" HASH_FMT64 "|" ADDR_FMT32 "]"
#define PEER_VAL(id, addr) HASH_VAL64(id), ADDR_VAL32(&(addr))

#define DHT_CODE(msg) dht_code_str[(msg)->code]

#define TX_HDR_FMT "%s --> " PEER_FMT
#define TX_HDR_VAL(msg, id, addr) DHT_CODE(msg), PEER_VAL(id, addr)

#define RX_HDR_FMT "%s <-- " PEER_FMT
#define RX_HDR_VAL(msg) DHT_CODE(msg), \
        PEER_VAL(msg->src->id.data, msg->src->addr)

#define CK_FMT "|" HASH_FMT64 "|"
#define CK_VAL(cookie) HASH_VAL64(&(cookie))

#define IS_REQUEST(code) \
        (code == DHT_FIND_NODE_REQ || code == DHT_FIND_VALUE_REQ)

enum dht_code {
        DHT_STORE,
        DHT_FIND_NODE_REQ,
        DHT_FIND_NODE_RSP,
        DHT_FIND_VALUE_REQ,
        DHT_FIND_VALUE_RSP
};

const char * dht_code_str[] = {
        "DHT_STORE",
        "DHT_FIND_NODE_REQ",
        "DHT_FIND_NODE_RSP",
        "DHT_FIND_VALUE_REQ",
        "DHT_FIND_VALUE_RSP"
};

enum dht_state {
        DHT_NULL = 0,
        DHT_INIT,
        DHT_RUNNING
};

struct val_entry {
        struct list_head next;

        buffer_t         val;

        time_t           t_exp;   /* Expiry time           */
        time_t           t_repl;  /* Last replication time */
};

struct dht_entry {
        struct list_head next;

        uint8_t *        key;

        struct {
                struct list_head list;
                size_t           len;
        } vals;  /* We don't own these, only replicate */

        struct {
                struct list_head list;
                size_t           len;
        } lvals; /* We own these, must be republished  */
};

struct contact {
        struct list_head next;

        uint8_t *        id;
        uint64_t         addr;

        size_t           fails;
        time_t           t_seen;
};

struct peer_entry {
        struct list_head next;

        uint64_t         cookie;
        uint8_t *        id;
        uint64_t         addr;
        enum dht_code    code;

        time_t           t_sent;
};

struct dht_req {
        struct list_head next;

        uint8_t *        key;
        time_t           t_exp;

        struct {
                struct list_head list;
                size_t           len;
        } peers;

        struct {
                struct list_head list;
                size_t           len;
        } cache;
};

struct bucket {
        struct {
                struct list_head list;
                size_t           len;
        } contacts;

        struct {
                struct list_head list;
                size_t           len;
        } alts;

        time_t           t_refr;

        size_t           depth;
        uint8_t          mask;

        struct bucket *  parent;
        struct bucket *  children[1L << DHT_BETA];
};

struct cmd {
        struct list_head next;
        buffer_t         cbuf;
};

struct dir_ops dht_dir_ops = {
        .init  = (int (*)(void *)) dht_init,
        .fini  = dht_fini,
        .start = dht_start,
        .stop  = dht_stop,
        .reg   = dht_reg,
        .unreg = dht_unreg,
        .query = dht_query
};

struct {
        struct { /* Kademlia parameters */
                uint32_t alpha;     /* Number of concurrent requests   */
                size_t   k;         /* Number of replicas to store     */
                time_t   t_expire;  /* Expiry time for values (s)      */
                time_t   t_refresh; /* Refresh time for contacts (s)   */
                time_t   t_repl;    /* Replication time for values (s) */
        };

        buffer_t       id;

        time_t         t0;    /* Creation time               */
        uint64_t       addr;  /* Our own address             */
        uint64_t       peer;  /* Enrollment peer address     */
        uint64_t       magic; /* Magic cookie for retransmit */

        uint64_t       eid;   /* Entity ID                   */

        struct tpm *   tpm;
        pthread_t      worker;

        enum dht_state state;

        struct {
                struct {
                        struct bucket * root;
                } contacts;

                struct {
                        struct list_head list;
                        size_t           len;
                        size_t           vals;
                        size_t           lvals;
                } kv;

                pthread_rwlock_t lock;
        } db;

        struct {
                struct list_head list;
                size_t           len;
                pthread_cond_t   cond;
                pthread_mutex_t  mtx;
        } reqs;

        struct {
                struct list_head list;
                pthread_cond_t   cond;
                pthread_mutex_t  mtx;
        } cmds;
} dht;


/* DHT RIB */

static const char * dht_dir[] = {
        "database",
        "stats",
        NULL
};

const char * dht_stats = \
        "DHT: " HASH_FMT64 "\n"
        "  Created: %s\n"
        "  Address: " ADDR_FMT32 "\n"
        "  Kademlia parameters:\n"
        "     Number of concurrent requests (alpha): %10zu\n"
        "     Number of replicas (k):                %10zu\n"
        "     Expiry time for values (s):            %10ld\n"
        "     Refresh time for contacts (s):         %10ld\n"
        "     Replication time for values (s):       %10ld\n"
        "  Number of keys:                           %10zu\n"
        "  Number of local values:                   %10zu\n"
        "  Number of non-local values:               %10zu\n";

static int dht_rib_statfile(char * buf,
                            size_t len)
{
        struct tm * tm;
        char        tmstr[RIB_TM_STRLEN];
        size_t      keys;
        size_t      vals;
        size_t      lvals;

        assert(buf != NULL);
        assert(len > 0);

        pthread_rwlock_rdlock(&dht.db.lock);

        keys  = dht.db.kv.len;
        lvals = dht.db.kv.lvals;
        vals  = dht.db.kv.vals;

        pthread_rwlock_unlock(&dht.db.lock);

        tm = gmtime(&dht.t0);
        strftime(tmstr, sizeof(tmstr), RIB_TM_FORMAT, tm);

        snprintf(buf, len, dht_stats,
                 HASH_VAL64(dht.id.data),
                 tmstr,
                 ADDR_VAL32(&dht.addr),
                 dht.alpha, dht.k,
                 dht.t_expire, dht.t_refresh, dht.t_repl,
                 keys, vals, lvals);

        return strlen(buf);
}

static size_t dht_db_file_len(void)
{
        size_t sz;
        size_t vals;

        sz = 18; /* DHT database + 2 * \n */

        pthread_rwlock_rdlock(&dht.db.lock);

        if (dht.db.kv.len == 0) {
                pthread_rwlock_unlock(&dht.db.lock);
                sz += 14; /* No entries */
                return sz;
        }

        sz += 39 * 3 + 1; /* tally + extra newline */
        sz += dht.db.kv.len * (25 + 19 + 23 + 1);

        vals = dht.db.kv.vals + dht.db.kv.lvals;

        sz += vals * (48 + 2 * RIB_TM_STRLEN);

        pthread_rwlock_unlock(&dht.db.lock);

        return sz;
}

static int dht_rib_dbfile(char * buf,
                          size_t len)
{
        struct tm * tm;
        char        tmstr[RIB_TM_STRLEN];
        char        exstr[RIB_TM_STRLEN];
        size_t      i = 0;
        struct      list_head * p;

        assert(buf != NULL);
        assert(len > 0);

        pthread_rwlock_rdlock(&dht.db.lock);

        if (dht.db.kv.len == 0) {
                i += snprintf(buf, len, "  No entries.\n");
                pthread_rwlock_unlock(&dht.db.lock);
                return i;
        }

        i += snprintf(buf + i, len - i, "DHT database:\n\n");
        i += snprintf(buf + i, len - i,
                      "Number of keys:             %10zu\n"
                      "Number of local values:     %10zu\n"
                      "Number of non-local values: %10zu\n\n",
                      dht.db.kv.len, dht.db.kv.vals, dht.db.kv.lvals);

        list_for_each(p, &dht.db.kv.list) {
                struct dht_entry * e = list_entry(p, struct dht_entry, next);
                struct list_head * h;

                i += snprintf(buf + i, len - i, "Key: " KEY_FMT "\n",
                              KEY_VAL(e->key));
                i += snprintf(buf + i, len - i, "  Local entries:\n");

                list_for_each(h, &e->vals.list) {
                        struct val_entry * v;

                        v = list_entry(h, struct val_entry, next);

                        tm = gmtime(&v->t_repl);
                        strftime(tmstr, sizeof(tmstr), RIB_TM_FORMAT, tm);

                        tm = gmtime(&v->t_exp);
                        strftime(exstr, sizeof(exstr), RIB_TM_FORMAT, tm);

                        i += snprintf(buf + i, len - i,
                                "    " VAL_FMT
                                ", t_replicated=%.*s, t_expire=%.*s\n",
                                VAL_VAL(v->val),
                                RIB_TM_STRLEN, tmstr,
                                RIB_TM_STRLEN, exstr);
                }

                i += snprintf(buf + i, len - i, "\n");

                i += snprintf(buf + i, len - i, "  Non-local entries:\n");

                list_for_each(h, &e->lvals.list) {
                        struct val_entry * v;

                        v= list_entry(h, struct val_entry, next);

                        tm = gmtime(&v->t_repl);
                        strftime(tmstr, sizeof(tmstr), RIB_TM_FORMAT, tm);

                        tm = gmtime(&v->t_exp);
                        strftime(exstr, sizeof(exstr), RIB_TM_FORMAT, tm);

                        i += snprintf(buf + i, len - i,
                                "    " VAL_FMT
                                ", t_replicated=%.*s, t_expire=%.*s\n",
                                VAL_VAL(v->val),
                                RIB_TM_STRLEN, tmstr,
                                RIB_TM_STRLEN, exstr);

                }
        }

        pthread_rwlock_unlock(&dht.db.lock);

        printf("DHT RIB DB file generated (%zu bytes).\n", i);

        return i;
}

static int dht_rib_read(const char * path,
                        char *       buf,
                        size_t       len)
{
        char * entry;

        entry = strstr(path, RIB_SEPARATOR) + 1;

        if (strcmp(entry, "database") == 0) {
                return dht_rib_dbfile(buf, len);
        } else if (strcmp(entry, "stats") == 0) {
                return dht_rib_statfile(buf, len);
        }

        return 0;
}

static int dht_rib_readdir(char *** buf)
{
        int i = 0;

        while (dht_dir[i++] != NULL);

        *buf = malloc(sizeof(**buf) * i);
        if (*buf == NULL)
                goto fail_buf;

        i = 0;

        while (dht_dir[i] != NULL) {
                (*buf)[i] = strdup(dht_dir[i]);
                if ((*buf)[i] == NULL)
                        goto fail_dup;
                i++;
        }

        return i;
 fail_dup:
        freepp(char, *buf, i);
 fail_buf:
        return -ENOMEM;
}

static int dht_rib_getattr(const char *      path,
                           struct rib_attr * attr)
{
        struct timespec now;
        char *          entry;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        attr->mtime = now.tv_sec;

        entry = strstr(path, RIB_SEPARATOR) + 1;

        if (strcmp(entry, "database") == 0) {
                attr->size = dht_db_file_len();
        } else if (strcmp(entry, "stats") == 0) {
                attr->size =  545;
        }

        return 0;
}

static struct rib_ops r_ops = {
        .read    = dht_rib_read,
        .readdir = dht_rib_readdir,
        .getattr = dht_rib_getattr
};

/* Helper functions */

static uint8_t * generate_id(void)
{
        uint8_t * id;

        if(dht.id.len < sizeof(uint64_t)) {
                log_err("DHT ID length is too short (%zu < %zu).",
                        dht.id.len, sizeof(uint64_t));
                return NULL;
        }

        id = malloc(dht.id.len);
        if (id == NULL) {
                log_err("Failed to malloc ID.");
                goto fail_id;
        }

        if (random_buffer(id, dht.id.len) < 0) {
                log_err("Failed to generate random ID.");
                goto fail_rnd;
        }

        return id;
 fail_rnd:
        free(id);
 fail_id:
        return NULL;
}

static uint64_t generate_cookie(void)
{
        uint64_t cookie = DHT_INVALID;

        while (cookie == DHT_INVALID)
                random_buffer((uint8_t *) &cookie, sizeof(cookie));

        return cookie;
}

/*
 * If someone builds a network where the n (n > k) closest nodes all
 * have IDs starting with the same 64 bits: by all means, change this.
 */
static uint64_t dist(const uint8_t * src,
                     const uint8_t * dst)
{
        assert(dht.id.len >= sizeof(uint64_t));

        return betoh64(*((uint64_t *) src) ^ *((uint64_t *) dst));
}

#define IS_CLOSER(x, y) (dist((x), dht.id.data) < dist((y), dht.id.data))

static int addr_to_buf(const uint64_t addr,
                       buffer_t *     buf)
{
        size_t len;
        uint64_t _addr;

        len = sizeof(addr);
        _addr = hton64(addr);

        assert(buf != NULL);

        buf->data = malloc(len);
        if (buf->data == NULL)
                goto fail_malloc;

        buf->len = sizeof(_addr);
        memcpy(buf->data, &_addr, sizeof(_addr));

        return 0;
 fail_malloc:
        return -ENOMEM;
}

static int buf_to_addr(const buffer_t buf,
                       uint64_t *     addr)
{
        assert(addr != NULL);
        assert(buf.data != NULL);

        if (buf.len != sizeof(*addr))
                return - EINVAL;

        *addr = ntoh64(*((uint64_t *) buf.data));

        if (*addr == dht.addr)
                *addr = INVALID_ADDR;

        return 0;
}

static uint8_t * dht_dup_key(const uint8_t * key)
{
        uint8_t * dup;

        assert(key != NULL);
        assert(dht.id.len != 0);

        dup = malloc(dht.id.len);
        if (dup == NULL)
                return NULL;

        memcpy(dup, key, dht.id.len);

        return dup;
}

/* DHT */

static struct val_entry * val_entry_create(const buffer_t val,
                                           time_t         exp)
{
        struct val_entry * e;
        struct timespec    now;

        assert(val.data != NULL);
        assert(val.len > 0);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

#ifndef __DHT_TEST_ALLOW_EXPIRED__
        if (exp < now.tv_sec)
                return NULL; /* Refuse to add expired values */
#endif
        e = malloc(sizeof(*e));
        if (e == NULL)
                goto fail_entry;

        list_head_init(&e->next);

        e->val.len = val.len;
        e->val.data = malloc(val.len);
        if (e->val.data == NULL)
                goto fail_val;

        memcpy(e->val.data, val.data, val.len);

        e->t_repl  = 0;
        e->t_exp   = exp;

        return e;

 fail_val:
        free(e);
 fail_entry:
        return NULL;
}

static void val_entry_destroy(struct val_entry * v)
{
        assert(v->val.data != NULL);

        freebuf(v->val);
        free(v);
}

static struct dht_entry * dht_entry_create(const uint8_t * key)
{
        struct dht_entry * e;

        assert(key != NULL);

        e = malloc(sizeof(*e));
        if (e == NULL)
                goto fail_entry;

        list_head_init(&e->next);
        list_head_init(&e->vals.list);
        list_head_init(&e->lvals.list);

        e->vals.len = 0;
        e->lvals.len = 0;

        e->key = dht_dup_key(key);
        if (e->key == NULL)
                goto fail_key;

        return e;
 fail_key:
        free(e);
 fail_entry:
        return NULL;
}

static void dht_entry_destroy(struct dht_entry * e)
{
        struct list_head * p;
        struct list_head * h;

        assert(e != NULL);

        list_for_each_safe(p, h, &e->vals.list) {
                struct val_entry * v = list_entry(p, struct val_entry, next);
                list_del(&v->next);
                val_entry_destroy(v);
                --e->vals.len;
                --dht.db.kv.vals;
        }

        list_for_each_safe(p, h, &e->lvals.list) {
                struct val_entry * v = list_entry(p, struct val_entry, next);
                list_del(&v->next);
                val_entry_destroy(v);
                --e->lvals.len;
                --dht.db.kv.lvals;
        }

        free(e->key);

        assert(e->vals.len == 0 && e->lvals.len == 0);

        free(e);
}

static struct val_entry * dht_entry_get_lval(const struct dht_entry * e,
                                             const buffer_t           val)
{
        struct list_head * p;

        assert(e != NULL);
        assert(val.data != NULL);
        assert(val.len > 0);

        list_for_each(p, &e->lvals.list) {
                struct val_entry * v = list_entry(p, struct val_entry, next);
                if (bufcmp(&v->val, &val) == 0)
                        return v;
        }

        return NULL;
}

static struct val_entry * dht_entry_get_val(const struct dht_entry * e,
                                            const buffer_t           val)
{
        struct list_head * p;

        assert(e != NULL);
        assert(val.data != NULL);
        assert(val.len > 0);

        list_for_each(p, &e->vals.list) {
                struct val_entry * v = list_entry(p, struct val_entry, next);
                if (bufcmp(&v->val, &val) == 0)
                        return v;

        }

        return NULL;
}

static int dht_entry_update_val(struct dht_entry * e,
                                buffer_t           val,
                                time_t             exp)
{
        struct val_entry * v;
        struct timespec    now;

        assert(e != NULL);
        assert(val.data != NULL);
        assert(val.len > 0);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        if (exp < now.tv_sec)
                return -EINVAL; /* Refuse to add expired values */

        if (dht_entry_get_lval(e, val) != NULL) {
                log_dbg(KV_FMT " Val already in lvals.", KV_VAL(e->key, val));
                return 0; /* Refuse to add local values */
        }

        v = dht_entry_get_val(e, val);
        if (v == NULL) {
                v = val_entry_create(val, exp);
                if (v == NULL)
                        return -ENOMEM;

                list_add_tail(&v->next, &e->vals.list);
                ++e->vals.len;
                ++dht.db.kv.vals;

                return 0;
        }

        if (v->t_exp < exp)
                v->t_exp  = exp;

        return 0;
}

static int dht_entry_update_lval(struct dht_entry * e,
                                 buffer_t           val)
{
        struct val_entry * v;
        struct timespec    now;

        assert(e != NULL);
        assert(val.data != NULL);
        assert(val.len > 0);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        v = dht_entry_get_lval(e, val);
        if (v == NULL) {
                log_dbg(KV_FMT " Adding lval.", KV_VAL(e->key, val));
                v = val_entry_create(val, now.tv_sec + dht.t_expire);
                if (v == NULL)
                        return -ENOMEM;

                list_add_tail(&v->next, &e->lvals.list);
                ++e->lvals.len;
                ++dht.db.kv.lvals;

                return 0;
        }

        return 0;
}

static int dht_entry_remove_lval(struct dht_entry * e,
                                 buffer_t           val)
{
        struct val_entry * v;

        assert(e != NULL);
        assert(val.data != NULL);
        assert(val.len > 0);

        v = dht_entry_get_lval(e, val);
        if (v == NULL)
                return -ENOENT;

        log_dbg(KV_FMT " Removing lval.", KV_VAL(e->key, val));

        list_del(&v->next);
        val_entry_destroy(v);
        --e->lvals.len;
        --dht.db.kv.lvals;

        return 0;
}

#define IS_EXPIRED(v, now) ((now)->tv_sec > (v)->t_exp)
static void dht_entry_remove_expired_vals(struct dht_entry * e)
{
        struct list_head * p;
        struct list_head * h;
        struct timespec    now;

        assert(e != NULL);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        list_for_each_safe(p, h, &e->vals.list) {
                struct val_entry * v = list_entry(p, struct val_entry, next);
                if (!IS_EXPIRED(v, &now))
                        continue;

                log_dbg(KV_FMT " Value expired." , KV_VAL(e->key, v->val));
                list_del(&v->next);
                val_entry_destroy(v);
                --e->vals.len;
                --dht.db.kv.vals;
        }
}

static struct dht_entry * __dht_kv_find_entry(const uint8_t * key)
{
        struct list_head * p;

        assert(key != NULL);

        list_for_each(p, &dht.db.kv.list) {
                struct dht_entry * e = list_entry(p, struct dht_entry, next);
                if (!memcmp(key, e->key, dht.id.len))
                        return e;
        }

        return NULL;
}

static void dht_kv_remove_expired_entries(void)
{
        struct list_head * p;
        struct list_head * h;
        struct timespec    now;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_rwlock_wrlock(&dht.db.lock);

        list_for_each_safe(p, h, &dht.db.kv.list) {
                struct dht_entry * e = list_entry(p, struct dht_entry, next);
                dht_entry_remove_expired_vals(e);
                if (e->lvals.len > 0 || e->vals.len > 0)
                        continue;

                log_dbg(KEY_FMT " Entry removed. ", KEY_VAL(e->key));
                list_del(&e->next);
                dht_entry_destroy(e);
                --dht.db.kv.len;
        }

        pthread_rwlock_unlock(&dht.db.lock);
}


static struct contact * contact_create(const uint8_t * id,
                                       uint64_t        addr)
{
        struct contact * c;
        struct timespec  t;

        c = malloc(sizeof(*c));
        if (c == NULL)
                return NULL;

        list_head_init(&c->next);

        clock_gettime(CLOCK_REALTIME_COARSE, &t);

        c->addr   = addr;
        c->fails  = 0;
        c->t_seen = t.tv_sec;
        c->id     = dht_dup_key(id);
        if (c->id == NULL) {
                free(c);
                return NULL;
        }

        return c;
}

static void contact_destroy(struct contact * c)
{
        assert(c != NULL);
        assert(list_is_empty(&c->next));

        free(c->id);
        free(c);
}

static struct dht_req * dht_req_create(const uint8_t * key)
{
        struct dht_req * req;
        struct timespec  now;

        assert(key != NULL);

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        req = malloc(sizeof(*req));
        if (req == NULL)
                goto fail_malloc;

        list_head_init(&req->next);

        req->t_exp = now.tv_sec + DHT_T_RESP;

        list_head_init(&req->peers.list);
        req->peers.len = 0;

        req->key = dht_dup_key(key);
        if (req->key == NULL)
                goto fail_dup_key;

        list_head_init(&req->cache.list);
        req->cache.len = 0;

        return req;

 fail_dup_key:
        free(req);
 fail_malloc:
        return NULL;
}

static void dht_req_destroy(struct dht_req * req)
{
        struct list_head * p;
        struct list_head * h;

        assert(req);
        assert(req->key);

        list_for_each_safe(p, h, &req->peers.list) {
                struct peer_entry * e = list_entry(p, struct peer_entry, next);
                list_del(&e->next);
                free(e->id);
                free(e);
                --req->peers.len;
        }

        list_for_each_safe(p, h, &req->cache.list) {
                struct val_entry * e = list_entry(p, struct val_entry, next);
                list_del(&e->next);
                val_entry_destroy(e);
                --req->cache.len;
        }

        free(req->key);

        assert(req->peers.len == 0);

        free(req);
}

static struct peer_entry * dht_req_get_peer(struct dht_req *    req,
                                            struct peer_entry * e)
{
        struct list_head * p;

        list_for_each(p, &req->peers.list) {
                struct peer_entry * x = list_entry(p, struct peer_entry, next);
                if (x->addr == e->addr)
                        return x;
        }

        return NULL;
}

#define IS_MAGIC(peer) ((peer)->cookie == dht.magic)
void dht_req_add_peer(struct dht_req * req,
                      struct peer_entry * e)
{
        struct peer_entry * x; /* existing */
        struct list_head *  p; /* iterator */
        size_t              pos = 0;

        assert(req   != NULL);
        assert(e     != NULL);
        assert(e->id != NULL);

        /*
         * Dedupe messages to the same peer, unless
         *   1) The previous request was FIND_NODE and now it's FIND_VALUE
         *   2) We urgently need contacts from emergency peer (magic cookie)
         */
        x = dht_req_get_peer(req, e);
        if (x != NULL && x->code >= e->code && !IS_MAGIC(e))
                goto skip;

        /* Find how this contact ranks in distance to the key */
        list_for_each(p, &req->peers.list) {
                struct peer_entry * y = list_entry(p, struct peer_entry, next);
                if (IS_CLOSER(y->id, e->id)) {
                        pos++;
                        continue;
                }
                break;
        }

        /* Add a new peer to this request if we need to */
        if (pos < dht.alpha || !IS_MAGIC(e)) {
                x = malloc(sizeof(*x));
                if (x == NULL) {
                        log_err("Failed to malloc peer entry.");
                        goto skip;
                }

                x->cookie = e->cookie;
                x->addr   = e->addr;
                x->code   = e->code;
                x->t_sent = e->t_sent;
                x->id     = dht_dup_key(e->id);
                if (x->id == NULL) {
                        log_err("Failed to dup peer ID.");
                        free(x);
                        goto skip;
                }

                if (IS_MAGIC(e))
                        list_add(&x->next, p);
                else
                        list_add_tail(&x->next, p);
                ++req->peers.len;
                return;
        }
 skip:
        list_del(&e->next);
        free(e->id);
        free(e);
}

static size_t dht_req_add_peers(struct dht_req *   req,
                                struct list_head * pl)
{
        struct list_head *  p;
        struct list_head *  h;
        size_t              n = 0;

        assert(req != NULL);
        assert(pl  != NULL);

        list_for_each_safe(p, h, pl) {
                struct peer_entry * e = list_entry(p, struct peer_entry, next);
                dht_req_add_peer(req, e);
        }

        return n;
}

static bool dht_req_has_peer(struct dht_req * req,
                             uint64_t         cookie)
{
        struct list_head * p;

        assert(req != NULL);

        list_for_each(p, &req->peers.list) {
                struct peer_entry * e = list_entry(p, struct peer_entry, next);
                if (e->cookie == cookie)
                        return true;
        }

        return false;
}

static void peer_list_destroy(struct list_head * pl)
{
        struct list_head * p;
        struct list_head * h;

        assert(pl != NULL);

        list_for_each_safe(p, h, pl) {
                struct peer_entry * e = list_entry(p, struct peer_entry, next);
                list_del(&e->next);
                free(e->id);
                free(e);
        }
}

static int dht_kv_create_peer_list(struct list_head * cl,
                                   struct list_head * pl,
                                   enum dht_code      code)
{
        struct list_head *  p;
        struct list_head *  h;
        struct timespec     now;
        size_t              len;

        assert(cl != NULL);
        assert(pl != NULL);
        assert(list_is_empty(pl));

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        len = 0;

        list_for_each_safe(p, h, cl) {
                struct contact * c = list_entry(p, struct contact, next);
                struct peer_entry * e;
                if (len++ == dht.alpha)
                        break;

                e = malloc(sizeof(*e));
                if (e == NULL)
                        return -ENOMEM;

                e->cookie = generate_cookie();
                e->code   = code;
                e->addr   = c->addr;
                e->t_sent = now.tv_sec;

                e->id = c->id;

                list_add_tail(&e->next, pl);

                list_del(&c->next);
                c->id = NULL; /* we stole the id */
                contact_destroy(c);
        }

        return 0;
}

static struct dht_req * __dht_kv_req_get_req(const uint8_t * key)
{
        struct list_head * p;

        list_for_each(p, &dht.reqs.list) {
                struct dht_req * r = list_entry(p, struct dht_req, next);
                if (memcmp(r->key, key, dht.id.len) == 0)
                        return r;
        }

        return NULL;
}

static struct dht_req * __dht_kv_get_req_cache(const uint8_t * key)
{
        struct dht_req * req;

        assert(key != NULL);

        req = __dht_kv_req_get_req(key);
        if (req == NULL)
                return NULL;

        if (req->cache.len == 0)
                return NULL;

        return req;
}

static void __dht_kv_req_remove(const uint8_t * key)
{
        struct dht_req * req;

        assert(key != NULL);

        req = __dht_kv_req_get_req(key);
        if (req == NULL)
                return;

        list_del(&req->next);
        --dht.reqs.len;

        dht_req_destroy(req);
}

static struct dht_req * __dht_kv_get_req_peer(const uint8_t * key,
                                              uint64_t        cookie)
{
        struct dht_req * req;

        assert(key != NULL);

        req = __dht_kv_req_get_req(key);
        if (req == NULL)
                return NULL;

        if (!dht_req_has_peer(req, cookie))
                return NULL;

        return req;
}

static bool dht_kv_has_req(const uint8_t * key,
                           uint64_t        cookie)
{
        bool found;

        pthread_mutex_lock(&dht.reqs.mtx);

        found = __dht_kv_get_req_peer(key, cookie) != NULL;

        pthread_mutex_unlock(&dht.reqs.mtx);

        return found;
}

/*
 * This will filter the peer list for addresses that still need to be
 * contacted.
 */
static int dht_kv_update_req(const uint8_t *    key,
                             struct list_head * pl)
{
        struct dht_req * req;
        struct timespec  now;

        assert(key != NULL);
        assert(pl != NULL);
        assert(!list_is_empty(pl));

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_mutex_lock(&dht.reqs.mtx);

        req = __dht_kv_req_get_req(key);
        if (req == NULL) {
                if (dht.reqs.len == DHT_MAX_REQS) {
                        log_err(KEY_FMT " Max reqs reached (%zu).",
                                KEY_VAL(key), dht.reqs.len);
                        peer_list_destroy(pl);
                        goto fail_req;
                }
                req = dht_req_create(key);
                if (req == NULL) {
                        log_err(KEY_FMT "Failed to create req.", KEY_VAL(key));
                        goto fail_req;
                }
                list_add_tail(&req->next, &dht.reqs.list);
                ++dht.reqs.len;
        }

        if (req->cache.len > 0) /* Already have values */
                peer_list_destroy(pl);

        dht_req_add_peers(req, pl);
        req->t_exp = now.tv_sec + DHT_T_RESP;

        if (dht.reqs.len > DHT_WARN_REQS) {
                log_warn("Number of outstanding requests (%zu) exceeds %u.",
                         dht.reqs.len, DHT_WARN_REQS);
        }

        pthread_mutex_unlock(&dht.reqs.mtx);

        return 0;
 fail_req:
        pthread_mutex_unlock(&dht.reqs.mtx);
        return -1;
}

static int dht_kv_respond_req(uint8_t *       key,
                              binary_data_t * vals,
                              size_t          len)
{
        struct dht_req * req;
        struct timespec  now;
        size_t i;

        assert(key != NULL);
        assert(vals != NULL);
        assert(len > 0);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_mutex_lock(&dht.reqs.mtx);

        req = __dht_kv_req_get_req(key);
        if (req == NULL) {
                log_warn(KEY_FMT " Failed to find req.", KEY_VAL(key));
                goto fail_req;
        }

        for (i = 0; i < len; ++i) {
                struct val_entry * e;
                buffer_t val;
                val.data = vals[i].data;
                val.len = vals[i].len;
                e = val_entry_create(val, now.tv_sec + DHT_T_CACHE);
                if (e == NULL) {
                        log_err(" Failed to create val_entry.");
                        continue;
                }

                list_add_tail(&e->next, &req->cache.list);
                ++req->cache.len;
        }

        pthread_cond_broadcast(&dht.reqs.cond);

        pthread_mutex_unlock(&dht.reqs.mtx);
 fail_req:
        pthread_mutex_unlock(&dht.reqs.mtx);
        return -1;
}

static ssize_t dht_kv_wait_req(const uint8_t * key,
                               buffer_t **     vals)
{
        struct list_head * p;
        struct dht_req *   req;
        struct timespec    t;
#ifdef __DHT_TEST__
        struct timespec    intv = TIMESPEC_INIT_MS(10);
#else
        struct timespec    intv = TIMESPEC_INIT_S(DHT_T_RESP);
#endif
        size_t             max;
        size_t             i = 0;
        int                ret = 0;

        assert(key != NULL);
        assert(vals != NULL);

        clock_gettime(PTHREAD_COND_CLOCK, &t);

        ts_add(&t, &intv, &t);

        pthread_mutex_lock(&dht.reqs.mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, &dht.reqs.mtx);

        while ((req = __dht_kv_get_req_cache(key)) == NULL) {
                ret = pthread_cond_timedwait(&dht.reqs.cond, &dht.reqs.mtx, &t);
                if (ret == ETIMEDOUT)
                        break;
        }

        pthread_cleanup_pop(false);

        if (ret == ETIMEDOUT) {
                log_warn(KEY_FMT " Req timed out.", KEY_VAL(key));
                __dht_kv_req_remove(key);
                goto timedout;
        }

        max = MIN(req->cache.len, DHT_MAX_VALS);
        if (max == 0)
                goto no_vals;

        *vals = malloc(max * sizeof(**vals));
        if (*vals == NULL) {
                log_err(KEY_FMT "Failed to malloc val buffer.", KEY_VAL(key));
                goto fail_vals;
        }

        memset(*vals, 0, max * sizeof(**vals));

        list_for_each(p, &req->cache.list) {
                struct val_entry * v;
                if (i == max)
                        break; /* We have enough values */
                v = list_entry(p, struct val_entry, next);
                (*vals)[i].data = malloc(v->val.len);
                if ((*vals)[i].data == NULL)
                        goto fail_val_data;

                (*vals)[i].len = v->val.len;
                memcpy((*vals)[i++].data, v->val.data, v->val.len);
        }

        pthread_mutex_unlock(&dht.reqs.mtx);

        return i;
 no_vals:
        pthread_mutex_unlock(&dht.reqs.mtx);
        return 0;
 fail_val_data:
        freebufs(*vals, i);
 fail_vals:
        pthread_mutex_unlock(&dht.reqs.mtx);
        return -ENOMEM;
 timedout:
        pthread_mutex_unlock(&dht.reqs.mtx);
        return -ETIMEDOUT;
}

static struct bucket * iter_bucket(struct bucket * b,
                                   const uint8_t * id)
{
        uint8_t byte;
        uint8_t mask;

        assert(b != NULL);

        if (b->children[0] == NULL)
                return b;

        byte = id[(b->depth * DHT_BETA) / CHAR_BIT];

        mask = ((1L << DHT_BETA) - 1) & 0xFF;

        byte >>= (CHAR_BIT - DHT_BETA) -
                (((b->depth) * DHT_BETA) & (CHAR_BIT - 1));

        return iter_bucket(b->children[(byte & mask)], id);
}

static struct bucket * __dht_kv_get_bucket(const uint8_t * id)
{
        assert(dht.db.contacts.root != NULL);

        return iter_bucket(dht.db.contacts.root, id);
}

static void contact_list_add(struct list_head * l,
                             struct contact *   c)
{
        struct list_head * p;

        assert(l != NULL);
        assert(c != NULL);

        list_for_each(p, l) {
                struct contact * e = list_entry(p, struct contact, next);
                if (IS_CLOSER(e->id, c->id))
                        continue;
        }

        list_add_tail(&c->next, p);
}

static ssize_t dht_kv_contact_list(const uint8_t *    key,
                                   struct list_head * l,
                                   size_t             max)
{
        struct list_head * p;
        struct bucket *    b;
        struct timespec    t;
        size_t             i;
        size_t             len = 0;

        assert(l   != NULL);
        assert(key != NULL);
        assert(list_is_empty(l));

        clock_gettime(CLOCK_REALTIME_COARSE, &t);

        max = MIN(max, dht.k);

        pthread_rwlock_rdlock(&dht.db.lock);

        b = __dht_kv_get_bucket(key);
        if (b == NULL) {
                log_err(KEY_FMT " Failed to get bucket.", KEY_VAL(key));
                goto fail_bucket;
        }

        b->t_refr = t.tv_sec + dht.t_refresh;

        if (b->contacts.len == dht.k || b->parent == NULL) {
                list_for_each(p, &b->contacts.list) {
                        struct contact * c;
                        struct contact * d;
                        c = list_entry(p, struct contact, next);
                        if (c->addr == dht.addr)
                                continue;
                        d = contact_create(c->id, c->addr);
                        if (d == NULL)
                                continue;
                        contact_list_add(l, d);
                        if (++len == max)
                                break;
                }
        } else {
                struct bucket * d = b->parent;
                for (i = 0; i < (1L << DHT_BETA) && len < dht.k; ++i) {
                        list_for_each(p, &d->children[i]->contacts.list) {
                                struct contact * c;
                                struct contact * d;
                                c = list_entry(p, struct contact, next);
                                if (c->addr == dht.addr)
                                        continue;
                                d = contact_create(c->id, c->addr);
                                if (d == NULL)
                                        continue;
                                contact_list_add(l, d);
                                if (++len == max)
                                        break;
                        }
                }
        }

        pthread_rwlock_unlock(&dht.db.lock);

        return len;
 fail_bucket:
        pthread_rwlock_unlock(&dht.db.lock);
        return -1;
}

static void contact_list_destroy(struct list_head * l)
{
        struct list_head * p;
        struct list_head * h;

        assert(l != NULL);

        list_for_each_safe(p, h, l) {
                struct contact * c = list_entry(p, struct contact, next);
                list_del(&c->next);
                contact_destroy(c);
        }
}

static ssize_t dht_kv_get_contacts(const uint8_t *       key,
                                   dht_contact_msg_t *** msgs)
{
        struct list_head   cl;
        struct list_head * p;
        struct list_head * h;
        size_t             len;
        size_t             i = 0;

        assert(key != NULL);
        assert(msgs != NULL);

        list_head_init(&cl);

        len = dht_kv_contact_list(key, &cl, dht.k);
        if (len == 0) {
                *msgs = NULL;
                return 0;
        }

        *msgs = malloc(len * sizeof(**msgs));
        if (*msgs == NULL)
                goto fail_msgs;

        list_for_each_safe(p, h, &cl) {
                struct contact * c;
                (*msgs)[i] = malloc(sizeof(***msgs));
                if ((*msgs)[i] == NULL)
                        goto fail_contact;

                dht_contact_msg__init((*msgs)[i]);
                c = list_entry(p, struct contact, next);
                list_del(&c->next);
                (*msgs)[i]->id.data = c->id;
                (*msgs)[i]->id.len  = dht.id.len;
                (*msgs)[i++]->addr  = c->addr;
                free(c);
        }

        return i;
 fail_contact:
        while (i-- > 0)
                dht_contact_msg__free_unpacked((*msgs)[i], NULL);
        free(*msgs);
        *msgs = NULL;
 fail_msgs:
        contact_list_destroy(&cl);
        return -ENOMEM;
}

/* Build a refresh list. */
static void __dht_kv_bucket_refresh_list(struct bucket *    b,
                                         time_t             t,
                                         struct list_head * r)
{
        struct contact * c;
        struct contact * d;

        assert(b != NULL);

        if (t < b->t_refr)
                return;

        if (*b->children != NULL) {
                size_t i;
                for (i = 0; i < (1L << DHT_BETA); ++i)
                        __dht_kv_bucket_refresh_list(b->children[i], t, r);
        }

        if (b->contacts.len == 0)
                return;

        c = list_first_entry(&b->contacts.list, struct contact, next);
        if (t > c->t_seen + dht.t_refresh) {
                d = contact_create(c->id, c->addr);
                if (d != NULL)
                        list_add(&d->next, r);
        }
}

static struct bucket * bucket_create(void)
{
        struct bucket * b;
        struct timespec t;
        size_t          i;

        b = malloc(sizeof(*b));
        if (b == NULL)
                return NULL;

        list_head_init(&b->contacts.list);
        b->contacts.len = 0;

        list_head_init(&b->alts.list);
        b->alts.len = 0;

        clock_gettime(CLOCK_REALTIME_COARSE, &t);
        b->t_refr = t.tv_sec + dht.t_refresh;

        for (i = 0; i < (1L << DHT_BETA); ++i)
                b->children[i]  = NULL;

        b->parent = NULL;
        b->depth = 0;
        b->mask  = 0;

        return b;
}

static void bucket_destroy(struct bucket * b)
{
        struct list_head * p;
        struct list_head * h;
        size_t             i;

        assert(b != NULL);

        for (i = 0; i < (1L << DHT_BETA); ++i)
                if (b->children[i] != NULL)
                        bucket_destroy(b->children[i]);

        list_for_each_safe(p, h, &b->contacts.list) {
                struct contact * c = list_entry(p, struct contact, next);
                list_del(&c->next);
                contact_destroy(c);
                --b->contacts.len;
        }

        list_for_each_safe(p, h, &b->alts.list) {
                struct contact * c = list_entry(p, struct contact, next);
                list_del(&c->next);
                contact_destroy(c);
                --b->alts.len;
        }

        free(b);
}

static bool bucket_has_id(struct bucket * b,
                          const uint8_t * id)
{
        uint8_t mask;
        uint8_t byte;

        if (b->depth == 0)
                return true;

        byte = id[(b->depth * DHT_BETA) / CHAR_BIT];

        mask = ((1L << DHT_BETA) - 1) & 0xFF;

        byte >>= (CHAR_BIT - DHT_BETA) -
                (((b->depth - 1) * DHT_BETA) & (CHAR_BIT - 1));

        return ((byte & mask) == b->mask);
}

static int move_contacts(struct bucket * b,
                         struct bucket * c)
{
        struct list_head * p;
        struct list_head * h;
        struct contact *   d;

        assert(b != NULL);
        assert(c != NULL);

        list_for_each_safe(p, h, &b->contacts.list) {
                d = list_entry(p, struct contact, next);
                if (bucket_has_id(c, d->id)) {
                        list_del(&d->next);
                        --b->contacts.len;
                        list_add_tail(&d->next, &c->contacts.list);
                        ++c->contacts.len;
                }
        }

        return 0;
}

static int split_bucket(struct bucket * b)
{
        uint8_t mask = 0;
        size_t i;
        size_t b_len;

        assert(b);
        assert(b->alts.len == 0);
        assert(b->contacts.len != 0);
        assert(b->children[0] == NULL);

        b_len = b->contacts.len;

        for (i = 0; i < (1L << DHT_BETA); ++i) {
                b->children[i] = bucket_create();
                if (b->children[i] == NULL)
                        goto fail_child;

                b->children[i]->depth  = b->depth + 1;
                b->children[i]->mask   = mask;
                b->children[i]->parent = b;

                move_contacts(b, b->children[i]);

                mask++;
        }

        for (i = 0; i < (1L << DHT_BETA); ++i)
                if (b->children[i]->contacts.len == b_len)
                        split_bucket(b->children[i]);

        return 0;
 fail_child:
        while (i-- > 0)
                bucket_destroy(b->children[i]);
        return -1;
}

static int dht_kv_update_contacts(const uint8_t * id,
                                  uint64_t        addr)
{
        struct list_head * p;
        struct list_head * h;
        struct bucket *    b;
        struct contact *   c;

        assert(id != NULL);
        assert(addr != INVALID_ADDR);

        pthread_rwlock_wrlock(&dht.db.lock);

        b = __dht_kv_get_bucket(id);
        if (b == NULL) {
                log_err(PEER_FMT " Failed to get bucket.", PEER_VAL(id, addr));
                        goto fail_update;
        }

        c = contact_create(id, addr);
        if (c == NULL) {
                log_err(PEER_FMT " Failed to create contact.",
                        PEER_VAL(id, addr));
                goto fail_update;
        }

        list_for_each_safe(p, h, &b->contacts.list) {
                struct contact * d = list_entry(p, struct contact, next);
                if (d->addr == addr) {
                        list_del(&d->next);
                        contact_destroy(d);
                        --b->contacts.len;
                }
        }

        if (b->contacts.len == dht.k) {
                if (bucket_has_id(b, dht.id.data)) {
                        list_add_tail(&c->next, &b->contacts.list);
                        ++b->contacts.len;
                        if (split_bucket(b)) {
                                list_del(&c->next);
                                contact_destroy(c);
                                --b->contacts.len;
                        }
                } else if (b->alts.len == dht.k) {
                        struct contact * d;
                        d = list_first_entry(&b->alts.list,
                                struct contact, next);
                        list_del(&d->next);
                        contact_destroy(d);
                        list_add_tail(&c->next, &b->alts.list);
                        ++b->alts.len;
                } else {
                        list_add_tail(&c->next, &b->alts.list);
                        ++b->alts.len;
                }
        } else {
                list_add_tail(&c->next, &b->contacts.list);
                ++b->contacts.len;
        }

        pthread_rwlock_unlock(&dht.db.lock);

        return 0;
 fail_update:
        pthread_rwlock_unlock(&dht.db.lock);
        return -1;
}

static time_t gcd(time_t a,
                  time_t b)
{
        if (a == 0)
                return b;

        return gcd(b % a, a);
}

static dht_contact_msg_t * dht_kv_src_contact_msg(void)
{
        dht_contact_msg_t * src;

        src = malloc(sizeof(*src));
        if (src == NULL)
                goto fail_malloc;

        dht_contact_msg__init(src);

        src->id.data = dht_dup_key(dht.id.data);
        if (src->id.data == NULL)
                goto fail_id;

        src->id.len  = dht.id.len;
        src->addr    = dht.addr;

        return src;
 fail_id:
        dht_contact_msg__free_unpacked(src, NULL);
 fail_malloc:
        return NULL;
}

static dht_msg_t * dht_kv_find_req_msg(const uint8_t * key,
                                       enum dht_code   code)
{
        dht_msg_t * msg;

        assert(key != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        dht_msg__init(msg);
        msg->code = code;

        msg->src = dht_kv_src_contact_msg();
        if (msg->src == NULL)
                goto fail_msg;

        msg->find = malloc(sizeof(*msg->find));
        if (msg->find == NULL)
                goto fail_msg;

        dht_find_req_msg__init(msg->find);

        msg->find->key.data = dht_dup_key(key);
        if (msg->find->key.data == NULL)
                goto fail_msg;

        msg->find->key.len = dht.id.len;
        msg->find->cookie  = DHT_INVALID;

        return msg;

 fail_msg:
        dht_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

static dht_msg_t * dht_kv_find_node_req_msg(const uint8_t * key)
{
        return dht_kv_find_req_msg(key, DHT_FIND_NODE_REQ);
}

static dht_msg_t * dht_kv_find_value_req_msg(const uint8_t * key)
{
        return dht_kv_find_req_msg(key, DHT_FIND_VALUE_REQ);
}

static dht_msg_t * dht_kv_find_node_rsp_msg(uint8_t *             key,
                                            uint64_t              cookie,
                                            dht_contact_msg_t *** contacts,
                                            size_t                len)
{
        dht_msg_t * msg;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        dht_msg__init(msg);
        msg->code = DHT_FIND_NODE_RSP;

        msg->src = dht_kv_src_contact_msg();
        if (msg->src == NULL)
                goto fail_msg;

        msg->node = malloc(sizeof(*msg->node));
        if (msg->node == NULL)
                goto fail_msg;

        dht_find_node_rsp_msg__init(msg->node);

        msg->node->key.data = dht_dup_key(key);
        if (msg->node->key.data == NULL)
                goto fail_msg;

        msg->node->cookie     = cookie;
        msg->node->key.len    = dht.id.len;
        msg->node->n_contacts = len;
        if (len != 0) { /* Steal the ptr */
                msg->node->contacts = *contacts;
                *contacts = NULL;
        }

        return msg;

 fail_msg:
        dht_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

static dht_msg_t * dht_kv_find_value_rsp_msg(uint8_t *             key,
                                             uint64_t              cookie,
                                             dht_contact_msg_t *** contacts,
                                             size_t                n_contacts,
                                             buffer_t **           vals,
                                             size_t                n_vals)
{
        dht_msg_t * msg;

        msg = dht_kv_find_node_rsp_msg(key, cookie, contacts, n_contacts);
        if (msg == NULL)
                goto fail_node_rsp;

        msg->code = DHT_FIND_VALUE_RSP;

        msg->val = malloc(sizeof(*msg->val));
        if (msg->val == NULL)
                goto fail_msg;

        dht_find_value_rsp_msg__init(msg->val);

        msg->val->n_values = n_vals;
        if (n_vals != 0)  /* Steal the ptr */
                msg->val->values = (binary_data_t *) *vals;

        return msg;

 fail_msg:
        dht_msg__free_unpacked(msg, NULL);
 fail_node_rsp:
        return NULL;
}

static dht_msg_t * dht_kv_store_msg(const uint8_t * key,
                                    const buffer_t  val,
                                    time_t          exp)
{
        dht_msg_t * msg;

        assert(key != NULL);
        assert(val.data != NULL);
        assert(val.len > 0);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        dht_msg__init(msg);

        msg->code = DHT_STORE;

        msg->src = dht_kv_src_contact_msg();
        if (msg->src == NULL)
                goto fail_msg;

        msg->store = malloc(sizeof(*msg->store));
        if (msg->store == NULL)
                goto fail_msg;

        dht_store_msg__init(msg->store);

        msg->store->key.data = dht_dup_key(key);
        if (msg->store->key.data == NULL)
                goto fail_msg;

        msg->store->key.len = dht.id.len;
        msg->store->val.data = malloc(val.len);
        if (msg->store->val.data == NULL)
                goto fail_msg;

        memcpy(msg->store->val.data, val.data, val.len);

        msg->store->val.len = val.len;
        msg->store->exp = exp;

        return msg;

 fail_msg:
        dht_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

static ssize_t dht_kv_retrieve(const uint8_t * key,
                               buffer_t **     vals)
{
        struct dht_entry * e;
        struct list_head * p;
        size_t             n;
        size_t             i;

        assert(key  != NULL);

        pthread_rwlock_rdlock(&dht.db.lock);

        e = __dht_kv_find_entry(key);
        if (e == NULL)
                goto no_vals;

        n = MIN(DHT_MAX_VALS, e->vals.len + e->lvals.len);
        if (n == 0)
                goto no_vals;

        *vals = malloc(n * sizeof(**vals));
        if (*vals == NULL)
                goto fail_vals;

        memset(*vals, 0, n * sizeof(**vals));

        i = 0;

        list_for_each(p, &e->vals.list) {
                struct val_entry * v;
                if (i == n)
                        break; /* We have enough values */
                v = list_entry(p, struct val_entry, next);
                (*vals)[i].data = malloc(v->val.len);
                if ((*vals)[i].data == NULL)
                        goto fail_val_data;

                (*vals)[i].len = v->val.len;
                memcpy((*vals)[i++].data, v->val.data, v->val.len);
        }

        list_for_each(p, &e->lvals.list) {
                struct val_entry * v;
                if (i == n)
                        break; /* We have enough values */
                v = list_entry(p, struct val_entry, next);
                (*vals)[i].data = malloc(v->val.len);
                if ((*vals)[i].data == NULL)
                        goto fail_val_data;

                (*vals)[i].len = v->val.len;
                memcpy((*vals)[i++].data, v->val.data, v->val.len);
        }

        pthread_rwlock_unlock(&dht.db.lock);

        return (ssize_t) i;

 fail_val_data:
        pthread_rwlock_unlock(&dht.db.lock);
        freebufs(*vals, i);
        *vals = NULL;
        return -ENOMEM;
 fail_vals:
        pthread_rwlock_unlock(&dht.db.lock);
        return -ENOMEM;
 no_vals:
        pthread_rwlock_unlock(&dht.db.lock);
        *vals = NULL;
        return 0;
}

static void __cleanup_dht_msg(void * msg)
{
        dht_msg__free_unpacked((dht_msg_t *) msg, NULL);
}

#ifdef DEBUG_PROTO_DHT
static void dht_kv_debug_msg(dht_msg_t * msg)
{
        struct tm *   tm;
        char          tmstr[RIB_TM_STRLEN];
        time_t        stamp;
        size_t        i;

        if (msg == NULL)
                return;

        pthread_cleanup_push(__cleanup_dht_msg, msg);

        switch (msg->code) {
        case DHT_STORE:
                log_proto("  key: " HASH_FMT64 " [%zu bytes]",
                          HASH_VAL64(msg->store->key.data),
                          msg->store->key.len);
                log_proto("  val: " HASH_FMT64 " [%zu bytes]",
                          HASH_VAL64(msg->store->val.data),
                          msg->store->val.len);
                stamp = msg->store->exp;
                tm = gmtime(&stamp);
                strftime(tmstr, sizeof(tmstr), RIB_TM_FORMAT, tm);
                log_proto("  exp: %s.", tmstr);
                break;
        case DHT_FIND_NODE_REQ:
                /* FALLTHRU */
        case DHT_FIND_VALUE_REQ:
                log_proto("  cookie: " HASH_FMT64,
                          HASH_VAL64(&msg->find->cookie));
                log_proto("  key:    " HASH_FMT64 " [%zu bytes]",
                          HASH_VAL64(msg->find->key.data),
                          msg->find->key.len);
                break;
        case DHT_FIND_VALUE_RSP:
                log_proto("  cookie: " HASH_FMT64,
                          HASH_VAL64(&msg->node->cookie));
                log_proto("  key:    " HASH_FMT64 " [%zu bytes]",
                          HASH_VAL64(msg->node->key.data),
                          msg->node->key.len);
                log_proto("  values: [%zd]", msg->val->n_values);
                for (i = 0; i < msg->val->n_values; i++)
                        log_proto("    " HASH_FMT64 " [%zu bytes]",
                                  HASH_VAL64(msg->val->values[i].data),
                                  msg->val->values[i].len);
                log_proto("  contacts: [%zd]", msg->node->n_contacts);
                for (i = 0; i < msg->node->n_contacts; i++) {
                        dht_contact_msg_t * c = msg->node->contacts[i];
                        log_proto("    " PEER_FMT,
                                  PEER_VAL(c->id.data, c->addr));
                }
                break;
        case DHT_FIND_NODE_RSP:
                log_proto("  cookie: " HASH_FMT64,
                        HASH_VAL64(&msg->node->cookie));
                log_proto("  key:    " HASH_FMT64 " [%zu bytes]",
                          HASH_VAL64(msg->node->key.data), msg->node->key.len);
                log_proto("  contacts: [%zd]", msg->node->n_contacts);
                for (i = 0; i < msg->node->n_contacts; i++) {
                        dht_contact_msg_t * c = msg->node->contacts[i];
                        log_proto("    " PEER_FMT,
                                  PEER_VAL(c->id.data, c->addr));
                }

                break;
        default:
                break;
        }

        pthread_cleanup_pop(false);
}

static void dht_kv_debug_msg_snd(dht_msg_t * msg,
                                 uint8_t *   id,
                                 uint64_t    addr)
{
        if (msg == NULL)
                return;

        log_proto(TX_HDR_FMT ".", TX_HDR_VAL(msg, id, addr));

        dht_kv_debug_msg(msg);
}

static void dht_kv_debug_msg_rcv(dht_msg_t * msg)
{
        if (msg == NULL)
                return;

        log_proto(RX_HDR_FMT ".", RX_HDR_VAL(msg));

        dht_kv_debug_msg(msg);
}
#endif

#ifndef __DHT_TEST__
static int dht_send_msg(dht_msg_t * msg,
                        uint64_t    addr)
{
        size_t               len;
        struct shm_du_buff * sdb;

        if (msg == NULL)
                return 0;

        assert(addr != INVALID_ADDR && addr != dht.addr);

        len = dht_msg__get_packed_size(msg);
        if (len == 0) {
                log_warn("%s failed to pack.", DHT_CODE(msg));
                goto fail_msg;
        }

        if (ipcp_sdb_reserve(&sdb, len)) {
                log_warn("%s failed to get sdb.", DHT_CODE(msg));
                goto fail_msg;
        }

        dht_msg__pack(msg, shm_du_buff_head(sdb));

        if (dt_write_packet(addr, QOS_CUBE_BE, dht.eid, sdb) < 0) {
                log_warn("%s write failed", DHT_CODE(msg));
                goto fail_send;
        }

        return 0;
 fail_send:
        ipcp_sdb_release(sdb);
 fail_msg:
        return -1;
}
#else /* funtion for testing  */
static int dht_send_msg(dht_msg_t * msg,
                        uint64_t    addr)
{
        buffer_t buf;

        assert(msg != NULL);
        assert(addr != INVALID_ADDR && addr != dht.addr);

        buf.len = dht_msg__get_packed_size(msg);
        if (buf.len == 0) {
                log_warn("%s failed to pack.", DHT_CODE(msg));
                goto fail_msg;
        }

        buf.data = malloc(buf.len);
        if (buf.data == NULL) {
                log_warn("%s failed to malloc buf.", DHT_CODE(msg));
                goto fail_msg;
        }

        dht_msg__pack(msg, buf.data);

        if (sink_send_msg(&buf, addr) < 0) {
                log_warn("%s write failed", DHT_CODE(msg));
                goto fail_send;
        }

        return 0;
 fail_send:
        freebuf(buf);
 fail_msg:
        return -1;
}
#endif /* __DHT_TEST__ */

static void __cleanup_peer_list(void * pl)
{
        struct list_head * p;
        struct list_head * h;

        assert(pl != NULL);

        list_for_each_safe(p, h, (struct list_head *) pl) {
                struct peer_entry * e = list_entry(p, struct peer_entry, next);
                list_del(&e->next);
                free(e->id);
                free(e);
        }
}


static int dht_kv_send_msgs(dht_msg_t *        msg,
                            struct list_head * pl)
{
        struct list_head * p;
        struct list_head * h;

        pthread_cleanup_push(__cleanup_dht_msg, msg);
        pthread_cleanup_push(__cleanup_peer_list, pl);

        list_for_each_safe(p, h, pl) {
                struct peer_entry * e = list_entry(p, struct peer_entry, next);
                if (IS_REQUEST(msg->code)) {
                        msg->find->cookie = e->cookie;
                        assert(msg->find->cookie != DHT_INVALID);
                }
                if (dht_send_msg(msg, e->addr) < 0)
                        continue;

#ifdef DEBUG_PROTO_DHT
                dht_kv_debug_msg_snd(msg, e->id, e->addr);
#endif
                list_del(&e->next);
                free(e->id);
                free(e);
        }

        pthread_cleanup_pop(false);
        pthread_cleanup_pop(false);

        return list_is_empty(pl) ? 0 : -1;
}

static int dht_kv_get_peer_list_for_msg(dht_msg_t *        msg,
                                        struct list_head * pl)
{
        struct list_head   cl;  /* contact list       */
        uint8_t *          key; /* key in the request */
        size_t             max;

        assert(msg != NULL);

        assert(list_is_empty(pl));

        max = msg->code == DHT_STORE ? dht.k : dht.alpha;

        switch (msg->code) {
        case DHT_FIND_NODE_REQ:
                /* FALLTHRU */
        case DHT_FIND_VALUE_REQ:
                key = msg->find->key.data;
                break;
        case DHT_STORE:
                key = msg->store->key.data;
                break;
        default:
                log_err("Invalid DHT msg code (%d).", msg->code);
                return -1;
        }

        list_head_init(&cl);

        if (dht_kv_contact_list(key, &cl, max) < 0) {
                log_err(KEY_FMT " Failed to get contact list.", KEY_VAL(key));
                goto fail_contacts;
        }

        if (list_is_empty(&cl)) {
                log_warn(KEY_FMT " No available contacts.", KEY_VAL(key));
                goto fail_contacts;
        }

        if (dht_kv_create_peer_list(&cl, pl, msg->code) < 0) {
                log_warn(KEY_FMT " Failed to get peer list.", KEY_VAL(key));
                goto fail_peers;
        }

        contact_list_destroy(&cl);
        return 0;
 fail_peers:
        contact_list_destroy(&cl);
 fail_contacts:
        return -1;
}

static int dht_kv_store_remote(const uint8_t * key,
                               const buffer_t  val,
                               time_t          exp)
{
        dht_msg_t *      msg;
        struct timespec  now;
        struct list_head pl;

        assert(key != NULL);
        assert(val.data != NULL);
        assert(val.len > 0);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        msg = dht_kv_store_msg(key, val, exp);
        if (msg == NULL) {
                log_err(KV_FMT " Failed to create %s.",
                        KV_VAL(key, val), dht_code_str[DHT_STORE]);
                goto fail_msg;
        }

        list_head_init(&pl);

        if (dht_kv_get_peer_list_for_msg(msg, &pl) < 0) {
                log_dbg(KV_FMT " Failed to get peer list.", KV_VAL(key, val));
                goto fail_peer_list;
        }

        if (dht_kv_send_msgs(msg, &pl) < 0) {
                log_warn(KV_FMT " Failed to send any %s msg.",
                         KV_VAL(key, val), DHT_CODE(msg));
                goto fail_msgs;
        }

        dht_msg__free_unpacked(msg, NULL);

        return 0;
 fail_msgs:
        peer_list_destroy(&pl);
 fail_peer_list:
        dht_msg__free_unpacked(msg, NULL);
 fail_msg:
        return -1;
}

/* recursive lookup, start with pl NULL */
static int dht_kv_query_contacts(const uint8_t *    key,
                                 struct list_head * pl)
{
        struct list_head p;

        dht_msg_t * msg;

        assert(key != NULL);

        msg = dht_kv_find_node_req_msg(key);
        if (msg == NULL) {
                log_err(KEY_FMT " Failed to create %s msg.",
                        KEY_VAL(key), dht_code_str[DHT_FIND_NODE_REQ]);
                goto fail_msg;
        }

        if (pl == NULL) {
                list_head_init(&p);
                pl = &p;
        }

        if (list_is_empty(pl) && dht_kv_get_peer_list_for_msg(msg, pl) < 0) {
                log_warn(KEY_FMT " Failed to get peer list.", KEY_VAL(key));
                goto fail_peer_list;
        }

        if (dht_kv_update_req(key, pl) < 0) {
                log_warn(KEY_FMT " Failed to update req.", KEY_VAL(key));
                goto fail_update;
        }

        if (dht_kv_send_msgs(msg, pl)) {
                log_warn(KEY_FMT " Failed to send any %s msg.",
                         KEY_VAL(key), DHT_CODE(msg));
                goto fail_update;
        }

        dht_msg__free_unpacked(msg, NULL);

        return 0;
 fail_update:
        peer_list_destroy(pl);
 fail_peer_list:
        dht_msg__free_unpacked(msg, NULL);
 fail_msg:
        return -1;
}

/* recursive lookup, start with pl NULL */
static ssize_t dht_kv_query_remote(const uint8_t *    key,
                                   buffer_t **        vals,
                                   struct list_head * pl)
{
        struct list_head p;
        dht_msg_t *      msg;

        assert(key != NULL);

        msg = dht_kv_find_value_req_msg(key);
        if (msg == NULL) {
                log_err(KEY_FMT " Failed to create value req.", KEY_VAL(key));
                goto fail_msg;
        }

        if (pl == NULL) {
                list_head_init(&p);
                pl = &p;
        }

        if (list_is_empty(pl) && dht_kv_get_peer_list_for_msg(msg, pl) < 0) {
                log_warn(KEY_FMT " Failed to get peer list.", KEY_VAL(key));
                goto fail_peer_list;
        }

        if (dht_kv_update_req(key, pl) < 0) {
                log_err(KEY_FMT " Failed to update request.", KEY_VAL(key));
                goto fail_update;
        }

        if (dht_kv_send_msgs(msg, pl)) {
                log_warn(KEY_FMT " Failed to send %s msg.",
                         KEY_VAL(key), DHT_CODE(msg));
                goto fail_update;
        }

        dht_msg__free_unpacked(msg, NULL);

        if (vals == NULL) /* recursive lookup, already waiting */
                return 0;

        return dht_kv_wait_req(key, vals);
 fail_update:
        peer_list_destroy(pl);
 fail_peer_list:
        dht_msg__free_unpacked(msg, NULL);
 fail_msg:
        return -1;
}

static void __add_dht_kv_entry(struct dht_entry * e)
{
        struct list_head * p;

        assert(e != NULL);

        list_for_each(p, &dht.db.kv.list) {
                struct dht_entry * d = list_entry(p, struct dht_entry, next);
                if (IS_CLOSER(d->key, e->key))
                        continue;
                break;
        }

        list_add_tail(&e->next, p);
        ++dht.db.kv.len;
}

/* incoming store message */
static int dht_kv_store(const uint8_t * key,
                        const buffer_t  val,
                        time_t          exp)
{
        struct dht_entry * e;
        bool               new = false;

        assert(key != NULL);
        assert(val.data != NULL);
        assert(val.len > 0);

        pthread_rwlock_wrlock(&dht.db.lock);

        e = __dht_kv_find_entry(key);
        if (e == NULL) {
                log_dbg(KV_FMT " Adding entry (store).", KV_VAL(key, val));
                e = dht_entry_create(key);
                if (e == NULL)
                        goto fail;

                new = true;

                __add_dht_kv_entry(e);
        }

        if (dht_entry_update_val(e, val, exp) < 0)
                goto fail_add;

        pthread_rwlock_unlock(&dht.db.lock);

        return 0;
 fail_add:
        if (new) {
                list_del(&e->next);
                dht_entry_destroy(e);
                --dht.db.kv.len;
        }
 fail:
        pthread_rwlock_unlock(&dht.db.lock);
        return -1;
}

static int dht_kv_publish(const uint8_t * key,
                          const buffer_t  val)
{
        struct dht_entry * e;
        struct timespec    now;
        bool               new = false;

        assert(key != NULL);
        assert(val.data != NULL);
        assert(val.len > 0);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_rwlock_wrlock(&dht.db.lock);

        e = __dht_kv_find_entry(key);
        if (e == NULL) {
                log_dbg(KV_FMT " Adding entry (publish).", KV_VAL(key, val));
                e = dht_entry_create(key);
                if (e == NULL)
                        goto fail;

                __add_dht_kv_entry(e);
                new = true;
        }

        if (dht_entry_update_lval(e, val) < 0)
                goto fail_add;

        pthread_rwlock_unlock(&dht.db.lock);

        dht_kv_store_remote(key, val, now.tv_sec + dht.t_expire);

        return 0;
 fail_add:
        if (new) {
                list_del(&e->next);
                dht_entry_destroy(e);
                --dht.db.kv.len;
        }
 fail:
        pthread_rwlock_unlock(&dht.db.lock);
        return -1;
}

static int dht_kv_unpublish(const uint8_t * key,
                            const buffer_t  val)
{
        struct dht_entry * e;
        int                rc;

        assert(key != NULL);

        pthread_rwlock_wrlock(&dht.db.lock);

        e = __dht_kv_find_entry(key);
        if (e == NULL)
                goto no_entry;

        rc = dht_entry_remove_lval(e, val);

        pthread_rwlock_unlock(&dht.db.lock);

        return rc;
 no_entry:
        pthread_rwlock_unlock(&dht.db.lock);
        return -ENOENT;

}

/* message validation */
static int dht_kv_validate_store_msg(const dht_store_msg_t * store)
{
        if (store == NULL) {
                log_warn("Store in msg is NULL.");
                return -EINVAL;
        }

        if (store->key.data == NULL || store->key.len == 0) {
                log_warn("Invalid key in DHT store msg.");
                return -EINVAL;
        }

        if (store->key.len != dht.id.len) {
                log_warn("Invalid key length in DHT store msg.");
                return -EINVAL;
        }

        if (store->val.data == NULL || store->val.len == 0) {
                log_warn("Invalid value in DHT store msg.");
                return -EINVAL;
        }

        return 0;
}

static int validate_find_req_msg(const dht_find_req_msg_t * req)
{
        if (req == NULL) {
                log_warn("Request in msg is NULL.");
                return -EINVAL;
        }

        if (req->key.data == NULL || req->key.len == 0) {
                log_warn("Find request without key.");
                return -EINVAL;
        }

        if (req->key.len != dht.id.len) {
                log_warn("Invalid key length in request msg.");
                return -EINVAL;
        }

        return 0;
}

static int validate_node_rsp_msg(const dht_find_node_rsp_msg_t * rsp)
{
        if (rsp == NULL) {
                log_warn("Node rsp in msg is NULL.");
                return -EINVAL;
        }

        if (rsp->key.data == NULL) {
                log_warn("Invalid key in DHT response msg.");
                return -EINVAL;
        }

        if (rsp->key.len != dht.id.len) {
                log_warn("Invalid key length in DHT response msg.");
                return -EINVAL;
        }

        if (!dht_kv_has_req(rsp->key.data, rsp->cookie)) {
                log_warn(KEY_FMT " No request " CK_FMT  ".",
                         KEY_VAL(rsp->key.data), CK_VAL(rsp->cookie));

                return -EINVAL;
        }

        return 0;
}

static int validate_value_rsp_msg(const dht_find_value_rsp_msg_t * rsp)
{
        if (rsp == NULL) {
                log_warn("Invalid DHT find value response msg.");
                return -EINVAL;
        }

        if (rsp->values == NULL && rsp->n_values > 0) {
                log_dbg("No values in DHT response msg.");
                return 0;
        }

        if (rsp->n_values == 0 && rsp->values != NULL) {
                log_dbg("DHT response did not set values NULL.");
                return 0;
        }

        return 0;
}

static int dht_kv_validate_msg(dht_msg_t * msg)
{

        assert(msg != NULL);

        if (msg->src->id.len != dht.id.len) {
                log_warn("%s Invalid source contact ID.", DHT_CODE(msg));
                return -EINVAL;
        }

        if (msg->src->addr == INVALID_ADDR) {
                log_warn("%s Invalid source address.", DHT_CODE(msg));
                return -EINVAL;
        }

        switch (msg->code) {
        case DHT_FIND_VALUE_REQ:
                /* FALLTHRU */
        case DHT_FIND_NODE_REQ:
                if (validate_find_req_msg(msg->find) < 0)
                        return -EINVAL;
                break;
        case DHT_FIND_VALUE_RSP:
                if (validate_value_rsp_msg(msg->val) < 0)
                        return -EINVAL;
                /* FALLTHRU */
        case DHT_FIND_NODE_RSP:
                if (validate_node_rsp_msg(msg->node) < 0)
                        return -EINVAL;
                break;
        case DHT_STORE:
                if (dht_kv_validate_store_msg(msg->store) < 0)
                        return -EINVAL;
                break;
        default:
                log_warn("Invalid DHT msg code (%d).", msg->code);
                return -ENOENT;
        }

        return 0;
}

static void do_dht_kv_store(const dht_store_msg_t * store)
{
        struct tm * tm;
        char        tmstr[RIB_TM_STRLEN];
        buffer_t    val;
        uint8_t *   key;
        time_t      exp;

        assert(store != NULL);

        val.data = store->val.data;
        val.len  = store->val.len;
        key      = store->key.data;
        exp      = store->exp;

        if (dht_kv_store(store->key.data, val, store->exp) < 0) {
                log_err(KV_FMT " Failed to store.", KV_VAL(key, val));
                return;
        }

        tm = gmtime(&exp);
        strftime(tmstr, sizeof(tmstr), RIB_TM_FORMAT, tm);
        log_dbg(KV_FMT " Stored value until %s.", KV_VAL(key, val), tmstr);
}

static dht_msg_t * do_dht_kv_find_node_req(const dht_find_req_msg_t * req)
{
        dht_contact_msg_t ** contacts;
        dht_msg_t *          rsp;
        uint8_t *            key;
        uint64_t             cookie;
        ssize_t              len;

        assert(req  != NULL);

        key    = req->key.data;
        cookie = req->cookie;

        len = dht_kv_get_contacts(key, &contacts);
        if (len < 0) {
                log_warn(KEY_FMT " Failed to get contacts.", KEY_VAL(key));
                goto fail_contacts;
        }

        rsp = dht_kv_find_node_rsp_msg(key, cookie, &contacts, len);
        if (rsp == NULL) {
                log_err(KEY_FMT " Failed to create %s.", KEY_VAL(key),
                        dht_code_str[DHT_FIND_NODE_RSP]);
                goto fail_msg;
        }

        assert(rsp->code == DHT_FIND_NODE_RSP);

        log_info(KEY_FMT " Responding with %zd contacts", KEY_VAL(key), len);

        return rsp;
 fail_msg:
        while (len-- > 0)
                dht_contact_msg__free_unpacked(contacts[len], NULL);
        free(contacts);
 fail_contacts:
        return NULL;
}

static void dht_kv_process_node_rsp(dht_contact_msg_t ** contacts,
                                    size_t               len,
                                    struct list_head *   pl,
                                    enum dht_code        code)
{
        struct timespec now;
        size_t          i;

        assert(contacts != NULL);
        assert(len > 0);
        assert(pl != NULL);
        assert(list_is_empty(pl));

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        for (i = 0; i < len; i++) {
                dht_contact_msg_t * c = contacts[i];
                struct peer_entry * e;
                if (c->addr == dht.addr)
                        continue;

                if (dht_kv_update_contacts(c->id.data, c->addr) < 0)
                        log_warn(PEER_FMT " Failed to update contacts.",
                                 PEER_VAL(c->id.data, c->addr));

                e = malloc(sizeof(*e));
                if (e == NULL) {
                        log_err(PEER_FMT " Failed to malloc entry.",
                                PEER_VAL(c->id.data, c->addr));
                        continue;
                }

                e->id = dht_dup_key(c->id.data);
                if (e->id == NULL) {
                        log_warn(PEER_FMT " Failed to duplicate id.",
                                 PEER_VAL(c->id.data, c->addr));
                        free(e);
                        continue;
                }

                e->cookie = generate_cookie();
                e->code   = code;
                e->addr   = c->addr;
                e->t_sent = now.tv_sec;

                list_add_tail(&e->next, pl);
        }
}

static dht_msg_t * do_dht_kv_find_value_req(const dht_find_req_msg_t * req)
{
        dht_contact_msg_t ** contacts;
        ssize_t              n_contacts;
        buffer_t *           vals;
        ssize_t              n_vals;
        dht_msg_t *          rsp;
        uint8_t *            key;
        uint64_t             cookie;

        assert(req != NULL);

        key    = req->key.data;
        cookie = req->cookie;

        n_contacts = dht_kv_get_contacts(key, &contacts);
        if (n_contacts < 0) {
                log_warn(KEY_FMT " Failed to get contacts.", KEY_VAL(key));
                goto fail_contacts;
        }

        assert(n_contacts > 0 || contacts == NULL);

        n_vals = dht_kv_retrieve(key, &vals);
        if (n_vals < 0) {
                log_dbg(KEY_FMT " Failed to get values.", KEY_VAL(key));
                goto fail_vals;
        }

        if (n_vals == 0)
                log_dbg(KEY_FMT " No values found.", KEY_VAL(key));

        rsp = dht_kv_find_value_rsp_msg(key, cookie, &contacts, n_contacts,
                                        &vals, n_vals);
        if (rsp == NULL) {
                log_err(KEY_FMT " Failed to create %s msg.",
                        KEY_VAL(key), dht_code_str[DHT_FIND_VALUE_RSP]);
                goto fail_msg;
        }

        log_info(KEY_FMT " Responding with %zd contacts, %zd values.",
                 KEY_VAL(req->key.data), n_contacts, n_vals);

        return rsp;

 fail_msg:
        freebufs(vals, n_vals);
 fail_vals:
        while (n_contacts-- > 0)
                dht_contact_msg__free_unpacked(contacts[n_contacts], NULL);
        free(contacts);
 fail_contacts:
        return NULL;
}

static void do_dht_kv_find_node_rsp(const dht_find_node_rsp_msg_t * rsp)
{
        struct list_head pl;

        assert(rsp != NULL);

        list_head_init(&pl);

        dht_kv_process_node_rsp(rsp->contacts, rsp->n_contacts, &pl,
                                DHT_FIND_NODE_REQ);

        if (list_is_empty(&pl))
                goto no_contacts;

        if (dht_kv_update_req(rsp->key.data, &pl) < 0) {
                log_err(KEY_FMT " Failed to update request.",
                        KEY_VAL(rsp->key.data));
                goto fail_update;
        }

        dht_kv_query_contacts(rsp->key.data, &pl);

        return;

 fail_update:
        peer_list_destroy(&pl);
 no_contacts:
        return;
}

static void do_dht_kv_find_value_rsp(const dht_find_node_rsp_msg_t  * node,
                                     const dht_find_value_rsp_msg_t * val)
{
        struct list_head pl;
        uint8_t *        key;

        assert(node != NULL);
        assert(val != NULL);

        list_head_init(&pl);

        key = node->key.data;

        dht_kv_process_node_rsp(node->contacts, node->n_contacts, &pl,
                                DHT_FIND_VALUE_REQ);

        if (val->n_values > 0) {
                log_dbg(KEY_FMT " %zd new values received.",
                        KEY_VAL(key), val->n_values);
                dht_kv_respond_req(key, val->values, val->n_values);
                peer_list_destroy(&pl);
                return; /* done! */
        }

        if (list_is_empty(&pl))
                goto no_contacts;

        if (dht_kv_update_req(key, &pl) < 0) {
                log_err(KEY_FMT " Failed to update request.", KEY_VAL(key));
                goto fail_update;
        }

        dht_kv_query_remote(key, NULL, &pl);

        return;
 fail_update:
        peer_list_destroy(&pl);
 no_contacts:
        return;
}

static dht_msg_t * dht_wait_for_dht_msg(void)
{
        dht_msg_t *  msg;
        struct cmd * cmd;

        pthread_mutex_lock(&dht.cmds.mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, &dht.cmds.mtx);

        while (list_is_empty(&dht.cmds.list))
                pthread_cond_wait(&dht.cmds.cond, &dht.cmds.mtx);

        cmd = list_last_entry(&dht.cmds.list, struct cmd, next);
        list_del(&cmd->next);

        pthread_cleanup_pop(true);

        msg = dht_msg__unpack(NULL, cmd->cbuf.len, cmd->cbuf.data);
        if (msg == NULL)
                log_warn("Failed to unpack DHT msg.");

        freebuf(cmd->cbuf);
        free(cmd);

        return msg;
}

static void do_dht_msg(dht_msg_t * msg)
{
        dht_msg_t * rsp = NULL;
        uint8_t *   id;
        uint64_t    addr;

#ifdef DEBUG_PROTO_DHT
        dht_kv_debug_msg_rcv(msg);
#endif
        if (dht_kv_validate_msg(msg) == -EINVAL) {
                log_warn("%s Validation failed.", DHT_CODE(msg));
                dht_msg__free_unpacked(msg, NULL);
                return;
        }

        id =   msg->src->id.data;
        addr = msg->src->addr;

        if (dht_kv_update_contacts(id, addr) < 0)
                log_warn(PEER_FMT " Failed to update contact from msg src.",
                         PEER_VAL(id, addr));

        pthread_cleanup_push(__cleanup_dht_msg, msg);

        switch(msg->code) {
        case DHT_FIND_VALUE_REQ:
                rsp = do_dht_kv_find_value_req(msg->find);
                break;
        case DHT_FIND_NODE_REQ:
                rsp = do_dht_kv_find_node_req(msg->find);
                break;
        case DHT_STORE:
                do_dht_kv_store(msg->store);
                break;
        case DHT_FIND_NODE_RSP:
                do_dht_kv_find_node_rsp(msg->node);
                break;
        case DHT_FIND_VALUE_RSP:
                do_dht_kv_find_value_rsp(msg->node, msg->val);
                break;
        default:
                assert(false); /* already validated */
        }

        pthread_cleanup_pop(true);

        if (rsp == NULL)
                return;

        pthread_cleanup_push(__cleanup_dht_msg, rsp);

        dht_send_msg(rsp, addr);

        pthread_cleanup_pop(true); /* free rsp */
}

static void * dht_handle_packet(void * o)
{
        (void) o;

        while (true) {
                dht_msg_t * msg;

                msg = dht_wait_for_dht_msg();
                if (msg == NULL)
                        continue;

                tpm_begin_work(dht.tpm);

                do_dht_msg(msg);

                tpm_end_work(dht.tpm);
        }

        return (void *) 0;
}
#ifndef __DHT_TEST__
static void dht_post_packet(void *               comp,
                            struct shm_du_buff * sdb)
{
        struct cmd * cmd;

        (void) comp;

        cmd = malloc(sizeof(*cmd));
        if (cmd == NULL) {
                log_err("Command malloc failed.");
                goto fail_cmd;
        }

        cmd->cbuf.data = malloc(shm_du_buff_len(sdb));
        if (cmd->cbuf.data == NULL) {
                log_err("Command buffer malloc failed.");
                goto fail_buf;
        }

        cmd->cbuf.len = shm_du_buff_len(sdb);

        memcpy(cmd->cbuf.data, shm_du_buff_head(sdb), cmd->cbuf.len);

        ipcp_sdb_release(sdb);

        pthread_mutex_lock(&dht.cmds.mtx);

        list_add(&cmd->next, &dht.cmds.list);

        pthread_cond_signal(&dht.cmds.cond);

        pthread_mutex_unlock(&dht.cmds.mtx);

        return;

 fail_buf:
        free(cmd);
 fail_cmd:
        ipcp_sdb_release(sdb);
        return;
}
#endif

int dht_reg(const uint8_t * key)
{
        buffer_t val;

        if (addr_to_buf(dht.addr, &val) < 0) {
                log_err("Failed to convert address to buffer.");
                goto fail_a2b;
        }

        if (dht_kv_publish(key, val)) {
                log_err(KV_FMT " Failed to publish.", KV_VAL(key, val));
                goto fail_publish;
        }

        freebuf(val);

        return 0;
 fail_publish:
        freebuf(val);
 fail_a2b:
        return -1;
}

int dht_unreg(const uint8_t * key)
{
        buffer_t val;

        if (addr_to_buf(dht.addr, &val) < 0) {
                log_err("Failed to convert address to buffer.");
                goto fail_a2b;
        }

        if (dht_kv_unpublish(key, val)) {
                log_err(KV_FMT " Failed to unpublish.", KV_VAL(key, val));
                goto fail_unpublish;
        }

        freebuf(val);

        return 0;
 fail_unpublish:
        freebuf(val);
 fail_a2b:
        return -ENOMEM;
}

uint64_t dht_query(const uint8_t * key)
{
        buffer_t *       vals;
        ssize_t          n;
        uint64_t         addr;

        n = dht_kv_retrieve(key, &vals);
        if (n < 0) {
                log_err(KEY_FMT " Failed to query db.", KEY_VAL(key));
                goto fail_vals;
        }

        if (n == 0) {
                log_dbg(KEY_FMT " No local values.", KEY_VAL(key));
                n = dht_kv_query_remote(key, &vals, NULL);
                if (n < 0) {
                        log_warn(KEY_FMT " Failed to query DHT.", KEY_VAL(key));
                        goto fail_vals;
                }
                if (n == 0) {
                        log_dbg(KEY_FMT " No values.", KEY_VAL(key));
                        goto no_vals;
                }
        }

        if (buf_to_addr(vals[0], &addr) < 0) {
                log_err(VAL_FMT " Failed addr conversion.", VAL_VAL(vals[0]));
                goto fail_b2a;
        }

        if (n > 1 && addr == INVALID_ADDR && buf_to_addr(vals[1], &addr) < 0) {
                log_err(VAL_FMT " Failed addr conversion.", VAL_VAL(vals[1]));
                goto fail_b2a;
        }

        freebufs(vals, n);

        return addr;
 fail_b2a:
        freebufs(vals, n);
        return INVALID_ADDR;
 no_vals:
        free(vals);
 fail_vals:
        return INVALID_ADDR;
}

static int emergency_peer(struct list_head * pl)
{
        struct peer_entry * e;
        struct timespec     now;

        assert(pl != NULL);
        assert(list_is_empty(pl));

        if (dht.peer == INVALID_ADDR)
                return -1;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        e = malloc(sizeof(*e));
        if (e == NULL) {
                log_err("Failed to malloc emergency peer entry.");
                goto fail_malloc;
        }

        e->id = dht_dup_key(dht.id.data);
        if (e->id == NULL) {
                log_err("Failed to duplicate DHT ID for emergency peer.");
                goto fail_id;
        }

        e->addr   = dht.peer;
        e->cookie = dht.magic;
        e->code   = DHT_FIND_NODE_REQ;
        e->t_sent = now.tv_sec;

        list_add_tail(&e->next, pl);

        return 0;
 fail_id:
        free(e);
 fail_malloc:
        return -ENOMEM;
}

static int dht_kv_seed_bootstrap_peer(void)
{
        struct list_head pl;

        list_head_init(&pl);

        if (dht.peer == INVALID_ADDR) {
                log_dbg("No-one to contact.");
                return 0;
        }

        if (emergency_peer(&pl) < 0) {
                log_err("Could not create emergency peer.");
                goto fail_peer;
        }

        log_dbg("Pinging emergency peer " ADDR_FMT32 ".",
                ADDR_VAL32(&dht.peer));

        if (dht_kv_query_contacts(dht.id.data, &pl) < 0) {
                log_warn("Failed to bootstrap peer.");
                goto fail_query;
        }

        peer_list_destroy(&pl);

        return 0;
 fail_query:
        peer_list_destroy(&pl);
 fail_peer:
        return -EAGAIN;
}

static void dht_kv_check_contacts(void)
{
        struct list_head cl;
        struct list_head pl;

        list_head_init(&cl);

        dht_kv_contact_list(dht.id.data, &cl, dht.k);

        if (!list_is_empty(&cl))
                goto success;

        contact_list_destroy(&cl);

        list_head_init(&pl);

        if (dht.peer == INVALID_ADDR) {
                log_dbg("No-one to contact.");
                return;
        }

        if (emergency_peer(&pl) < 0) {
                log_err("Could not create emergency peer.");
                goto fail_peer;
        }

        log_dbg("No contacts found, using emergency peer " ADDR_FMT32 ".",
                ADDR_VAL32(&dht.peer));

        dht_kv_query_contacts(dht.id.data, &pl);

        peer_list_destroy(&pl);

        return;
 success:
        contact_list_destroy(&cl);
        return;
 fail_peer:
        return;
}

static void dht_kv_remove_expired_reqs(void)
{
        struct list_head * p;
        struct list_head * h;
        struct timespec    now;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        pthread_mutex_lock(&dht.reqs.mtx);

        list_for_each_safe(p, h, &dht.reqs.list) {
                struct dht_req * e;
                e = list_entry(p, struct dht_req, next);
                if (IS_EXPIRED(e, &now)) {
                        log_dbg(KEY_FMT " Removing expired request.",
                                KEY_VAL(e->key));
                        list_del(&e->next);
                        dht_req_destroy(e);
                        --dht.reqs.len;
                }
        }

        pthread_mutex_unlock(&dht.reqs.mtx);
}

static void value_list_destroy(struct list_head * vl)
{
        struct list_head * p;
        struct list_head * h;

        assert(vl != NULL);

        list_for_each_safe(p, h, vl) {
                struct val_entry * v = list_entry(p, struct val_entry, next);
                list_del(&v->next);
                val_entry_destroy(v);
        }
}

#define MUST_REPLICATE(v, now) ((now)->tv_sec > (v)->t_repl + dht.t_repl)
#define MUST_REPUBLISH(v, now) /* Close to expiry deadline */ \
        (((v)->t_exp - (now)->tv_sec) < (DHT_N_REPUB * dht.t_repl))
static void dht_entry_get_repl_lists(const struct dht_entry * e,
                                     struct list_head *       repl,
                                     struct list_head *       rebl,
                                     struct timespec *        now)
{
        struct list_head * p;
        struct val_entry * n;

        list_for_each(p, &e->vals.list) {
                struct val_entry * v = list_entry(p, struct val_entry, next);
                if (MUST_REPLICATE(v, now) && !IS_EXPIRED(v, now)) {
                        n = val_entry_create(v->val, v->t_exp);
                        if (n == NULL)
                                continue;

                        list_add_tail(&n->next, repl);
                }
        }

        list_for_each(p, &e->lvals.list) {
                struct val_entry * v = list_entry(p, struct val_entry, next);
                if (MUST_REPLICATE(v, now) && MUST_REPUBLISH(v, now)) {
                        /* Add expire time here, to allow creating val_entry */
                        n = val_entry_create(v->val, now->tv_sec + dht.t_expire);
                        if (n == NULL)
                                continue;

                        list_add_tail(&n->next, rebl);
                }
        }
}

static int dht_kv_next_values(uint8_t *          key,
                              struct list_head * repl,
                              struct list_head * rebl)
{
        struct timespec    now;
        struct list_head * p;
        struct list_head * h;
        struct dht_entry * e = NULL;

        assert(key != NULL);
        assert(repl != NULL);
        assert(rebl != NULL);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        assert(list_is_empty(repl));
        assert(list_is_empty(rebl));

        pthread_rwlock_rdlock(&dht.db.lock);

        if (dht.db.kv.len == 0)
                goto no_entries;

        list_for_each_safe(p, h, &dht.db.kv.list) {
                e = list_entry(p, struct dht_entry, next);
                if (IS_CLOSER(e->key, key))
                        continue;  /* Already processed */
        }

        if (e != NULL) {
                memcpy(key, e->key, dht.id.len);
                dht_entry_get_repl_lists(e, repl, rebl, &now);
        }
 no_entries:
        pthread_rwlock_unlock(&dht.db.lock);

        return list_is_empty(repl) && list_is_empty(rebl) ? -ENOENT : 0;
}

static void dht_kv_replicate_value(const uint8_t *         key,
                                   struct val_entry *      v,
                                   const struct timespec * now)
{
        assert(MUST_REPLICATE(v, now));

        (void) now;

        if (dht_kv_store_remote(key, v->val, v->t_exp) == 0) {
                log_dbg(KV_FMT " Replicated.", KV_VAL(key, v->val));
                return;
        }

        log_dbg(KV_FMT " Replication failed.", KV_VAL(key, v->val));

        list_del(&v->next);
        val_entry_destroy(v);
}

static void dht_kv_republish_value(const uint8_t *  key,
                            struct val_entry *      v,
                            const struct timespec * now)
{
        assert(MUST_REPLICATE(v, now));

        if (MUST_REPUBLISH(v, now))
                assert(v->t_exp >= now->tv_sec + dht.t_expire);

        if (dht_kv_store_remote(key, v->val, v->t_exp) == 0) {
                log_dbg(KV_FMT " Republished.", KV_VAL(key, v->val));
                return;
        }

        if (MUST_REPUBLISH(v, now))
                log_warn(KV_FMT " Republish failed.", KV_VAL(key, v->val));
        else
                log_dbg(KV_FMT " Replication failed.", KV_VAL(key, v->val));

        list_del(&v->next);
        val_entry_destroy(v);
}

static void dht_kv_update_replication_times(const uint8_t *         key,
                                            struct list_head *      repl,
                                            struct list_head *      rebl,
                                            const struct timespec * now)
{
        struct dht_entry * e;
        struct list_head * p;
        struct list_head * h;
        struct val_entry * v;

        assert(key != NULL);
        assert(repl != NULL);
        assert(rebl != NULL);
        assert(now != NULL);

        pthread_rwlock_wrlock(&dht.db.lock);

        e = __dht_kv_find_entry(key);
        if (e == NULL) {
                pthread_rwlock_unlock(&dht.db.lock);
                return;
        }

        list_for_each_safe(p, h, repl) {
                struct val_entry * x;
                v = list_entry(p, struct val_entry, next);
                x = dht_entry_get_val(e, v->val);
                if (x == NULL) {
                        log_err(KV_FMT " Not in vals.", KV_VAL(key, v->val));
                        continue;
                }

                x->t_repl = now->tv_sec;

                list_del(&v->next);
                val_entry_destroy(v);
        }

        list_for_each_safe(p, h, rebl) {
                struct val_entry * x;
                v = list_entry(p, struct val_entry, next);
                x = dht_entry_get_lval(e, v->val);
                if (x == NULL) {
                        log_err(KV_FMT " Not in lvals.", KV_VAL(key, v->val));
                        continue;
                }

                x->t_repl = now->tv_sec;
                if (v->t_exp > x->t_exp) {
                        x->t_exp = v->t_exp; /* update expiration time */
                }

                list_del(&v->next);
                val_entry_destroy(v);
        }

        pthread_rwlock_unlock(&dht.db.lock);
}

static void dht_kv_replicate_values(const uint8_t *    key,
                                    struct list_head * repl,
                                    struct list_head * rebl)
{
        struct timespec    now;
        struct list_head * p;
        struct list_head * h;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        list_for_each_safe(p, h, repl) {
                struct val_entry * v;
                v = list_entry(p, struct val_entry, next);
                dht_kv_replicate_value(key, v, &now);
        }

        list_for_each_safe(p, h, rebl) {
                struct val_entry * v;
                v = list_entry(p, struct val_entry, next);
                dht_kv_republish_value(key, v, &now);
        }

        /* removes non-replicated items from the list */
        dht_kv_update_replication_times(key, repl, rebl, &now);

        if (list_is_empty(repl) && list_is_empty(rebl))
                return;

        log_warn(KEY_FMT " Failed to update replication times.", KEY_VAL(key));
}

static void dht_kv_replicate(void)
{
        struct list_head repl; /* list of values to replicate       */
        struct list_head rebl; /* list of local values to republish */
        uint8_t *        key;

        key = dht_dup_key(dht.id.data); /* dist == 0 */
        if (key == NULL) {
                log_err("Replicate: Failed to duplicate DHT ID.");
                return;
        }

        list_head_init(&repl);
        list_head_init(&rebl);

        pthread_cleanup_push(free, key);

        while (dht_kv_next_values(key, &repl, &rebl) == 0) {
                dht_kv_replicate_values(key, &repl, &rebl);
                if (!list_is_empty(&repl)) {
                        log_warn(KEY_FMT " Replication items left.",
                                 KEY_VAL(key));
                        value_list_destroy(&repl);
                }

                if (!list_is_empty(&rebl)) {
                        log_warn(KEY_FMT " Republish items left.",
                                 KEY_VAL(key));
                        value_list_destroy(&rebl);
                }
        }

        pthread_cleanup_pop(true);
}

static void dht_kv_refresh_contacts(void)
{
        struct list_head * p;
        struct list_head * h;
        struct list_head   rl; /* refresh list */
        struct timespec    now;

        list_head_init(&rl);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_rwlock_rdlock(&dht.db.lock);

        __dht_kv_bucket_refresh_list(dht.db.contacts.root, now.tv_sec, &rl);

        pthread_rwlock_unlock(&dht.db.lock);

        list_for_each_safe(p, h, &rl) {
                struct contact * c;
                c = list_entry(p, struct contact, next);
                log_dbg(PEER_FMT " Refreshing contact.",
                        PEER_VAL(c->id, c->addr));
                dht_kv_query_contacts(c->id, NULL);
                list_del(&c->next);
                contact_destroy(c);
        }

        assert(list_is_empty(&rl));
}

static void (*tasks[])(void) = {
        dht_kv_check_contacts,
        dht_kv_remove_expired_entries,
        dht_kv_remove_expired_reqs,
        dht_kv_replicate,
        dht_kv_refresh_contacts,
        NULL
};

static void * work(void * o)
{
        struct timespec now = TIMESPEC_INIT_MS(1);
        time_t          intv;
        size_t          n; /* number of tasks */

        n = sizeof(tasks) / sizeof(tasks[0]) - 1; /* last is NULL */

        (void) o;

        while (dht_kv_seed_bootstrap_peer() == -EAGAIN) {
                ts_add(&now, &now, &now); /* exponential backoff */
                if (now.tv_sec > 1)       /* cap at 1 second     */
                        now.tv_sec = 1;
                nanosleep(&now, NULL);
        }

        intv = gcd(dht.t_expire, (dht.t_expire - DHT_N_REPUB * dht.t_repl));
        intv = gcd(intv, gcd(dht.t_repl, dht.t_refresh)) / 2;
        intv = MAX(1, intv / n);

        log_dbg("DHT worker starting %ld seconds interval.", intv * n);

        while (true) {
                int i = 0;
                while (tasks[i] != NULL) {
                        tasks[i++]();
                        sleep(intv);
                }
        }

        return (void *) 0;
}

int dht_start(void)
{
        dht.state = DHT_RUNNING;

        if (tpm_start(dht.tpm))
                goto fail_tpm_start;

#ifndef __DHT_TEST__
        if (pthread_create(&dht.worker, NULL, work, NULL)) {
                log_err("Failed to create DHT worker thread.");
                goto fail_worker;
        }

        dht.eid = dt_reg_comp(&dht, &dht_post_packet, DHT);
        if ((int) dht.eid < 0) {
                log_err("Failed to register DHT component.");
                goto fail_reg;
        }
#else
        (void) work;
#endif
        return 0;
#ifndef __DHT_TEST__
 fail_reg:
        pthread_cancel(dht.worker);
        pthread_join(dht.worker, NULL);
 fail_worker:
        tpm_stop(dht.tpm);
#endif
 fail_tpm_start:
        dht.state = DHT_INIT;
        return -1;
}

void dht_stop(void)
{
        assert(dht.state == DHT_RUNNING);

#ifndef __DHT_TEST__
        dt_unreg_comp(dht.eid);

        pthread_cancel(dht.worker);
        pthread_join(dht.worker, NULL);
#endif
        tpm_stop(dht.tpm);

        dht.state = DHT_INIT;
}

int dht_init(struct dir_dht_config * conf)
{
        struct timespec now;
        pthread_condattr_t cattr;

        assert(conf != NULL);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

#ifndef __DHT_TEST__
        dht.id.len    = ipcp_dir_hash_len();
        dht.addr      = addr_auth_address();
#else
        dht.id.len    = DHT_TEST_KEY_LEN;
        dht.addr      = DHT_TEST_ADDR;
#endif
        dht.t0        = now.tv_sec;
        dht.alpha     = conf->params.alpha;
        dht.k         = conf->params.k;
        dht.t_expire  = conf->params.t_expire;
        dht.t_refresh = conf->params.t_refresh;
        dht.t_repl    = conf->params.t_replicate;
        dht.peer      = conf->peer;

        dht.magic = generate_cookie();

        /* Send my address on enrollment */
        conf->peer    = dht.addr;

        dht.id.data = generate_id();
        if (dht.id.data == NULL) {
                log_err("Failed to create DHT ID.");
                goto fail_id;
        }

        list_head_init(&dht.cmds.list);

        if (pthread_mutex_init(&dht.cmds.mtx, NULL)) {
                log_err("Failed to initialize command mutex.");
                goto fail_cmds_mutex;
        }

        if (pthread_cond_init(&dht.cmds.cond, NULL)) {
                log_err("Failed to initialize command condvar.");
                goto fail_cmds_cond;
        }

        list_head_init(&dht.reqs.list);
        dht.reqs.len = 0;

        if (pthread_mutex_init(&dht.reqs.mtx, NULL)) {
                log_err("Failed to initialize request mutex.");
                goto fail_reqs_mutex;
        }

        if (pthread_condattr_init(&cattr)) {
                log_err("Failed to initialize request condvar attributes.");
                goto fail_cattr;
        }
#ifndef __APPLE__
        if (pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK)) {
                log_err("Failed to set request condvar clock.");
                goto fail_cattr;
        }
#endif
        if (pthread_cond_init(&dht.reqs.cond, &cattr)) {
                log_err("Failed to initialize request condvar.");
                goto fail_reqs_cond;
        }

        list_head_init(&dht.db.kv.list);
        dht.db.kv.len   = 0;
        dht.db.kv.vals  = 0;
        dht.db.kv.lvals = 0;

        if (pthread_rwlock_init(&dht.db.lock, NULL)) {
                log_err("Failed to initialize store rwlock.");
                goto fail_rwlock;
        }

        dht.db.contacts.root = bucket_create();
        if (dht.db.contacts.root == NULL) {
                log_err("Failed to create DHT buckets.");
                goto fail_buckets;
        }

        if (rib_reg(DHT, &r_ops) < 0) {
                log_err("Failed to register DHT RIB operations.");
                goto fail_rib_reg;
        }

        dht.tpm = tpm_create(2, 1, dht_handle_packet, NULL);
        if (dht.tpm == NULL) {
                log_err("Failed to create TPM for DHT.");
                goto fail_tpm_create;
        }

        if (dht_kv_update_contacts(dht.id.data, dht.addr) < 0)
                log_warn("Failed to update contacts with DHT ID.");

        pthread_condattr_destroy(&cattr);
#ifndef __DHT_TEST__
        log_info("DHT initialized.");
        log_dbg("  ID: " HASH_FMT64 " [%zu bytes].",
                HASH_VAL64(dht.id.data), dht.id.len);
        log_dbg("  address: " ADDR_FMT32 ".", ADDR_VAL32(&dht.addr));
        log_dbg("  peer: " ADDR_FMT32 ".", ADDR_VAL32(&dht.peer));
        log_dbg("  magic cookie: " HASH_FMT64 ".", HASH_VAL64(&dht.magic));
        log_info("  parameters: alpha=%u, k=%zu, t_expire=%ld, "
                "t_refresh=%ld, t_replicate=%ld.",
                dht.alpha, dht.k, dht.t_expire, dht.t_refresh, dht.t_repl);
#endif
        dht.state = DHT_INIT;

        return 0;

 fail_tpm_create:
        rib_unreg(DHT);
 fail_rib_reg:
        bucket_destroy(dht.db.contacts.root);
 fail_buckets:
        pthread_rwlock_destroy(&dht.db.lock);
 fail_rwlock:
        pthread_cond_destroy(&dht.reqs.cond);
 fail_reqs_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(&dht.reqs.mtx);
 fail_reqs_mutex:
        pthread_cond_destroy(&dht.cmds.cond);
 fail_cmds_cond:
        pthread_mutex_destroy(&dht.cmds.mtx);
 fail_cmds_mutex:
        freebuf(dht.id);
 fail_id:
        return -1;
}

void dht_fini(void)
{
        struct list_head * p;
        struct list_head * h;

        rib_unreg(DHT);

        tpm_destroy(dht.tpm);

        pthread_mutex_lock(&dht.cmds.mtx);

        list_for_each_safe(p, h, &dht.cmds.list) {
                struct cmd * c = list_entry(p, struct cmd, next);
                list_del(&c->next);
                freebuf(c->cbuf);
                free(c);
        }

        pthread_mutex_unlock(&dht.cmds.mtx);

        pthread_cond_destroy(&dht.cmds.cond);
        pthread_mutex_destroy(&dht.cmds.mtx);

        pthread_mutex_lock(&dht.reqs.mtx);

        list_for_each_safe(p, h, &dht.reqs.list) {
                struct dht_req * r = list_entry(p, struct dht_req, next);
                list_del(&r->next);
                dht_req_destroy(r);
                dht.reqs.len--;
        }

        pthread_mutex_unlock(&dht.reqs.mtx);

        pthread_cond_destroy(&dht.reqs.cond);
        pthread_mutex_destroy(&dht.reqs.mtx);

        pthread_rwlock_wrlock(&dht.db.lock);

        list_for_each_safe(p, h, &dht.db.kv.list) {
                struct dht_entry * e = list_entry(p, struct dht_entry, next);
                list_del(&e->next);
                dht_entry_destroy(e);
                dht.db.kv.len--;
        }

        if (dht.db.contacts.root != NULL)
                bucket_destroy(dht.db.contacts.root);

        pthread_rwlock_unlock(&dht.db.lock);

        pthread_rwlock_destroy(&dht.db.lock);

        assert(dht.db.kv.len == 0);
        assert(dht.db.kv.vals == 0);
        assert(dht.db.kv.lvals == 0);
        assert(dht.reqs.len == 0);

        freebuf(dht.id);
}
