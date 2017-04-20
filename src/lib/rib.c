/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Resource Information Base
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/rib.h>
#include <ouroboros/rqueue.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/crc32.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/sha3.h>
#include <ouroboros/btree.h>

#include "ro.pb-c.h"
typedef RoMsg ro_msg_t;

#include <pthread.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>

#define RIB_PATH_DLR     "/"
#define RIB_BTREE_ORDER   64
#define GEN_NAME_SIZE      8

struct revent {
        struct list_head next;

        char *           path;
        int32_t          flags;
};

struct rqueue {
        struct list_head events;
};

struct ro_set {
        uint32_t         sid;
};

struct rn_ptr {
        struct list_head next;

        struct rnode *   node;
};

struct rib_sub {
        struct list_head next;

        uint32_t         sid;

        struct list_head rnodes;

        struct list_head events;

        pthread_cond_t   cond;
        pthread_mutex_t  lock;
};

struct rn_sub {
        struct list_head next;

        struct rib_sub * sub;
        int32_t          flags;
};

struct rnode {
        char *           path;
        char *           name;

        uint8_t *        data;
        size_t           len;

        uint8_t          sha3[SHA3_256_HASH_LEN];

        struct rnode *   parent;

        size_t           chlen;
        struct list_head children;

        struct list_head subs;
};

struct child {
        struct list_head next;

        struct rnode * node;
};

struct rib {
        struct rnode *   root;

        struct btree *   idx;

        pthread_rwlock_t lock;

        struct bmp *     sids;

        struct list_head subs;

        pthread_rwlock_t s_lock;
} rib;

static void rnode_hash(struct rnode * node)
{
        struct sha3_ctx ctx;
        struct list_head * p;

        assert(node);
        assert(node->path);
        assert(node->name);

        rhash_sha3_256_init(&ctx);

        rhash_sha3_update(&ctx, (uint8_t *) node->path, strlen(node->path));

        if (node->data != NULL)
                rhash_sha3_update(&ctx, node->data, node->len);

        list_for_each(p, &node->children) {
                struct child * c = list_entry(p, struct child, next);
                rhash_sha3_update(&ctx, c->node->sha3, SHA3_256_HASH_LEN);
        }

        rhash_sha3_final(&ctx, node->sha3);
}

static void branch_hash(struct rnode * node)
{
        assert(node);

        do {
                rnode_hash(node);
                node = node->parent;
        } while (node != NULL);
}

static struct revent * revent_dup(struct revent * ev)
{
        struct revent * re;

        assert(ev);
        assert(ev->path);

        re = malloc(sizeof(*re));
        if (re == NULL)
                return NULL;

        re->path = strdup(ev->path);
        if (re->path == NULL) {
                free(re);
                return NULL;
        }

        re->flags = ev->flags;

        list_head_init(&re->next);

        return re;
}

/* defined below but needed here */
static void rib_sub_del_rnode(struct rib_sub * sub,
                              struct rnode *   node);

static void rnode_notify_subs(struct rnode *  node,
                              struct rnode *  ch,
                              struct revent * ev)
{
        struct list_head * p;

        assert(node);

        list_for_each(p, &node->subs) {
                struct rn_sub * s = list_entry(p, struct rn_sub, next);
                if (s->flags & ev->flags) {
                        struct revent * e = revent_dup(ev);
                        if (e == NULL)
                                continue;

                        pthread_mutex_lock(&s->sub->lock);
                        list_add_tail(&e->next, &s->sub->events);
                        pthread_cond_signal(&s->sub->cond);
                        pthread_mutex_unlock(&s->sub->lock);
                }

                if (ev->flags & RO_DELETE)
                        rib_sub_del_rnode(s->sub, ch);
        }
}

static int rnode_throw_event(struct rnode * node,
                             int32_t        flags)
{
        struct revent * ev = malloc(sizeof(*ev));
        struct rnode * rn = node;

        assert(node);
        assert(node->path);

        if (ev == NULL)
                return -ENOMEM;

        list_head_init(&ev->next);

        ev->path = strdup(node->path);
        if (ev->path == NULL) {
                free(ev);
                return -ENOMEM;
        }

        ev->flags = flags;

        do {
                rnode_notify_subs(rn, node, ev);
                rn = rn->parent;
        } while (rn != NULL);

        free(ev->path);
        free(ev);

        return 0;
}

static int rnode_add_child(struct rnode * node,
                           struct rnode * child)
{
        struct child * c;
        struct list_head * p;
        struct child * n;

        assert(node);
        assert(child);

        c = malloc(sizeof(*c));
        if (c == NULL)
                return -ENOMEM;

        c->node = child;

        list_for_each(p, &node->children) {
                n = list_entry(p, struct child, next);
                if (strcmp(n->node->name, child->name) > 0)
                        break;
        }

        list_add_tail(&c->next, p);

        ++node->chlen;

        return 0;
}

static void rnode_remove_child(struct rnode * node,
                               struct rnode * child)
{
        struct list_head * p;
        struct list_head * h;

        assert(node);
        assert(child);

        list_for_each_safe(p, h, &node->children) {
                struct child * c = list_entry(p, struct child, next);
                if (c->node == child) {
                        list_del(&c->next);
                        free(c);
                        --node->chlen;
                        return;
                }
        }
}

static struct rnode * rnode_create(struct rnode *  parent,
                                   const char *    name)
{
        struct rnode * node;
        char * parent_path;

        uint32_t crc = 0;

        assert(name);

        node = malloc(sizeof(*node));
        if (node == NULL)
                return NULL;

        list_head_init(&node->children);
        list_head_init(&node->subs);

        if (parent == NULL)
                parent_path = "";
        else
                parent_path = parent->path;

        node->path = malloc(strlen(parent_path)
                            + strlen(RIB_PATH_DLR)
                            + strlen(name)
                            + 1);
        if (node->path == NULL) {
                free(node);
                return NULL;
        }

        strcpy(node->path, parent_path);
        node->name = node->path + strlen(parent_path);
        if (parent != NULL) {
                strcpy(node->name, RIB_PATH_DLR);
                node->name += strlen(RIB_PATH_DLR);
        }

        strcpy(node->name, name);

        if (parent != NULL) {
                if (rnode_add_child(parent, node)) {
                        free(node->path);
                        free(node);
                        return NULL;
                }
        }

        node->data = NULL;
        node->len = 0;

        node->parent = parent;

        node->chlen = 0;

        crc32(&crc, node->path, strlen(node->path));
        btree_insert(rib.idx, crc, node);

        branch_hash(node);
        rnode_throw_event(node, RO_CREATE);

        return node;
}

static void destroy_rnode(struct rnode * node)
{
        struct list_head * p;
        struct list_head * h;

        uint32_t crc = 0;

        assert(node);

        if (node != rib.root) {
                rnode_remove_child(node->parent, node);
                branch_hash(node->parent);
        }

        rnode_throw_event(node, RO_DELETE);

        list_for_each_safe(p, h, &node->subs) {
                struct rn_sub * s = list_entry(p, struct rn_sub, next);
                list_del(&s->next);
                free(s);
        }

        crc32(&crc, node->path, strlen(node->path));
        btree_remove(rib.idx, crc);

        free(node->path);
        if (node->data != NULL)
                free(node->data);

        free(node);
}

static void destroy_rtree(struct rnode * node)
{
        struct list_head * p;
        struct list_head * h;

        assert(node);

        list_for_each_safe(p, h, &node->children) {
                struct child * c = list_entry(p, struct child, next);
                destroy_rtree(c->node);
        }

        destroy_rnode(node);
}

static void rnode_update(struct rnode *  node,
                         uint8_t *       data,
                         size_t          len)
{
        assert(node);
        assert(!(data == NULL && len != 0));
        assert(!(data != NULL && len == 0));

        if (node->data != NULL)
                free(node->data);

        node->data = data;
        node->len = len;

        rnode_throw_event(node, RO_MODIFY);

        branch_hash(node);
}

static struct rn_sub * rnode_get_sub(struct rnode *   node,
                                     struct rib_sub * sub)
{
        struct list_head * p;

        list_for_each(p, &node->subs) {
                struct rn_sub * r = list_entry(p, struct rn_sub, next);
                if (r->sub == sub)
                        return r;
        }

        return NULL;
}

static int rnode_add_sub(struct rnode *   node,
                         struct rib_sub * sub,
                         int32_t          flags)
{
        struct rn_sub * rs;

        assert(node);
        assert(sub);

        rs = rnode_get_sub(node, sub);
        if (rs != NULL)
                return -EPERM;

        rs = malloc(sizeof(*rs));
        if (rs == NULL)
                return -ENOMEM;

        rs->sub = sub;
        rs->flags = flags;

        list_add(&rs->next, &node->subs);

        return 0;
}

static int rnode_del_sub(struct rnode *   node,
                         struct rib_sub * sub)
{
        struct rn_sub * rs;

        assert(node);
        assert(sub);

        rs = rnode_get_sub(node, sub);
        if (rs == NULL)
                return 0;

        list_del(&rs->next);
        free(rs);

        return 0;
}

static struct rnode * find_rnode_by_path(const char * path)
{
        uint32_t crc = 0;

        if (strcmp(path, RIB_ROOT) == 0)
                return rib.root;

        crc32(&crc, path, strlen(path));

        return (struct rnode *) btree_search(rib.idx, crc);
}

int rib_init(void)
{
        if (rib.root != NULL)
                return -EPERM;

        rib.idx = btree_create(RIB_BTREE_ORDER);
        if (rib.idx == NULL) {
                destroy_rtree(rib.root);
                rib.root = NULL;
                return -1;
        }

        rib.root = rnode_create(NULL, "");
        if (rib.root == NULL)
                return -ENOMEM;

        rib.sids = bmp_create(32, 1);
        if (rib.sids == NULL) {
                btree_destroy(rib.idx);
                destroy_rtree(rib.root);
                rib.root = NULL;
                return -1;
        }

        if (pthread_rwlock_init(&rib.lock, NULL)) {
                bmp_destroy(rib.sids);
                btree_destroy(rib.idx);
                destroy_rtree(rib.root);
                rib.root = NULL;
                return -1;
        }

        if (pthread_rwlock_init(&rib.s_lock, NULL)) {
                pthread_rwlock_destroy(&rib.lock);
                bmp_destroy(rib.sids);
                btree_destroy(rib.idx);
                destroy_rtree(rib.root);
                rib.root = NULL;
                return -1;
        }

        list_head_init(&rib.subs);

        assert(rib.root);

        return 0;
}

void rib_fini(void)
{
        if (rib.root == NULL)
                return;

        bmp_destroy(rib.sids);

        destroy_rtree(rib.root);
        rib.root = NULL;

        btree_destroy(rib.idx);

        pthread_rwlock_destroy(&rib.lock);
}

int rib_add(const char * path,
            const char * name)
{
        struct rnode * parent;
        struct rnode * node;

        if (name == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&rib.lock);

        parent = find_rnode_by_path(path);
        if (parent == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -EPERM;
        }

        node = rnode_create(parent, name);
        if (node == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -ENOMEM;
        }

        pthread_rwlock_unlock(&rib.lock);

        return 0;
}

int rib_del(char * path)
{
        struct rnode * node;

        if (path == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&rib.lock);

        node = find_rnode_by_path(path);
        if (node == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -EINVAL;
        }

        destroy_rtree(node);

        pthread_rwlock_unlock(&rib.lock);

        return 0;
}

ssize_t rib_read(const char * path,
                 void *       data,
                 size_t       len)
{
        struct rnode * node;
        ssize_t        rlen;

        if (path == NULL || data == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&rib.lock);

        node = find_rnode_by_path(path);
        if (node == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -EPERM;
        }

        if (len < node->len) {
                pthread_rwlock_unlock(&rib.lock);
                return -EFBIG;
        }

        if (node->data == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return 0;
        }

        assert(node->len > 0);

        memcpy(data, node->data, node->len);
        rlen = node->len;

        rnode_throw_event(node, RO_READ);

        pthread_rwlock_unlock(&rib.lock);

        return rlen;
}

int rib_write(const char * path,
              const void * data,
              size_t       len)
{
        struct rnode * node;

        uint8_t * cdata;

        if (path == NULL || data == NULL || len == 0)
                return -EINVAL;

        cdata = malloc(len);
        if (cdata == NULL)
                return -ENOMEM;

        memcpy(cdata, data, len);

        pthread_rwlock_rdlock(&rib.lock);

        node = find_rnode_by_path(path);
        if (node == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                free(cdata);
                return -1;
        }

        rnode_update(node, cdata, len);

        pthread_rwlock_unlock(&rib.lock);

        return 0;
}

int rib_put(const char * path,
            void *       data,
            size_t       len)
{
        struct rnode * node;

        if (path == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&rib.lock);

        node = find_rnode_by_path(path);
        if (node != NULL)
                rnode_update(node, (uint8_t *) data, len);

        pthread_rwlock_unlock(&rib.lock);

        return 0;
}

bool rib_has(const char * path)
{
        struct rnode * node;

        if (path == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&rib.lock);

        node = find_rnode_by_path(path);

        pthread_rwlock_unlock(&rib.lock);

        return node != NULL;
}

ssize_t rib_children(const char * path,
                     char ***     children)
{
        struct list_head * p;

        struct rnode * node;

        ssize_t i = 0;

        if (path == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&rib.lock);

        node = find_rnode_by_path(path);
        if (node == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -EPERM;
        }

        if (children == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                assert((ssize_t) node->chlen >= 0);
                return (ssize_t) node->chlen;
        }

        if (node->chlen == 0) {
                pthread_rwlock_unlock(&rib.lock);
                *children = NULL;
                return 0;
        }

        *children = malloc(sizeof(**children) * node->chlen);
        if (*children == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -ENOMEM;
        }

        list_for_each(p, &node->children) {
                struct child * c = list_entry(p, struct child, next);
                (*children)[i] = strdup(c->node->name);
                if ((*children)[i] == NULL) {
                        ssize_t j;
                        pthread_rwlock_unlock(&rib.lock);
                        for (j = 0; j < i; ++j)
                                free((*children)[j]);
                        free(*children);
                        return -ENOMEM;
                }
                ++i;
        }

        assert(i > 0);
        assert((size_t) i == node->chlen);

        pthread_rwlock_unlock(&rib.lock);

        return i;
}

static struct rib_sub * rib_get_sub(uint32_t sid)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &rib.subs) {
                struct rib_sub * r = list_entry(p, struct rib_sub, next);
                if (r->sid == sid)
                        return r;
        }

        return 0;
}

static struct rib_sub * rib_sub_create(uint32_t sid)
{
        pthread_condattr_t cattr;
        struct rib_sub * sub = malloc(sizeof(*sub));
        if (sub == NULL)
                return NULL;

        if (pthread_condattr_init(&cattr)) {
                free(sub);
                return NULL;
        }
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&sub->cond, &cattr)) {
                free(sub);
                return NULL;
        }

        if (pthread_mutex_init(&sub->lock, NULL)) {
                pthread_cond_destroy(&sub->cond);
                free(sub);
                return NULL;
        }

        list_head_init(&sub->rnodes);
        list_head_init(&sub->events);

        sub->sid = sid;

        return sub;
}

static void rib_sub_zero(struct rib_sub * sub)
{
        struct list_head * p;
        struct list_head * h;

        assert(sub);

        list_for_each_safe(p, h, &sub->rnodes) {
                struct rn_ptr * r = list_entry(p, struct rn_ptr, next);
                assert(r->node);
                rnode_del_sub(r->node, sub);
                list_del(&r->next);
                free(r);
        }

        list_for_each_safe(p, h, &sub->events) {
                struct revent * r = list_entry(p, struct revent, next);
                list_del(&r->next);
                assert(r->path);
                free(r->path);
                free(r);
        }
}

static struct rn_ptr * rib_sub_get_rn_ptr(struct rib_sub * sub,
                                          struct rnode *   node)
{
        struct list_head * p;

        list_for_each(p, &sub->rnodes) {
                struct rn_ptr * r = list_entry(p, struct rn_ptr, next);
                assert(r->node);
                if (r->node == node)
                        return r;
        }

        return NULL;
}

static int rib_sub_add_rnode(struct rib_sub * sub,
                             struct rnode *   node)
{
        struct rn_ptr * rn;

        assert(sub);
        assert(node);

        if (rib_sub_get_rn_ptr(sub, node) != NULL)
                return 0;

        rn = malloc(sizeof(*rn));
        if (rn == NULL)
                return -ENOMEM;

        rn->node = node;

        list_add(&rn->next, &sub->rnodes);

        return 0;
}

static void rib_sub_del_rnode(struct rib_sub * sub,
                              struct rnode *   node)
{
        struct rn_ptr * rn;

        assert(sub);
        assert(node);

        rn = rib_sub_get_rn_ptr(sub, node);
        if (rn == NULL)
                return;

        list_del(&rn->next);

        free(rn);
}

static void rib_sub_destroy(struct rib_sub * sub)
{
        assert(sub);

        rib_sub_zero(sub);

        free(sub);
}

/* Event calls from rqueue.h. */
ro_set_t * ro_set_create(void)
{
        ro_set_t * set;
        struct rib_sub * sub;

        set = malloc(sizeof(*set));
        if (set == NULL)
                return NULL;

        pthread_rwlock_wrlock(&rib.s_lock);

        set->sid = bmp_allocate(rib.sids);
        if (!bmp_is_id_valid(rib.sids, set->sid)) {
                pthread_rwlock_unlock(&rib.s_lock);
                free(set);
                return NULL;
        }

        pthread_rwlock_unlock(&rib.s_lock);

        pthread_rwlock_wrlock(&rib.lock);

        sub = rib_sub_create(set->sid);
        if (sub == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                free(set);
                return NULL;
        }

        list_add(&sub->next, &rib.subs);

        pthread_rwlock_unlock(&rib.lock);

        return set;
}

void ro_set_destroy(ro_set_t * set)
{
        struct rib_sub * sub = NULL;

        struct list_head * p;
        struct list_head * h;

        pthread_rwlock_wrlock(&rib.lock);

        list_for_each_safe(p, h, &rib.subs) {
                struct rib_sub * r = list_entry(p, struct rib_sub, next);
                if (r->sid == set->sid) {
                        sub = r;
                        break;
                }
        }

        if (sub != NULL)
                rib_sub_destroy(sub);

        pthread_rwlock_unlock(&rib.lock);

        pthread_rwlock_wrlock(&rib.s_lock);

        bmp_release(rib.sids, set->sid);

        pthread_rwlock_unlock(&rib.s_lock);

        free(set);
}

rqueue_t * rqueue_create(void)
{
        rqueue_t * rq = malloc(sizeof(*rq));
        if (rq == NULL)
                return NULL;

        list_head_init(&rq->events);

        return rq;
}

int rqueue_destroy(struct rqueue * rq)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &rq->events) {
                struct revent * e = list_entry(p, struct revent, next);
                list_del(&e->next);
                free(e->path);
                free(e);
        }

        free(rq);

        return 0;
}

int ro_set_zero(ro_set_t * set)
{
        struct rib_sub * sub;

        if (set == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&rib.lock);

        sub = rib_get_sub(set->sid);

        assert(sub);

        rib_sub_zero(sub);

        pthread_rwlock_unlock(&rib.lock);

        return 0;
}

int ro_set_add(ro_set_t *   set,
               const char * path,
               int32_t      flags)
{
        struct rib_sub * sub;
        struct rnode * node;

        if (set == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&rib.lock);

        sub = rib_get_sub(set->sid);

        assert(sub);

        node = find_rnode_by_path(path);
        if (node == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -1;
        }

        if (rnode_add_sub(node, sub, flags)) {
                pthread_rwlock_unlock(&rib.lock);
                return -ENOMEM;
        }

        if (rib_sub_add_rnode(sub, node)) {
                pthread_rwlock_unlock(&rib.lock);
                return -ENOMEM;
        }

        pthread_rwlock_unlock(&rib.lock);

        return 0;
}

int ro_set_del(ro_set_t *   set,
               const char * path)
{
        struct rib_sub * sub;
        struct rnode * node;

        if (set == NULL)
                return -EINVAL;

        pthread_rwlock_wrlock(&rib.lock);

        sub = rib_get_sub(set->sid);

        assert(sub);

        node = find_rnode_by_path(path);
        if (node == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -1;
        }

        rnode_del_sub(node, sub);

        rib_sub_del_rnode(sub, node);

        pthread_rwlock_unlock(&rib.lock);

        return 0;
}

int32_t rqueue_next(rqueue_t * rq,
                    char *     path)
{
        struct revent * ev;
        int32_t         ret;

        if (list_is_empty(&rq->events))
                return -1;

        ev = list_first_entry(&rq->events, struct revent, next);
        list_del(&ev->next);

        strcpy(path, ev->path);
        ret = ev->flags;

        free(ev->path);
        free(ev);

        return ret;
}

int rib_event_wait(ro_set_t *              set,
                   rqueue_t *              rq,
                   const struct timespec * timeout)
{
        struct rib_sub * sub;
        struct timespec abstime;
        struct revent * ev;

        ssize_t ret = 0;

        if (set == NULL || rq == NULL)
                return -EINVAL;

        if (!list_is_empty(&rq->events))
                return 0;

        if (timeout != NULL) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, timeout, &abstime);
        }

        pthread_rwlock_rdlock(&rib.lock);

        sub = rib_get_sub(set->sid);

        pthread_rwlock_unlock(&rib.lock);

        pthread_mutex_lock(&sub->lock);

        pthread_cleanup_push((void(*)(void *)) pthread_mutex_unlock,
                             (void *) &sub->lock);

        while (list_is_empty(&sub->events) && ret != -ETIMEDOUT) {
                if (timeout != NULL)
                        ret = -pthread_cond_timedwait(&sub->cond,
                                                      &sub->lock,
                                                      &abstime);
                else
                        ret = -pthread_cond_wait(&sub->cond, &sub->lock);
        }

        pthread_cleanup_pop(true);

        pthread_rwlock_wrlock(&rib.lock);

        if (ret != -ETIMEDOUT) {
                ev = list_first_entry(&sub->events, struct revent, next);
                list_move(&ev->next, &rq->events);
        }

        pthread_rwlock_unlock(&rib.lock);

        return ret;
}

/* Path name management. */
char * rib_path_append(char *       path,
                       const char * name)
{
        char * pos;

        if (path == NULL || name == NULL || strstr(name, RIB_PATH_DLR))
                return NULL;

        pos = path + strlen(path);
        memcpy(pos++, RIB_PATH_DLR, 1);
        strcpy(pos, name);

        return path;
}

char * rib_name_gen(void *       data,
                    size_t       len)
{
        uint32_t crc = 0;
        char * name;

        if (data == NULL || len == 0)
                return NULL;

        name= malloc(GEN_NAME_SIZE + 1);
        if (name == NULL)
                return NULL;

        crc32(&crc, data, len);

        sprintf(name, "%08x", crc);

        return name;
}

static ro_msg_t * rnode_pack(struct rnode * node,
                             uint32_t       flags,
                             bool           root)
{
        ro_msg_t * msg;

        assert(node);

        if (node->parent == NULL)
                return NULL;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                return NULL;

        ro_msg__init(msg);

        msg->name = node->name;
        if (root) {
                assert(node->parent->path);
                msg->parent = node->parent->path;
        }

        if ((root && (flags & PACK_HASH_ROOT)) ||
            (flags & PACK_HASH_ALL)) {
                msg->has_hash  = true;
                msg->hash.data = node->sha3;
                msg->hash.len  = SHA3_256_HASH_LEN;
        }

        if (node->data != NULL) {
                msg->has_data  = true;
                msg->data.data = node->data;
                msg->data.len  = node->len;
        }

        if (node->chlen > 0) {
                int n = 0;
                struct list_head * p;
                ro_msg_t ** msgs = malloc(sizeof(*msgs) * node->chlen);
                if (msgs == NULL) {
                        free(msg);
                        return NULL;
                }

                msg->n_children = node->chlen;

                list_for_each(p, &node->children) {
                        struct child * c = list_entry(p, struct child, next);
                        msgs[n] = rnode_pack(c->node, flags, false);
                        if (msgs[n] == NULL) {
                                int i;
                                for (i = 0; i < n; ++i)
                                        free(msgs[i]);
                                free(msgs);
                                free(msg);
                                return NULL;
                        }
                        ++n;
                }
                msg->children = msgs;
        }

        return msg;
}

static void free_ro_msg(ro_msg_t * msg)
{
        size_t n = 0;
        while (n < msg->n_children)
                free_ro_msg(msg->children[n++]);

        free(msg->children);
        free(msg);
}

ssize_t rib_pack(const char *   path,
                 uint8_t **     buf,
                 uint32_t       flags)
{
        struct rnode * node;
        ro_msg_t * msg;
        ssize_t len;

        if (path == NULL)
                return -EINVAL;

        pthread_rwlock_rdlock(&rib.lock);

        node = find_rnode_by_path(path);
        if (node == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -EPERM;
        }

        msg = rnode_pack(node, flags, true);
        if (msg == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -EPERM;
        }

        len = ro_msg__get_packed_size(msg);
        if (len == 0) {
                pthread_rwlock_unlock(&rib.lock);
                free_ro_msg(msg);
                return 0;
        }

        *buf = malloc(len);
        if (*buf == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                free_ro_msg(msg);
                return -ENOMEM;
        }

        ro_msg__pack(msg, *buf);

        pthread_rwlock_unlock(&rib.lock);

        free_ro_msg(msg);

        return len;
}

static struct rnode * rnode_get_child(struct rnode * node,
                                      const char *   name)
{
        struct list_head * p;

        list_for_each(p, &node->children) {
                struct child * c = list_entry(p, struct child, next);
                if (strcmp(c->node->name, name) == 0)
                        return c->node;
        }

        return NULL;
}

static int rnode_unpack(ro_msg_t *     msg,
                        struct rnode * parent,
                        uint32_t       flags)
{
        struct rnode * node;

        size_t i;

        assert(msg);
        assert(parent);

        node = rnode_get_child(parent, msg->name);
        if (node == NULL) {
                if (flags & UNPACK_CREATE)
                        node = rnode_create(parent, msg->name);
                else
                        return -EPERM;
        }

        if (node == NULL)
                return -ENOMEM;

        /* Unpack in reverse order for faster insertion */
        i = msg->n_children;
        while (i > 0)
                rnode_unpack(msg->children[--i], node, flags);

        if (msg->has_data) {
                uint8_t * data = malloc(msg->data.len);
                if (data == NULL)
                        return -ENOMEM;

                memcpy(data, msg->data.data, msg->data.len);
                rnode_update(node, data, msg->data.len);
        }

        return 0;
}

int rib_unpack(uint8_t * packed,
               size_t    len,
               uint32_t  flags)
{
        ro_msg_t * msg;
        struct rnode * root;
        int ret;

        if (packed == NULL)
                return -EINVAL;

        msg = ro_msg__unpack(NULL, len, packed);
        if (msg == NULL)
                return -EPERM;

        assert(msg->parent);

        pthread_rwlock_wrlock(&rib.lock);

        root = find_rnode_by_path(msg->parent);
        if (root == NULL) {
                pthread_rwlock_unlock(&rib.lock);
                return -EPERM;
        }

        ret = rnode_unpack(msg, root, flags);

        if (ret == 0 && msg->has_hash) {
                root = rnode_get_child(root, msg->name);
                if (memcmp(msg->hash.data, root->sha3, SHA3_256_HASH_LEN)) {
                        ro_msg__free_unpacked(msg, NULL);
                        pthread_rwlock_unlock(&rib.lock);
                        return -EFAULT;
                }
        }

        pthread_rwlock_unlock(&rib.lock);

        ro_msg__free_unpacked(msg, NULL);

        free(packed);

        return ret;
}
