/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The Common Distributed Application Protocol
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
#include <ouroboros/cdap.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/fcntl.h>
#include <ouroboros/errno.h>

#include "cdap_req.h"

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>

#include "cdap.pb-c.h"
typedef Cdap cdap_t;

#define CDAP_REPLY (CDAP_DELETE + 1)

#define INVALID_ID -1
#define IDS_SIZE 2048
#define BUF_SIZE 2048

struct fd_el {
        struct list_head next;

        int              fd;
};

struct cdap {
        flow_set_t *     set;
        fqueue_t *       fq;

        bool             proc;
        pthread_mutex_t  mtx;
        pthread_cond_t   cond;

        size_t           n_flows;
        struct list_head flows;
        pthread_rwlock_t flows_lock;

        struct bmp *     ids;
        pthread_mutex_t  ids_lock;

        struct list_head sent;
        pthread_rwlock_t sent_lock;

        struct list_head rcvd;
        pthread_cond_t   rcvd_cond;
        pthread_mutex_t  rcvd_lock;

        pthread_t        reader;
};

struct cdap_rcvd {
        struct list_head next;

        int              fd;
        bool             proc;

        invoke_id_t      iid;
        cdap_key_t       key;

        enum cdap_opcode opcode;
        char *           name;
        void *           data;
        size_t           len;
        uint32_t         flags;
};

static int next_id(struct cdap * instance)
{
        int ret;

        assert(instance);

        pthread_mutex_lock(&instance->ids_lock);

        ret = bmp_allocate(instance->ids);
        if (!bmp_is_id_valid(instance->ids, ret))
                ret = INVALID_ID;

        pthread_mutex_unlock(&instance->ids_lock);

        return ret;
}

static int release_id(struct cdap * instance,
                      int32_t       id)
{
        int ret;

        assert(instance);

        pthread_mutex_lock(&instance->ids_lock);

        ret = bmp_release(instance->ids, id);

        pthread_mutex_unlock(&instance->ids_lock);

        return ret;
}

#define cdap_sent_has_key(i, key) (cdap_sent_get_by_key(i, key) != NULL)

static struct cdap_req * cdap_sent_get_by_key(struct cdap * instance,
                                              cdap_key_t    key)
{
        struct list_head * p = NULL;
        struct cdap_req *  req = NULL;

        assert(instance);

        pthread_rwlock_rdlock(&instance->sent_lock);

        list_for_each(p, &instance->sent) {
                req = list_entry(p, struct cdap_req, next);
                if (req->key == key) {
                        pthread_rwlock_unlock(&instance->sent_lock);
                        return req;
                }
        }

        pthread_rwlock_unlock(&instance->sent_lock);

        return NULL;
}

static struct cdap_req * cdap_sent_get_by_iid(struct cdap * instance,
                                              invoke_id_t   iid)
{
        struct list_head * p = NULL;
        struct cdap_req *  req = NULL;

        assert(instance);

        pthread_rwlock_rdlock(&instance->sent_lock);

        list_for_each(p, &instance->sent) {
                req = list_entry(p, struct cdap_req, next);
                if (req->iid == iid) {
                        pthread_rwlock_unlock(&instance->sent_lock);
                        return req;
                }
        }

        pthread_rwlock_unlock(&instance->sent_lock);

        return NULL;
}

static struct cdap_rcvd * cdap_rcvd_get_by_key(struct cdap * instance,
                                               cdap_key_t    key)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;
        struct cdap_rcvd * rcvd = NULL;

        assert(instance);

        pthread_mutex_lock(&instance->rcvd_lock);

        list_for_each_safe(p, h, &instance->rcvd) {
                rcvd = list_entry(p, struct cdap_rcvd, next);
                if (rcvd->key == key) {
                        list_del(&rcvd->next);
                        pthread_mutex_unlock(&instance->rcvd_lock);
                        return rcvd;
                }
        }

        pthread_mutex_unlock(&instance->rcvd_lock);

        assert(false);

        return NULL;
}

static struct cdap_req * cdap_sent_add(struct cdap * instance,
                                       int           fd,
                                       invoke_id_t   iid,
                                       cdap_key_t    key)
{
        struct cdap_req * req;

        assert(instance);
        assert(!cdap_sent_has_key(instance, key));

        req = cdap_req_create(fd, iid, key);
        if (req == NULL)
                return NULL;

        pthread_rwlock_wrlock(&instance->sent_lock);

        list_add(&req->next, &instance->sent);

        pthread_rwlock_unlock(&instance->sent_lock);

        return req;
}

static void cdap_sent_del(struct cdap *     instance,
                          struct cdap_req * req)
{
        assert(instance);
        assert(req);

        assert(cdap_sent_has_key(instance, req->key));

        pthread_rwlock_wrlock(&instance->sent_lock);

        list_del(&req->next);

        pthread_rwlock_unlock(&instance->sent_lock);

        cdap_req_destroy(req);
}

static void cdap_sent_destroy(struct cdap * instance)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        assert(instance);

        pthread_rwlock_wrlock(&instance->sent_lock);

        list_for_each_safe(p, h, &instance->sent) {
                struct cdap_req * req = list_entry(p, struct cdap_req, next);
                list_del(&req->next);
                cdap_req_cancel(req);
                cdap_req_destroy(req);
        }

        pthread_rwlock_unlock(&instance->sent_lock);
}

static void cdap_rcvd_destroy(struct cdap * instance)
{
        struct list_head * p = NULL;
        struct list_head * h = NULL;

        assert(instance);

        pthread_mutex_lock(&instance->rcvd_lock);

        list_for_each_safe(p, h, &instance->sent) {
                struct cdap_rcvd * r = list_entry(p, struct cdap_rcvd, next);
                list_del(&r->next);
                if (r->data != NULL)
                        free(r->data);
                if (r->name != NULL)
                        free(r->name);
                free(r);
        }

        pthread_cond_broadcast(&instance->rcvd_cond);

        pthread_mutex_unlock(&instance->rcvd_lock);
}

static void set_proc(struct cdap * instance,
                     bool          status)
{
        pthread_mutex_lock(&instance->mtx);

        instance->proc = status;
        pthread_cond_signal(&instance->cond);

        pthread_mutex_unlock(&instance->mtx);
}

static void * sdu_reader(void * o)
{
        struct cdap * instance = (struct cdap *) o;
        struct cdap_req * req;
        struct cdap_rcvd * rcvd;
        cdap_t * msg;
        uint8_t buf[BUF_SIZE];
        ssize_t len;
        buffer_t data;

        while (flow_event_wait(instance->set, instance->fq, NULL)) {
                int fd;
                set_proc(instance, true);
                fd = fqueue_next(instance->fq);
                len = flow_read(fd, buf, BUF_SIZE);
                if (len < 0)
                        continue;

                msg = cdap__unpack(NULL, len, buf);
                if (msg == NULL)
                        continue;

                if (msg->opcode != CDAP_REPLY) {
                        rcvd = malloc(sizeof(*rcvd));
                        if (rcvd == NULL) {
                                cdap__free_unpacked(msg, NULL);
                                continue;
                        }

                        assert(msg->name);

                        rcvd->opcode = msg->opcode;
                        rcvd->fd     = fd;
                        rcvd->iid    = msg->invoke_id;
                        rcvd->key    = next_id(instance);
                        if (rcvd->key == INVALID_ID) {
                                cdap__free_unpacked(msg, NULL);
                                free(rcvd);
                                continue;
                        }

                        rcvd->flags  = msg->flags;
                        rcvd->proc   = false;
                        rcvd->name   = strdup(msg->name);
                        if (rcvd->name == NULL) {
                                release_id(instance, rcvd->key);
                                cdap__free_unpacked(msg, NULL);
                                free(rcvd);
                                continue;
                        }

                        if (msg->has_value) {
                                rcvd->len = msg->value.len;
                                rcvd->data = malloc(rcvd->len);
                                if (rcvd->data == NULL) {
                                        release_id(instance, rcvd->key);
                                        cdap__free_unpacked(msg, NULL);
                                        free(rcvd->name);
                                        free(rcvd);
                                        continue;
                                }
                                memcpy(rcvd->data, msg->value.data, rcvd->len);
                        } else {
                                rcvd->len = 0;
                                rcvd->data = NULL;
                        }

                        pthread_mutex_lock(&instance->rcvd_lock);

                        list_add(&rcvd->next, &instance->rcvd);

                        pthread_cond_signal(&instance->rcvd_cond);
                        pthread_mutex_unlock(&instance->rcvd_lock);
                } else  {
                        req = cdap_sent_get_by_iid(instance, msg->invoke_id);
                        if (req == NULL) {
                                cdap__free_unpacked(msg, NULL);
                                continue;
                        }

                        if (msg->has_value) {
                                data.len = msg->value.len;
                                data.data = malloc(data.len);
                                if (data.data == NULL) {
                                        cdap__free_unpacked(msg, NULL);
                                        continue;
                                }
                                memcpy(data.data, msg->value.data, data.len);
                        } else {
                                data.len = 0;
                                data.data = NULL;
                        }

                        cdap_req_respond(req, msg->result, data);
                }

                cdap__free_unpacked(msg, NULL);
                set_proc(instance, false);
        }

        return (void *) 0;
}

struct cdap * cdap_create()
{
        struct cdap * instance = NULL;

        instance = malloc(sizeof(*instance));
        if (instance == NULL)
                goto fail_malloc;

        if (pthread_rwlock_init(&instance->flows_lock, NULL))
                goto fail_flows_lock;

        if (pthread_mutex_init(&instance->ids_lock, NULL))
                goto fail_ids_lock;

        if (pthread_mutex_init(&instance->rcvd_lock, NULL))
                goto fail_rcvd_lock;

        if (pthread_rwlock_init(&instance->sent_lock, NULL))
                goto fail_sent_lock;

        if (pthread_cond_init(&instance->rcvd_cond, NULL))
                goto fail_rcvd_cond;

        if (pthread_mutex_init(&instance->mtx, NULL))
                goto fail_mtx;

        if (pthread_cond_init(&instance->cond, NULL))
                goto fail_cond;

        instance->ids = bmp_create(IDS_SIZE, 0);
        if (instance->ids == NULL)
                goto fail_bmp_create;

        instance->set = flow_set_create();
        if (instance->set == NULL)
                goto fail_set_create;

        instance->fq = fqueue_create();
        if (instance->fq == NULL)
                goto fail_fqueue_create;

        instance->n_flows = 0;
        instance->proc = false;

        list_head_init(&instance->flows);
        list_head_init(&instance->sent);
        list_head_init(&instance->rcvd);

        if (pthread_create(&instance->reader, NULL, sdu_reader, instance))
                goto fail_pthread_create;

        return instance;

 fail_pthread_create:
        fqueue_destroy(instance->fq);
 fail_fqueue_create:
        flow_set_destroy(instance->set);
 fail_set_create:
        bmp_destroy(instance->ids);
 fail_bmp_create:
        pthread_cond_destroy(&instance->cond);
 fail_cond:
        pthread_mutex_destroy(&instance->mtx);
 fail_mtx:
        pthread_cond_destroy(&instance->rcvd_cond);
 fail_rcvd_cond:
        pthread_rwlock_destroy(&instance->sent_lock);
 fail_sent_lock:
        pthread_mutex_destroy(&instance->rcvd_lock);
 fail_rcvd_lock:
        pthread_mutex_destroy(&instance->ids_lock);
 fail_ids_lock:
        pthread_rwlock_destroy(&instance->flows_lock);
 fail_flows_lock:
        free(instance);
 fail_malloc:
        return NULL;
}

int cdap_destroy(struct cdap * instance)
{
        struct list_head * p;
        struct list_head * h;

        if (instance == NULL)
                return 0;

        pthread_cancel(instance->reader);
        pthread_join(instance->reader, NULL);

        fqueue_destroy(instance->fq);

        flow_set_destroy(instance->set);

        pthread_cond_destroy(&instance->cond);
        pthread_mutex_destroy(&instance->mtx);

        pthread_rwlock_wrlock(&instance->flows_lock);

        list_for_each_safe(p,h, &instance->flows) {
                struct fd_el * e = list_entry(p, struct fd_el, next);
                list_del(&e->next);
                free(e);
        }

        pthread_rwlock_unlock(&instance->flows_lock);

        pthread_rwlock_destroy(&instance->flows_lock);

        pthread_mutex_lock(&instance->ids_lock);

        bmp_destroy(instance->ids);

        pthread_mutex_unlock(&instance->ids_lock);

        pthread_mutex_destroy(&instance->ids_lock);

        cdap_sent_destroy(instance);

        pthread_rwlock_destroy(&instance->sent_lock);

        cdap_rcvd_destroy(instance);

        pthread_mutex_destroy(&instance->rcvd_lock);

        free(instance);

        return 0;
}

int cdap_add_flow(struct cdap * instance,
                  int           fd)
{
        struct fd_el * e;

        if (fd < 0)
                return -EINVAL;

        e = malloc(sizeof(*e));
        if (e == NULL)
                return -ENOMEM;

        e->fd = fd;

        pthread_rwlock_wrlock(&instance->flows_lock);

        if (flow_set_add(instance->set, fd)) {
                pthread_rwlock_unlock(&instance->flows_lock);
                return -1;
        }

        list_add(&e->next, &instance->flows);

        ++instance->n_flows;

        pthread_rwlock_unlock(&instance->flows_lock);

        return 0;
}

int cdap_del_flow(struct cdap * instance,
                  int           fd)
{
        struct list_head * p;
        struct list_head * h;

        if (fd < 0)
                return -EINVAL;

        pthread_rwlock_wrlock(&instance->flows_lock);

        pthread_mutex_lock(&instance->mtx);

        while (instance->proc)
                pthread_cond_wait(&instance->cond, &instance->mtx);

        flow_set_del(instance->set, fd);

        pthread_mutex_unlock(&instance->mtx);

        list_for_each_safe(p, h, &instance->flows) {
                struct fd_el * e = list_entry(p, struct fd_el, next);
                if (e->fd == fd) {
                        list_del(&e->next);
                        free(e);
                        break;
                }
        }

        --instance->n_flows;

        pthread_rwlock_unlock(&instance->flows_lock);

        return 0;
}

static int write_msg(int           fd,
                     cdap_t *      msg)
{
        uint8_t * data;
        size_t len;

        assert(msg);

        len = cdap__get_packed_size(msg);
        if (len == 0)
                return -1;

        data = malloc(len);
        if (data == NULL)
                return -ENOMEM;

        cdap__pack(msg, data);

        if (flow_write(fd, data, len)) {
                free(data);
                return -1;
        }

        free(data);

        return 0;
}

cdap_key_t * cdap_request_send(struct cdap *    instance,
                               enum cdap_opcode code,
                               const char *     name,
                               const void *     data,
                               size_t           len,
                               uint32_t         flags)
{
        cdap_key_t *       keys;
        cdap_key_t *       key;
        cdap_t             msg = CDAP__INIT;
        struct list_head * p;
        int                ret;

        if (instance == NULL || name == NULL || code > CDAP_DELETE)
                return NULL;

        pthread_rwlock_rdlock(&instance->flows_lock);

        keys = malloc(sizeof(*keys) * (instance->n_flows + 1));
        if (keys == NULL)
                return NULL;

        memset(keys, INVALID_CDAP_KEY, sizeof(*keys) * (instance->n_flows + 1));

        key = keys;

        cdap__init(&msg);

        msg.opcode = code;
        msg.name = (char *) name;
        msg.has_flags = true;
        msg.flags = flags;

        if (data != NULL) {
                msg.has_value = true;
                msg.value.data = (uint8_t *) data;
                msg.value.len = len;
        }

        list_for_each(p, &instance->flows) {
                struct cdap_req * req;
                invoke_id_t iid;
                struct fd_el * e;

                iid = next_id(instance);
                if (iid == INVALID_ID) {
                        pthread_rwlock_unlock(&instance->flows_lock);
                        return keys;
                }

                msg.invoke_id = iid;

                e = list_entry(p, struct fd_el, next);

                *key = next_id(instance);
                if (*key == INVALID_ID) {
                        pthread_rwlock_unlock(&instance->flows_lock);
                        release_id(instance, iid);
                        return keys;
                }

                req = cdap_sent_add(instance, e->fd, iid, *key);
                if (req == NULL) {
                        pthread_rwlock_unlock(&instance->flows_lock);
                        release_id(instance, *key);
                        release_id(instance, iid);
                        *key = INVALID_CDAP_KEY;
                        return keys;
                }

                ret = write_msg(e->fd, &msg);
                if (ret == -ENOMEM) {
                        pthread_rwlock_unlock(&instance->flows_lock);
                        cdap_sent_del(instance, req);
                        release_id(instance, *key);
                        release_id(instance, iid);
                        *key = INVALID_CDAP_KEY;
                        return keys;
                }

                if (ret < 0) {
                        pthread_rwlock_unlock(&instance->flows_lock);
                        cdap_sent_del(instance, req);
                        release_id(instance, *key);
                        release_id(instance, iid);
                        *key = INVALID_CDAP_KEY;
                        return keys;
                }

                ++key;
        }

        pthread_rwlock_unlock(&instance->flows_lock);

        return keys;
}

int cdap_reply_wait(struct cdap * instance,
                    cdap_key_t    key,
                    uint8_t **    data,
                    size_t *      len)
{
        int ret;
        struct cdap_req * r;
        invoke_id_t iid;

        if (instance == NULL || (data != NULL && len == NULL))
                return -EINVAL;

        r = cdap_sent_get_by_key(instance, key);
        if (r == NULL)
                return -EINVAL;

        iid = r->iid;

        ret = cdap_req_wait(r);
        if (ret < 0) {
                cdap_sent_del(instance, r);
                release_id(instance, iid);
                release_id(instance, key);
                return ret;
        }

        assert(ret == 0);

        if (data != NULL) {
                *data = r->data.data;
                *len  = r->data.len;
        }

        ret = r->response;

        cdap_sent_del(instance, r);
        release_id(instance, iid);
        release_id(instance, key);

        return ret;
}

cdap_key_t cdap_request_wait(struct cdap *      instance,
                             enum cdap_opcode * opcode,
                             char **            name,
                             uint8_t **         data,
                             size_t *           len,
                             uint32_t *         flags)
{
        struct cdap_rcvd * rcv = NULL;

        if (instance == NULL || opcode == NULL || name == NULL || data == NULL
            || len == NULL || flags == NULL)
                return -EINVAL;

        pthread_mutex_lock(&instance->rcvd_lock);

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) &instance->rcvd_lock);

        while (rcv == NULL) {
                while (list_is_empty(&instance->rcvd))
                        pthread_cond_wait(&instance->rcvd_cond,
                                          &instance->rcvd_lock);

                rcv = list_first_entry(&instance->rcvd, struct cdap_rcvd, next);
                if (rcv->proc) {
                        rcv = NULL;
                        pthread_cond_wait(&instance->rcvd_cond,
                                          &instance->rcvd_lock);
                }
        }

        assert(rcv->proc == false);

        rcv->proc = true;
        list_del(&rcv->next);
        list_add_tail(&rcv->next, &instance->rcvd);

        pthread_cleanup_pop(true);

        *opcode = rcv->opcode;
        *name   = rcv->name;
        *data   = rcv->data;
        *len    = rcv->len;
        *flags  = rcv->flags;

        rcv->name = NULL;
        rcv->data = NULL;

        return rcv->key;
}

int cdap_reply_send(struct cdap * instance,
                    cdap_key_t    key,
                    int           result,
                    const void *  data,
                    size_t        len)
{
        int                fd;
        cdap_t             msg  = CDAP__INIT;
        struct cdap_rcvd * rcvd;

        if (instance == NULL)
                return -EINVAL;

        rcvd = cdap_rcvd_get_by_key(instance, key);
        if (rcvd == NULL)
                return -1;

        msg.opcode = CDAP_REPLY;
        msg.invoke_id = rcvd->iid;
        msg.has_result = true;
        msg.result = result;

        if (data != NULL) {
                msg.has_value = true;
                msg.value.data = (uint8_t *) data;
                msg.value.len = len;
        }

        fd = rcvd->fd;

        release_id(instance, rcvd->key);

        assert(rcvd->data == NULL);
        assert(rcvd->name == NULL);
        assert(rcvd->proc);

        free(rcvd);

        return write_msg(fd, &msg);
}
