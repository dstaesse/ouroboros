/*
 * Ouroboros - Copyright (C) 2016
 *
 * The Common Distributed Application Protocol
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <ouroboros/config.h>
#include <ouroboros/cdap.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/dev.h>
#include <ouroboros/fcntl.h>
#include <ouroboros/errno.h>

#include "cdap_req.h"

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <assert.h>

#include "cdap.pb-c.h"
typedef Cdap cdap_t;
typedef Opcode opcode_t;

typedef int32_t invoke_id_t;

#define INVALID_INVOKE_ID -1
#define IDS_SIZE 256
#define BUF_SIZE 2048

struct cdap {
        int              fd;

        struct bmp *     ids;
        pthread_mutex_t  ids_lock;

        pthread_t        reader;

        struct list_head sent;
        pthread_rwlock_t sent_lock;

        struct list_head rcvd;
        pthread_cond_t   rcvd_cond;
        pthread_mutex_t  rcvd_lock;
};

struct cdap_rcvd {
        struct list_head next;

        invoke_id_t      iid;

        enum cdap_opcode opcode;
        char *           name;
        uint8_t *        data;
        size_t           len;
        uint32_t         flags;
};

static int next_invoke_id(struct cdap * instance)
{
        int ret;

        assert(instance);

        pthread_mutex_lock(&instance->ids_lock);

        ret = bmp_allocate(instance->ids);
        if (!bmp_is_id_valid(instance->ids, ret))
                ret = INVALID_INVOKE_ID;

        pthread_mutex_unlock(&instance->ids_lock);

        return ret;
}

static int release_invoke_id(struct cdap * instance, int id)
{
        int ret;

        assert(instance);

        pthread_mutex_lock(&instance->ids_lock);

        ret = bmp_release(instance->ids, id);

        pthread_mutex_unlock(&instance->ids_lock);

        return ret;
}

#define cdap_sent_has_key(i, key) (cdap_sent_get_by_key(i, key) != NULL)

struct cdap_req * cdap_sent_get_by_key(struct cdap * instance, cdap_key_t key)
{
        struct list_head * p = NULL;
        struct cdap_req *  req = NULL;

        assert(instance);
        assert(key >= 0);

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

static int cdap_sent_add(struct cdap * instance, struct cdap_req * req)
{
        assert (instance);
        assert (req);

        if (cdap_sent_has_key(instance, req->key))
                return -EPERM;

        pthread_rwlock_wrlock(&instance->sent_lock);

        list_add(&req->next, &instance->sent);

        pthread_rwlock_unlock(&instance->sent_lock);

        return 0;
}

static void cdap_sent_del(struct cdap * instance, struct cdap_req * req)
{
        assert(instance);
        assert(req);

        assert(cdap_sent_has_key(instance, req->key));

        pthread_rwlock_wrlock(&instance->sent_lock);

        list_del(&req->next);

        pthread_rwlock_unlock(&instance->sent_lock);
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

        pthread_mutex_unlock(&instance->rcvd_lock);
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

        while (true) {
                len = flow_read(instance->fd, buf, BUF_SIZE);
                if (len < 0)
                        continue;

                msg = cdap__unpack(NULL, len, buf);
                if (msg == NULL)
                        continue;

                if (msg->opcode != OPCODE__REPLY) {
                        rcvd = malloc(sizeof(*rcvd));
                        if (rcvd == NULL) {
                                cdap__free_unpacked(msg, NULL);
                                continue;
                        }

                        switch (msg->opcode) {
                        case OPCODE__START:
                                rcvd->opcode = CDAP_START;
                                break;
                        case OPCODE__STOP:
                                rcvd->opcode = CDAP_STOP;
                                break;
                        case OPCODE__READ:
                                rcvd->opcode = CDAP_READ;
                                break;
                        case OPCODE__WRITE:
                                rcvd->opcode = CDAP_WRITE;
                                break;
                        case OPCODE__CREATE:
                                rcvd->opcode = CDAP_CREATE;
                                break;
                        case OPCODE__DELETE:
                                rcvd->opcode = CDAP_DELETE;
                                break;
                        default:
                                cdap__free_unpacked(msg, NULL);
                                free(rcvd);
                                continue;
                        }
                        rcvd->iid   = msg->invoke_id;
                        rcvd->flags = msg->flags;
                        rcvd->name  = strdup(msg->name);
                        if (rcvd->name == NULL) {
                                cdap__free_unpacked(msg, NULL);
                                free(rcvd);
                                continue;
                        }

                        if (msg->has_value) {
                                rcvd->len = msg->value.len;
                                rcvd->data = malloc(rcvd->len);
                                if (rcvd->data == NULL) {
                                        cdap__free_unpacked(msg, NULL);
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
                        req = cdap_sent_get_by_key(instance, msg->invoke_id);
                        if (req == NULL)
                                continue;

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
        }

        return (void *) 0;
}

struct cdap * cdap_create(int fd)
{
        struct cdap * instance = NULL;
        int flags;

        if (fd < 0)
                return NULL;

        flags = flow_get_flags(fd);
        if (flags & FLOW_O_NONBLOCK)
                return NULL;

        instance = malloc(sizeof(*instance));
        if (instance == NULL)
                return NULL;

        if (pthread_mutex_init(&instance->ids_lock, NULL)) {
                free(instance);
                return NULL;
        }

        if (pthread_mutex_init(&instance->rcvd_lock, NULL)) {
                pthread_mutex_destroy(&instance->ids_lock);
                free(instance);
                return NULL;
        }

        if (pthread_rwlock_init(&instance->sent_lock, NULL)) {
                pthread_mutex_destroy(&instance->rcvd_lock);
                pthread_mutex_destroy(&instance->ids_lock);
                free(instance);
                return NULL;
        }

        if (pthread_cond_init(&instance->rcvd_cond, NULL)) {
                pthread_rwlock_destroy(&instance->sent_lock);
                pthread_mutex_destroy(&instance->rcvd_lock);
                pthread_mutex_destroy(&instance->ids_lock);
                free(instance);
                return NULL;
        }

        instance->ids = bmp_create(IDS_SIZE, 0);
        if (instance->ids == NULL) {
                pthread_cond_destroy(&instance->rcvd_cond);
                pthread_rwlock_destroy(&instance->sent_lock);
                pthread_mutex_destroy(&instance->rcvd_lock);
                pthread_mutex_destroy(&instance->ids_lock);
                free(instance);
                return NULL;
        }

        INIT_LIST_HEAD(&instance->sent);
        INIT_LIST_HEAD(&instance->rcvd);

        instance->fd = fd;

        pthread_create(&instance->reader, NULL, sdu_reader, instance);

        return instance;
}

int cdap_destroy(struct cdap * instance)
{
        if (instance == NULL)
                return 0;

        pthread_cancel(instance->reader);
        pthread_join(instance->reader, NULL);

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

static int write_msg(struct cdap * instance, cdap_t * msg)
{
        int ret;
        uint8_t * data;
        size_t len;

        assert(instance);
        assert(msg);

        len = cdap__get_packed_size(msg);
        if (len == 0)
                return -1;

        data = malloc(len);
        if (data == NULL)
                return -ENOMEM;

        cdap__pack(msg, data);

        ret = flow_write(instance->fd, data, len);

        free(data);

        return ret;
}

static cdap_key_t invoke_id_to_key(invoke_id_t iid)
{
        if (iid == INVALID_INVOKE_ID)
                return INVALID_CDAP_KEY;

        return (cdap_key_t) iid;
}

static invoke_id_t key_to_invoke_id(cdap_key_t key)
{
        if (key == INVALID_CDAP_KEY)
                return INVALID_INVOKE_ID;

        return (invoke_id_t) key;
}

cdap_key_t cdap_request_send(struct cdap *    instance,
                             enum cdap_opcode code,
                             char *           name,
                             uint8_t *        data,
                             size_t           len,
                             uint32_t         flags)
{
        cdap_t msg = CDAP__INIT;
        struct cdap_req * req;
        invoke_id_t iid;
        cdap_key_t key;

        if (instance == NULL || name == NULL)
                return -EINVAL;


        iid = next_invoke_id(instance);
        if (iid == INVALID_INVOKE_ID)
                return INVALID_CDAP_KEY;

        switch (code) {
        case CDAP_READ:
                msg.opcode = OPCODE__READ;
                break;
        case CDAP_WRITE:
                msg.opcode = OPCODE__WRITE;
                break;
        case CDAP_CREATE:
                msg.opcode = OPCODE__CREATE;
                break;
        case CDAP_DELETE:
                msg.opcode = OPCODE__DELETE;
                break;
        case CDAP_START:
                msg.opcode = OPCODE__START;
                break;
        case CDAP_STOP:
                msg.opcode = OPCODE__STOP;
                break;
        default:
                release_invoke_id(instance, iid);
                return -EINVAL;
        }

        msg.name = name;
        msg.has_flags = true;
        msg.flags = flags;
        msg.invoke_id = iid;
        if (data != NULL) {
                msg.has_value = true;
                msg.value.data = data;
                msg.value.len = len;
        }

        key = invoke_id_to_key(iid);

        req = cdap_req_create(key);
        if (req == NULL)
                return INVALID_CDAP_KEY;

        if (cdap_sent_add(instance, req)) {
                cdap_req_destroy(req);
                return INVALID_CDAP_KEY;
        }

        if (write_msg(instance, &msg)) {
                cdap_sent_del(instance, req);
                cdap_req_destroy(req);
                return INVALID_CDAP_KEY;
        }

        return key;
}

int cdap_reply_wait(struct cdap * instance,
                    cdap_key_t    key,
                    uint8_t **    data,
                    size_t *      len)
{
        int ret;
        struct cdap_req * r;
        invoke_id_t iid = key_to_invoke_id(key);

        if (instance == NULL || iid == INVALID_INVOKE_ID)
                return -EINVAL;

        r = cdap_sent_get_by_key(instance, key);
        if (r == NULL)
                return -EINVAL;

        ret = cdap_req_wait(r);
        if (ret < 0)
                return ret;

        if (r->response)
                return r->response;

        assert(ret == 0);

        if (data != NULL) {
                *data = r->data.data;
                *len  = r->data.len;
        }

        cdap_sent_del(instance, r);

        release_invoke_id(instance, iid);

        return 0;
}

cdap_key_t cdap_request_wait(struct cdap *      instance,
                             enum cdap_opcode * opcode,
                             char **            name,
                             uint8_t **         data,
                             size_t *           len,
                             uint32_t *         flags)
{
        struct cdap_rcvd * rcvd;
        invoke_id_t iid;

        if (instance == NULL || opcode == NULL || name == NULL || data == NULL
            || len == NULL || flags == NULL)
                return -EINVAL;

        pthread_mutex_lock(&instance->rcvd_lock);

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) &instance->rcvd_lock);

        while (list_empty(&instance->rcvd))
                pthread_cond_wait(&instance->rcvd_cond, &instance->rcvd_lock);

        rcvd = list_first_entry(&instance->rcvd, struct cdap_rcvd, next);

        list_del(&rcvd->next);

        pthread_cleanup_pop(true);

        *opcode = rcvd->opcode;
        *name   = rcvd->name;
        *data   = rcvd->data;
        *len    = rcvd->len;
        *flags  = rcvd->flags;

        iid = rcvd->iid;

        free(rcvd);

        return invoke_id_to_key(iid);
}

int cdap_reply_send(struct cdap * instance,
                    cdap_key_t    key,
                    int           result,
                    uint8_t *     data,
                    size_t        len)
{
        cdap_t msg = CDAP__INIT;
        invoke_id_t iid = key_to_invoke_id(key);

        if (instance == NULL)
                return -EINVAL;

        msg.opcode = OPCODE__REPLY;
        msg.invoke_id = iid;
        msg.has_result = true;
        msg.result = result;

        if (data != NULL) {
                msg.has_value = true;
                msg.value.data = data;
                msg.value.len = len;
        }

        return write_msg(instance, &msg);
}
