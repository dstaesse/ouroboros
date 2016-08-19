/*
 * Ouroboros - Copyright (C) 2016
 *
 * The Common Distributed Application Protocol
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#include <stdlib.h>
#include <pthread.h>

#include "cdap.pb-c.h"
typedef Cdap cdap_t;
typedef Opcode opcode_t;

#define IDS_SIZE 256
#define BUF_SIZE 2048

struct cdap {
        int               fd;
        struct bmp *      ids;
        pthread_mutex_t   ids_lock;
        pthread_t         reader;
        struct cdap_ops * ops;
};

struct cdap_info {
        pthread_t thread;
        struct cdap * instance;
        cdap_t * msg;
};

static int next_invoke_id(struct cdap * instance)
{
        int ret;

        pthread_mutex_lock(&instance->ids_lock);
        ret = bmp_allocate(instance->ids);
        pthread_mutex_unlock(&instance->ids_lock);

        return ret;
}

static int release_invoke_id(struct cdap * instance,
                             int id)
{
        int ret;

        pthread_mutex_lock(&instance->ids_lock);
        ret = bmp_release(instance->ids, id);
        pthread_mutex_unlock(&instance->ids_lock);

        return ret;
}

static void * handle_cdap_msg(void * o)
{
        struct cdap_info * info = (struct cdap_info *) o;
        struct cdap * instance = info->instance;
        cdap_t * msg = info->msg;

        switch (msg->opcode) {
        case OPCODE__READ:
                if (msg->name != NULL)
                        instance->ops->cdap_read(instance,
                                                 msg->invoke_id,
                                                 msg->name);
                break;
        case OPCODE__WRITE:
                if (msg->name != NULL &&
                    msg->has_value)
                        instance->ops->cdap_write(instance,
                                                  msg->invoke_id,
                                                  msg->name,
                                                  msg->value.data,
                                                  msg->value.len,
                                                  msg->flags);
                break;
        case OPCODE__CREATE:
                if (msg->name != NULL &&
                    msg->has_value)
                        instance->ops->cdap_create(instance,
                                                   msg->invoke_id,
                                                   msg->name,
                                                   msg->value.data,
                                                   msg->value.len);
                break;
        case OPCODE__DELETE:
                if (msg->name != NULL &&
                    msg->has_value)
                        instance->ops->cdap_create(instance,
                                                   msg->invoke_id,
                                                   msg->name,
                                                   msg->value.data,
                                                   msg->value.len);
                break;
        case OPCODE__START:
                if (msg->name != NULL)
                        instance->ops->cdap_start(instance,
                                                  msg->invoke_id,
                                                  msg->name);
                break;
        case OPCODE__STOP:
                if (msg->name != NULL)
                        instance->ops->cdap_stop(instance,
                                                 msg->invoke_id,
                                                 msg->name);
                break;
        case OPCODE__REPLY:
                instance->ops->cdap_reply(instance,
                                          msg->invoke_id,
                                          msg->result,
                                          msg->value.data,
                                          msg->value.len);
                release_invoke_id(instance, msg->invoke_id);
                break;
        default:
                break;
        }

        free(info);
        cdap__free_unpacked(msg, NULL);

        return (void *) 0;
}

static void * sdu_reader(void * o)
{
        struct cdap * instance = (struct cdap *) o;
        cdap_t * msg;
        uint8_t buf[BUF_SIZE];
        ssize_t len;
        struct cdap_info * cdap_info;

        while (true) {
                len = flow_read(instance->fd, buf, BUF_SIZE);
                if (len < 0)
                        return (void *) -1;

                msg = cdap__unpack(NULL, len, buf);
                if (msg == NULL)
                        continue;

                cdap_info = malloc(sizeof(*cdap_info));
                if (cdap_info == NULL) {
                        cdap__free_unpacked(msg, NULL);
                        continue;
                }

                cdap_info->instance = instance;
                cdap_info->msg = msg;

                pthread_create(&cdap_info->thread,
                               NULL,
                               handle_cdap_msg,
                               (void *) cdap_info);

                pthread_detach(cdap_info->thread);

        }

        return (void *) 0;
}

struct cdap * cdap_create(struct cdap_ops * ops,
                          int               fd)
{
        struct cdap * instance = NULL;
        int flags;

        if (ops == NULL || fd < 0 ||
            ops->cdap_reply == NULL ||
            ops->cdap_read == NULL ||
            ops->cdap_write == NULL ||
            ops->cdap_create == NULL ||
            ops->cdap_delete == NULL ||
            ops->cdap_start == NULL ||
            ops->cdap_stop == NULL)
                return NULL;

        flags = flow_cntl(fd, FLOW_F_GETFL, 0);
        if (flags & FLOW_O_NONBLOCK)
                return NULL;

        instance = malloc(sizeof(*instance));
        if (instance == NULL)
                return NULL;

        if (pthread_mutex_init(&instance->ids_lock, NULL)) {
                free(instance);
                return NULL;
        }

        instance->ops = ops;
        instance->fd = fd;

        instance->ids = bmp_create(IDS_SIZE, 0);
        if (instance->ids == NULL) {
                free(instance);
                return NULL;
        }

        pthread_create(&instance->reader,
                       NULL,
                       sdu_reader,
                       (void *) instance);

        return instance;
}

int cdap_destroy(struct cdap * instance)
{
        if (instance == NULL)
                return -1;

        pthread_cancel(instance->reader);

        if (flow_dealloc(instance->fd))
                return -1;

        pthread_mutex_lock(&instance->ids_lock);

        bmp_destroy(instance->ids);

        pthread_mutex_unlock(&instance->ids_lock);

        pthread_join(instance->reader,
                     NULL);

        free(instance);

        return 0;
}

static int write_msg(struct cdap * instance,
                     cdap_t * msg)
{
        int ret;
        uint8_t * data;
        size_t len;

        len = cdap__get_packed_size(msg);
        if (len == 0)
                return -1;

        data = malloc(BUF_SIZE);
        if (data == NULL)
                return -1;

        cdap__pack(msg, data);

        ret = flow_write(instance->fd, data, len);

        free(data);

        return ret;
}

static int send_read_or_start_or_stop(struct cdap * instance,
                                      char *        name,
                                      opcode_t      code)
{
        int id;
        cdap_t msg = CDAP__INIT;

        if (instance == NULL || name == NULL)
                return -1;

        id = next_invoke_id(instance);
        if (!bmp_is_id_valid(instance->ids, id))
                return -1;

        msg.opcode = code;
        msg.invoke_id = id;
        msg.name = name;

        if (write_msg(instance, &msg))
                return -1;

        return id;
}

static int send_create_or_delete(struct cdap * instance,
                                 char *        name,
                                 uint8_t *     data,
                                 size_t        len,
                                 opcode_t      code)
{
        int id;
        cdap_t msg = CDAP__INIT;

        if (instance == NULL || name == NULL || data == NULL)
                return -1;

        id = next_invoke_id(instance);
        if (!bmp_is_id_valid(instance->ids, id))
                return -1;

        msg.opcode = code;
        msg.name = name;
        msg.invoke_id = id;
        msg.has_value = true;
        msg.value.data = data;
        msg.value.len = len;

        if (write_msg(instance, &msg))
                return -1;

        return id;
}

int cdap_send_read(struct cdap * instance,
                   char *        name)
{
        return send_read_or_start_or_stop(instance, name, OPCODE__READ);
}

int cdap_send_write(struct cdap * instance,
                    char *        name,
                    uint8_t *     data,
                    size_t        len,
                    uint32_t      flags)
{
        int id;
        cdap_t msg = CDAP__INIT;

        if (instance == NULL || name == NULL || data == NULL)
                return -1;

        id = next_invoke_id(instance);
        if (!bmp_is_id_valid(instance->ids, id))
                return -1;

        msg.opcode = OPCODE__WRITE;
        msg.name = name;
        msg.has_flags = true;
        msg.flags = flags;
        msg.invoke_id = id;
        msg.has_value = true;
        msg.value.data = data;
        msg.value.len = len;

        if (write_msg(instance, &msg))
                return -1;

        return id;
}

int cdap_send_create(struct cdap * instance,
                     char *        name,
                     uint8_t *     data,
                     size_t        len)
{
        return send_create_or_delete(instance, name, data, len, OPCODE__CREATE);
}

int cdap_send_delete(struct cdap * instance,
                     char *        name,
                     uint8_t *     data,
                     size_t        len)
{
        return send_create_or_delete(instance, name, data, len, OPCODE__DELETE);
}

int cdap_send_start(struct cdap * instance,
                    char *        name)
{
        return send_read_or_start_or_stop(instance, name, OPCODE__START);
}

int cdap_send_stop(struct cdap * instance,
                   char *        name)
{
        return send_read_or_start_or_stop(instance, name, OPCODE__STOP);
}

int cdap_send_reply(struct cdap * instance,
                    int           invoke_id,
                    int           result,
                    uint8_t *     data,
                    size_t        len)
{
        cdap_t msg = CDAP__INIT;

        if (instance == NULL)
                return -1;

        msg.opcode = OPCODE__REPLY;
        msg.invoke_id = invoke_id;
        msg.has_result = true;
        msg.result = result;

        if (data != NULL) {
                msg.has_value = true;
                msg.value.data = data;
                msg.value.len = len;
        }

        return write_msg(instance, &msg);
}
