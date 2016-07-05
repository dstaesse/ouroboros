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

#include <ouroboros/cdap.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/common.h>
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


static ssize_t cdap_msg_to_buffer(cdap_t * msg,
                                  buffer_t ** val)
{
        int i;
        size_t len;

        len = msg->n_value;

        *val = malloc(len * sizeof(**val));
        if (*val == NULL) {
                return -1;
        }

        for (i = 0; i < len; i++) {
                if (msg->value[i].data == NULL) {
                        free(*val);
                        return -1;
                }

                (*val)[i].data = msg->value[i].data;
                (*val)[i].len = msg->value[i].len;
        }

        return len;
}


static void * sdu_reader(void * o)
{
        struct cdap * instance = (struct cdap *) o;
        cdap_t * msg;
        uint8_t buf[BUF_SIZE];
        size_t len;
        ssize_t length;
        buffer_t * val;

        while (true) {
                len = flow_read(instance->fd, buf, BUF_SIZE);
                if (len < 0) {
                        return (void *) -1;
                }

                msg = cdap__unpack(NULL, len, buf);
                if (msg == NULL) {
                        continue;
                }

                switch (msg->opcode) {
                case OPCODE__READ:
                        if (msg->name != NULL)
                                instance->ops->cdap_read(instance,
                                                         msg->name);
                        break;
                case OPCODE__WRITE:
                        length = cdap_msg_to_buffer(msg, &val);
                        if (msg->name != NULL &&
                            msg->value != NULL &&
                            len > 0) {
                                instance->ops->cdap_write(instance,
                                                          msg->name,
                                                          val,
                                                          length,
                                                          msg->flags);
                                free(val);
                        }
                        break;
                case OPCODE__CREATE:
                        length = cdap_msg_to_buffer(msg, &val);
                        if (msg->name != NULL &&
                            length == 1) {
                                instance->ops->cdap_create(instance,
                                                           msg->name,
                                                           val[0]);
                                free(val);
                        }
                        break;
                case OPCODE__DELETE:
                        length = cdap_msg_to_buffer(msg, &val);
                        if (msg->name != NULL &&
                            length == 1) {
                                instance->ops->cdap_create(instance,
                                                           msg->name,
                                                           val[0]);
                                free(val);
                        }
                        break;
                case OPCODE__START:
                        if (msg->name != NULL)
                                instance->ops->cdap_start(instance,
                                                          msg->name);
                        break;
                case OPCODE__STOP:
                        if (msg->name != NULL)
                                instance->ops->cdap_stop(instance,
                                                         msg->name);
                        break;
                case OPCODE__REPLY:
                        length = cdap_msg_to_buffer(msg, &val);
                        if (msg->name != NULL &&
                            length > 0) {
                                instance->ops->cdap_reply(instance,
                                                          msg->invoke_id,
                                                          msg->result,
                                                          val,
                                                          length);
                                free(val);
                        }
                        break;
                default:
                        break;
                }

                cdap__free_unpacked(msg, NULL);
        }

        return (void *) 0;
}

struct cdap * cdap_create(struct cdap_ops * ops,
                          int               fd)
{
        struct cdap * instance = NULL;

        if (ops == NULL || fd < 0 ||
            ops->cdap_reply == NULL ||
            ops->cdap_read == NULL ||
            ops->cdap_write == NULL ||
            ops->cdap_create == NULL ||
            ops->cdap_delete == NULL ||
            ops->cdap_start == NULL ||
            ops->cdap_stop == NULL)
                return NULL;

        instance = malloc(sizeof(*instance));
        if (instance == NULL)
                return NULL;

        if (pthread_mutex_init(&instance->ids_lock, NULL)) {
                free(instance);
                return NULL;
        }

        instance->ops = ops;

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

        pthread_mutex_lock(&instance->ids_lock);

        bmp_destroy(instance->ids);

        pthread_mutex_unlock(&instance->ids_lock);

        pthread_join(instance->reader,
                     NULL);

        free(instance);

        return 0;
}

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

static int write_msg(struct cdap * instance,
                     cdap_t * msg)
{
        buffer_t buf;

        buf.len = cdap__get_packed_size(msg);
        if (buf.len == 0) {
                return -1;
        }

        cdap__pack(msg, buf.data);

        return flow_write(instance->fd, buf.data, buf.len);
}

static int buffer_to_cdap_msg(cdap_t * msg,
                              buffer_t * val,
                              size_t len)
{
        int i;

        msg->value = malloc(len * sizeof(*msg->value));
        if (msg->value == NULL) {
                return -1;
        }

        msg->n_value = len;
        for (i = 0; i < len; i++) {
                if (val[i].data == NULL) {
                        free(msg->value);
                        return -1;
                }

                msg->value[i].data = val[i].data;
                msg->value[i].len = val[i].len;
        }

        return 0;
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

        return write_msg(instance, &msg);
}

static int send_create_or_delete(struct cdap * instance,
                                 char *        name,
                                 buffer_t      val,
                                 opcode_t      code)
{
        int id;
        cdap_t msg = CDAP__INIT;
        int ret;

        if (instance == NULL || name == NULL)
                return -1;

        id = next_invoke_id(instance);
        if (!bmp_is_id_valid(instance->ids, id))
                return -1;

        msg.opcode = code;
        msg.name = name;
        msg.invoke_id = id;

        if (buffer_to_cdap_msg(&msg, &val, 1)) {
                release_invoke_id(instance, id);
                return -1;
        }

        ret = write_msg(instance, &msg);

        free(msg.value);

        return ret;
}

int cdap_send_read(struct cdap * instance,
                   char *        name)
{
        return send_read_or_start_or_stop(instance, name, OPCODE__READ);
}

int cdap_send_write(struct cdap * instance,
                    char *        name,
                    buffer_t *    val,
                    size_t        len,
                    uint32_t      flags)
{
        int id;
        int ret;
        cdap_t msg = CDAP__INIT;

        if (instance == NULL || name == NULL ||
            val == NULL || len < 1)
                return -1;

        id = next_invoke_id(instance);
        if (!bmp_is_id_valid(instance->ids, id))
                return -1;

        msg.opcode = OPCODE__WRITE;
        msg.name = name;
        msg.has_flags = true;
        msg.flags = flags;
        msg.invoke_id = id;

        if (buffer_to_cdap_msg(&msg, val, len)) {
                release_invoke_id(instance, id);
                return -1;
        }

        ret = write_msg(instance, &msg);

        free(msg.value);

        return ret;
}

int cdap_send_create(struct cdap * instance,
                     char *        name,
                     buffer_t      val)
{
        return send_create_or_delete(instance, name, val, OPCODE__CREATE);
}

int cdap_send_delete(struct cdap * instance,
                     char *        name,
                     buffer_t      val)
{
        return send_create_or_delete(instance, name, val, OPCODE__DELETE);
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
                    buffer_t *    val,
                    size_t        len)
{
        cdap_t msg = CDAP__INIT;

        if (instance == NULL || val == NULL)
                return -1;

        msg.invoke_id = invoke_id;
        msg.has_result = true;
        msg.result = result;

        if (buffer_to_cdap_msg(&msg, val, len)) {
                return -1;
        }

        return write_msg(instance, &msg);
}
