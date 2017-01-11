/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The Common Application Connection Establishment Phase
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
#include <ouroboros/cacep.h>
#include <ouroboros/dev.h>
#include <ouroboros/errno.h>

#include <stdlib.h>
#include <string.h>

#include "cacep.pb-c.h"
typedef Cacep cacep_t;

#define BUF_SIZE 2048

struct cacep {
        int      fd;
        char *   name;
        uint64_t address;
};

struct cacep * cacep_create(int          fd,
                            const char * name,
                            uint64_t     address)
{
        struct cacep * tmp;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return NULL;

        tmp->fd = fd;
        tmp->address = address;
        tmp->name = strdup(name);
        if (tmp->name == NULL) {
                free(tmp);
                return NULL;
        }

        return tmp;
}

int cacep_destroy(struct cacep * instance)
{
        if (instance == NULL)
                return 0;

        free(instance);

        return 0;
}

static struct cacep_info * read_msg(struct cacep * instance)
{
        struct cacep_info * tmp;
        uint8_t             buf[BUF_SIZE];
        cacep_t *           msg;
        ssize_t             len;

        len = flow_read(instance->fd, buf, BUF_SIZE);
        if (len < 0)
                return NULL;

        msg = cacep__unpack(NULL, len, buf);
        if (msg == NULL)
                return NULL;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL) {
                cacep__free_unpacked(msg, NULL);
                return NULL;
        }

        tmp->addr = msg->address;
        tmp->name = strdup(msg->name);
        if (tmp->name == NULL) {
                free(tmp);
                cacep__free_unpacked(msg, NULL);
                return NULL;
        }

        cacep__free_unpacked(msg, NULL);

        return tmp;
}

static int send_msg(struct cacep * instance)
{
        cacep_t   msg = CACEP__INIT;
        int       ret = 0;
        uint8_t * data = NULL;
        size_t    len = 0;

        msg.name = instance->name;
        msg.address = instance->address;

        len = cacep__get_packed_size(&msg);
        if (len == 0)
                return -1;

        data = malloc(len);
        if (data == NULL)
                return -ENOMEM;

        cacep__pack(&msg, data);

        if (flow_write(instance->fd, data, len) < 0)
                ret = -1;

        free(data);

        return ret;
}

struct cacep_info * cacep_auth(struct cacep * instance)
{
        struct cacep_info * tmp;

        if (instance == NULL)
                return NULL;

        if (send_msg(instance))
                return NULL;

        tmp = read_msg(instance);
        if (tmp == NULL)
                return NULL;

        return tmp;
}

struct cacep_info * cacep_auth_wait(struct cacep * instance)
{
        struct cacep_info * tmp;

        if (instance == NULL)
                return NULL;

        tmp = read_msg(instance);
        if (tmp == NULL)
                return NULL;

        if (send_msg(instance)) {
                free(tmp->name);
                free(tmp);
                return NULL;
        }

        return tmp;
}
