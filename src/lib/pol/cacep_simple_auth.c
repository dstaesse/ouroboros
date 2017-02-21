/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Simple authentication policy for CACEP
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
#include <ouroboros/cacep.h>
#include <ouroboros/dev.h>
#include <ouroboros/errno.h>

#include "cacep_proto.h"
#include "cacep_simple_auth.h"

#include <stdlib.h>
#include <string.h>

#include "cacep_simple_auth.pb-c.h"
typedef CacepSimpleAuthMsg cacep_simple_auth_msg_t;
typedef CacepProtoMsg cacep_proto_msg_t;

#define BUF_SIZE 2048

static struct cacep_info * read_msg(int fd)
{
        struct cacep_info *       tmp;
        uint8_t                   buf[BUF_SIZE];
        cacep_simple_auth_msg_t * msg;
        ssize_t                   len;

        len = flow_read(fd, buf, BUF_SIZE);
        if (len < 0)
                return NULL;

        msg = cacep_simple_auth_msg__unpack(NULL, len, buf);
        if (msg == NULL)
                return NULL;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL) {
                cacep_simple_auth_msg__free_unpacked(msg, NULL);
                return NULL;
        }

        cacep_info_init(tmp);

        tmp->addr = msg->addr;
        tmp->name = strdup(msg->name);
        if (tmp->name == NULL) {
                free(tmp);
                cacep_simple_auth_msg__free_unpacked(msg, NULL);
                return NULL;
        }

        tmp->proto.protocol = strdup(msg->proto->protocol);
        if (tmp->proto.protocol == NULL) {
                free(tmp->name);
                free(tmp);
                cacep_simple_auth_msg__free_unpacked(msg, NULL);
                return NULL;
        }

        tmp->proto.pref_version = msg->proto->pref_version;
        tmp->proto.pref_syntax  = code_to_syntax(msg->proto->pref_syntax);
        if (tmp->proto.pref_syntax < 0) {
                cacep_info_fini(tmp);
                free(tmp);
                cacep_simple_auth_msg__free_unpacked(msg, NULL);
                return NULL;
        }

        cacep_simple_auth_msg__free_unpacked(msg, NULL);

        return tmp;
}

static int send_msg(int                       fd,
                    const struct cacep_info * info)
{
        cacep_simple_auth_msg_t msg  = CACEP_SIMPLE_AUTH_MSG__INIT;
        cacep_proto_msg_t       cmsg = CACEP_PROTO_MSG__INIT;
        int                     ret  = 0;
        uint8_t *               data = NULL;
        size_t                  len  = 0;

        cmsg.protocol     = info->proto.protocol;
        cmsg.pref_version = info->proto.pref_version;
        cmsg.pref_syntax  = syntax_to_code(info->proto.pref_syntax);
        if (cmsg.pref_syntax < 0)
                return -1;

        msg.proto = &cmsg;
        msg.name  = info->name;
        msg.addr  = info->addr;

        len = cacep_simple_auth_msg__get_packed_size(&msg);
        if (len == 0)
                return -1;

        data = malloc(len);
        if (data == NULL)
                return -ENOMEM;

        cacep_simple_auth_msg__pack(&msg, data);

        if (flow_write(fd, data, len) < 0)
                ret = -1;

        free(data);

        return ret;
}

struct cacep_info * cacep_simple_auth_auth(int                       fd,
                                           const struct cacep_info * info)
{
        struct cacep_info * tmp;

        assert(info);

        if (send_msg(fd, info))
                return NULL;

        tmp = read_msg(fd);
        if (tmp == NULL)
                return NULL;

        if (strcmp(info->proto.protocol, tmp->proto.protocol) ||
            info->proto.pref_version != tmp->proto.pref_version ||
            info->proto.pref_syntax != tmp->proto.pref_syntax) {
                cacep_info_fini(tmp);
                free(tmp);
                return NULL;
        }

        return tmp;
}


struct cacep_info * cacep_simple_auth_auth_wait(int                       fd,
                                                const struct cacep_info * info)
{
        struct cacep_info * tmp;

        assert(info);

        tmp = read_msg(fd);
        if (tmp == NULL)
                return NULL;

        if (send_msg(fd, info)) {
                cacep_info_fini(tmp);
                free(tmp);
                return NULL;
        }

        if (strcmp(info->proto.protocol, tmp->proto.protocol) ||
            info->proto.pref_version != tmp->proto.pref_version ||
            info->proto.pref_syntax != tmp->proto.pref_syntax) {
                cacep_info_fini(tmp);
                free(tmp);
                return NULL;
        }

        return tmp;
}
