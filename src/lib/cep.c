/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * The Ouroboros Connection Establishment Protocol
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#define _POSIX_C_SOURCE 199309L

#include <ouroboros/cep.h>
#include <ouroboros/dev.h>
#include <ouroboros/errno.h>

#include <stdlib.h>
#include <string.h>

#include "cep.pb-c.h"
typedef CepMsg cep_msg_t;

#define BUF_SIZE 128

static int read_msg(int                fd,
                    struct conn_info * info)
{
        uint8_t     buf[BUF_SIZE];
        cep_msg_t * msg;
        ssize_t     len;

        len = flow_read(fd, buf, BUF_SIZE);
        if (len < 0)
                return (int) len;

        msg = cep_msg__unpack(NULL, len, buf);
        if (msg == NULL)
                return -1;

        if (strlen(msg->comp_name) > OCEP_BUF_STRLEN) {
                cep_msg__free_unpacked(msg, NULL);
                return -1;
        }

        strcpy(info->comp_name, msg->comp_name);
        strcpy(info->protocol, msg->protocol);

        info->pref_version = msg->pref_version;
        info->pref_syntax  = msg->pref_syntax;
        info->addr         = msg->address;

        cep_msg__free_unpacked(msg, NULL);

        return 0;
}

static int send_msg(int                      fd,
                    const struct conn_info * info)
{
        cep_msg_t msg = CEP_MSG__INIT;
        uint8_t * data = NULL;
        size_t    len  = 0;

        msg.comp_name    = (char *) info->comp_name;
        msg.protocol     = (char *) info->protocol;
        msg.address      = info->addr;
        msg.pref_version = info->pref_version;
        msg.pref_syntax  = info->pref_syntax;
        if (msg.pref_syntax < 0)
                return -1;

        len = cep_msg__get_packed_size(&msg);
        if (len == 0)
                return -1;

        data = malloc(len);
        if (data == NULL)
                return -ENOMEM;

        cep_msg__pack(&msg, data);

        if (flow_write(fd, data, len) < 0) {
                free(data);
                return -1;
        }

        free(data);

        return 0;
}

int cep_snd(int                      fd,
            const struct conn_info * in)
{
        if (in == NULL)
                return -EINVAL;

        return send_msg(fd, in);
}

int cep_rcv(int                fd,
            struct conn_info * out)
{
        if (out == NULL)
                return -EINVAL;

        return read_msg(fd, out);
}
