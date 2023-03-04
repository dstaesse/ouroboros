/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Ouroboros Enrollment Protocol - serialization/deserialization
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#define _POSIX_C_SOURCE 200112L

#include <ouroboros/protobuf.h>
#include <ouroboros/serdes-oep.h>


ssize_t enroll_req_ser(buffer_t buf)
{
        enroll_req_msg_t * msg;
        ssize_t            sz;

        msg = enroll_req_s_to_msg();
        if (msg == NULL)
                goto fail_msg;

        sz = enroll_req_msg__get_packed_size(msg);
        if (sz < 0 || (size_t) sz > buf.len)
                goto fail_pack;

        enroll_req_msg__pack(msg, buf.data);

        enroll_req_msg__free_unpacked(msg, NULL);

        return sz;

 fail_pack:
    enroll_req_msg__free_unpacked(msg, NULL);
 fail_msg:
    return -1;
}

int enroll_req_des(const buffer_t buf)
{
        enroll_req_msg_t * msg;

        msg = enroll_req_msg__unpack(NULL, buf.len, buf.data);
        if (msg == NULL)
                return -1;

        /* Nothing in request yet, if it unpacks, it's good. */

        enroll_req_msg__free_unpacked(msg, NULL);

        return 0;
}

ssize_t enroll_resp_ser(const struct enroll_resp * resp,
                        buffer_t                   buf)
{
        enroll_resp_msg_t * msg;
        ssize_t             sz;

        msg = enroll_resp_s_to_msg(resp);
        if (msg == NULL)
                goto fail_msg;

        sz = enroll_resp_msg__get_packed_size(msg);
        if (sz < 0 || (size_t) sz > buf.len)
                goto fail_pack;

        msg->t_sec = resp->t.tv_sec;
        msg->t_nsec = resp->t.tv_nsec;

        enroll_resp_msg__pack(msg, buf.data);

        enroll_resp_msg__free_unpacked(msg, NULL);

        return sz;

 fail_pack:
        enroll_resp_msg__free_unpacked(msg, NULL);
 fail_msg:
        return -1;
}

int enroll_resp_des(struct enroll_resp * resp,
                    const buffer_t       buf)
{
        enroll_resp_msg_t * msg;

        msg = enroll_resp_msg__unpack(NULL, buf.len, buf.data);
        if (msg == NULL)
                return -1;

        *resp = enroll_resp_msg_to_s(msg);

        enroll_resp_msg__free_unpacked(msg, NULL);

        return 0;
}

ssize_t enroll_ack_ser(const int response,
                       buffer_t  buf)
{
        enroll_ack_msg_t * msg;
        ssize_t            sz;

        msg = enroll_ack_s_to_msg(response);
        if (msg == NULL)
                goto fail_msg;

        sz = enroll_ack_msg__get_packed_size(msg);
        if (sz < 0 || (size_t) sz > buf.len)
                goto fail_pack;

        enroll_ack_msg__pack(msg, buf.data);

        enroll_ack_msg__free_unpacked(msg, NULL);

        return sz;

 fail_pack:
        enroll_ack_msg__free_unpacked(msg, NULL);
 fail_msg:
        return -1;

}

int enroll_ack_des(int *          response,
                   const buffer_t buf)
{
        enroll_ack_msg_t * msg;

        msg = enroll_ack_msg__unpack(NULL, buf.len, buf.data);
        if (msg == NULL)
                return -1;

        *response = enroll_ack_msg_to_s(msg);

        enroll_ack_msg__free_unpacked(msg, NULL);

        return 0;
}