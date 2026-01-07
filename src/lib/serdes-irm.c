/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Ouroboros IRM Protocol - serialization/deserialization
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

#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <ouroboros/crypt.h>
#include <ouroboros/errno.h>
#include <ouroboros/serdes-irm.h>
#include <ouroboros/protobuf.h>

#include <stdlib.h>
#include <string.h>

int flow_accept__irm_req_ser(buffer_t *               buf,
                             const struct flow_info * flow,
                             const struct timespec *  timeo)
{
        irm_msg_t * msg;
        size_t      len;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        irm_msg__init(msg);

        msg->code    = IRM_MSG_CODE__IRM_FLOW_ACCEPT;
        msg->flow_info = flow_info_s_to_msg(flow);
        if (msg->flow_info == NULL)
                goto fail_msg;

        msg->timeo = timeo == NULL ? NULL : timespec_s_to_msg(timeo);
        if (timeo != NULL && msg->timeo == NULL)
                goto fail_msg;

        len = irm_msg__get_packed_size(msg);
        if (len == 0 || len > buf->len)
                goto fail_msg;

        buf->len = len;

        irm_msg__pack(msg, buf->data);
        irm_msg__free_unpacked(msg, NULL);

        return 0;

 fail_msg:
        irm_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return -ENOMEM;
}

static int __flow_alloc_ser(buffer_t *               buf,
                            const struct flow_info * flow,
                            const char *             dst,
                            const struct timespec *  timeo,
                            int                      msg_code)
{
        irm_msg_t *     msg;
        size_t          len;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        irm_msg__init(msg);

        msg->code = msg_code;
        msg->flow_info = flow_info_s_to_msg(flow);
        if (msg->flow_info == NULL)
                goto fail_msg;

        msg->dst = strdup(dst);
        if (msg->dst == NULL)
                goto fail_msg;

        msg->timeo = timeo == NULL ? NULL : timespec_s_to_msg(timeo);
        if (timeo != NULL && msg->timeo == NULL)
                goto fail_msg;

        len = irm_msg__get_packed_size(msg);
        if (len == 0 || len > buf->len)
                goto fail_msg;

        buf->len = len;

        irm_msg__pack(msg, buf->data);
        irm_msg__free_unpacked(msg, NULL);

        return 0;

 fail_msg:
        irm_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return -ENOMEM;
}

int flow_alloc__irm_req_ser(buffer_t *               buf,
                            const struct flow_info * flow,
                            const char *             dst,
                            const struct timespec *  timeo)
{
        return __flow_alloc_ser(buf, flow, dst, timeo,
                                IRM_MSG_CODE__IRM_FLOW_ALLOC);
}

int flow_join__irm_req_ser(buffer_t *               buf,
                           const struct flow_info * flow,
                           const char *             dst,
                           const struct timespec *  timeo)
{
        return __flow_alloc_ser(buf, flow, dst, timeo,
                                IRM_MSG_CODE__IRM_FLOW_JOIN);
}

int flow__irm_result_des(buffer_t *          buf,
                         struct flow_info *  flow,
                         struct crypt_sk * sk)
{
        irm_msg_t * msg;
        int         err;

        msg = irm_msg__unpack(NULL, buf->len, buf->data);
        if (msg == NULL) {
                err = -EIRMD;
                goto fail_msg;
        }

        if (!msg->has_result) {
                err = -EIRMD;
                goto fail;
        }

        if (msg->result < 0) {
                err = msg->result;
                goto fail;
        }

        if (msg->flow_info == NULL) {
                err = -EBADF;
                goto fail;
        }

        *flow = flow_info_msg_to_s(msg->flow_info);

        if (msg->has_cipher_nid)
                sk->nid = msg->cipher_nid;
        else
                sk->nid = NID_undef;

        if (msg->sym_key.len == SYMMKEYSZ)
                memcpy(sk->key, msg->sym_key.data, SYMMKEYSZ);
        else
                memset(sk->key, 0, SYMMKEYSZ);

        irm_msg__free_unpacked(msg, NULL);

        return 0;
 fail:
        irm_msg__free_unpacked(msg, NULL);
 fail_msg:
        return err;
}

int flow_dealloc__irm_req_ser(buffer_t *               buf,
                              const struct flow_info * flow,
                              const struct timespec *  timeo)
{
        irm_msg_t * msg;
        size_t      len;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        irm_msg__init(msg);

        msg->code = IRM_MSG_CODE__IRM_FLOW_DEALLOC;
        msg->flow_info = flow_info_s_to_msg(flow);
        if (msg->flow_info == NULL)
                goto fail_msg;

        msg->timeo = timespec_s_to_msg(timeo);
        if (msg->timeo == NULL)
                goto fail_msg;

        len = irm_msg__get_packed_size(msg);
        if (len == 0 || len > buf->len)
                goto fail_msg;

        buf->len = len;

        irm_msg__pack(msg, buf->data);
        irm_msg__free_unpacked(msg, NULL);

        return 0;

 fail_msg:
        irm_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return -ENOMEM;
}

int ipcp_flow_dealloc__irm_req_ser(buffer_t *               buf,
                                   const struct flow_info * flow)
{
        irm_msg_t * msg;
        size_t      len;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        irm_msg__init(msg);

        msg->code = IRM_MSG_CODE__IPCP_FLOW_DEALLOC;
        msg->flow_info = flow_info_s_to_msg(flow);
        if (msg->flow_info == NULL)
                goto fail_msg;

        len = irm_msg__get_packed_size(msg);
        if (len == 0 || len > buf->len)
                goto fail_msg;

        buf->len = len;

        irm_msg__pack(msg, buf->data);
        irm_msg__free_unpacked(msg, NULL);

        return 0;
 fail_msg:
        irm_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return -ENOMEM;
}


int ipcp_create_r__irm_req_ser(buffer_t *               buf,
                               const struct ipcp_info * ipcp)
{
        irm_msg_t * msg;
        size_t      len;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        irm_msg__init(msg);

        msg->code       = IRM_MSG_CODE__IPCP_CREATE_R;
        msg->ipcp_info  = ipcp_info_s_to_msg(ipcp);
        if (msg->ipcp_info == NULL)
                goto fail_msg;

        len = irm_msg__get_packed_size(msg);
        if (len == 0 || len > buf->len)
                goto fail_msg;

        buf->len = len;

        irm_msg__pack(msg, buf->data);
        irm_msg__free_unpacked(msg, NULL);

        return 0;
 fail_msg:
        irm_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return -ENOMEM;
}

int proc_announce__irm_req_ser(buffer_t *   buf,
                               const char * prog)
{
        irm_msg_t * msg;
        size_t      len;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        irm_msg__init(msg);

        msg->code    = IRM_MSG_CODE__IRM_PROC_ANNOUNCE;
        msg->has_pid = true;
        msg->pid     = getpid();
        msg->prog    = strdup(prog);
        if (msg->prog == NULL)
                goto fail_msg;

        len = irm_msg__get_packed_size(msg);
        if (len == 0 || len > buf->len)
                goto fail_msg;

        buf->len = len;

        irm_msg__pack(msg, buf->data);
        irm_msg__free_unpacked(msg, NULL);

        return 0;
 fail_msg:
        irm_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return -ENOMEM;
}

int proc_exit__irm_req_ser(buffer_t *   buf)
{
        irm_msg_t * msg;
        size_t      len;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        irm_msg__init(msg);

        msg->code    = IRM_MSG_CODE__IRM_PROC_EXIT;
        msg->has_pid = true;
        msg->pid     = getpid();

        len = irm_msg__get_packed_size(msg);
        if (len == 0 || len > buf->len)
                goto fail_msg;

        buf->len = len;

        irm_msg__pack(msg, buf->data);
        irm_msg__free_unpacked(msg, NULL);

        return 0;
 fail_msg:
        irm_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return -ENOMEM;
}

int ipcp_flow_req_arr__irm_req_ser(buffer_t *               buf,
                                   const buffer_t *         dst,
                                   const struct flow_info * flow,
                                   const buffer_t *         data)
{
        irm_msg_t * msg;
        size_t      len;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        irm_msg__init(msg);

        msg->code      = IRM_MSG_CODE__IPCP_FLOW_REQ_ARR;
        msg->flow_info = flow_info_s_to_msg(flow);
        if (msg->flow_info == NULL)
                goto fail_msg;

        msg->has_hash  = true;
        msg->hash.len  = dst->len;
        msg->hash.data = dst->data;
        msg->has_pk    = true;
        msg->pk.len    = data->len;
        msg->pk.data   = data->data;

        len = irm_msg__get_packed_size(msg);
        if (len == 0 || len > buf->len)
                goto fail_msg;

        buf->len = len;

        irm_msg__pack(msg, buf->data);

        /* Don't free * dst or data! */
        msg->hash.len = 0;
        msg->hash.data = NULL;
        msg->pk.len = 0;
        msg->pk.data = NULL;
        irm_msg__free_unpacked(msg, NULL);

        return 0;
 fail_msg:
        irm_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return -ENOMEM;
}

int ipcp_flow_alloc_reply__irm_msg_ser(buffer_t *               buf,
                                       const struct flow_info * flow,
                                       int                      response,
                                       const buffer_t *         data)
{
        irm_msg_t * msg;
        size_t      len;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        irm_msg__init(msg);

        msg->code      = IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY;
        msg->flow_info = flow_info_s_to_msg(flow);
        if (msg->flow_info == NULL)
                goto fail_msg;

        msg->has_pk       = true;
        msg->pk.len       = data->len;
        msg->pk.data      = data->data;
        msg->has_response = true;
        msg->response     = response;

        len = irm_msg__get_packed_size(msg);
        if (len == 0 || len > buf->len)
                goto fail_msg;

        buf->len = len;

        irm_msg__pack(msg, buf->data);

        /* Don't free * data! */
        msg->pk.len = 0;
        msg->pk.data = NULL;

        irm_msg__free_unpacked(msg, NULL);

        return 0;
 fail_msg:
        irm_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return -ENOMEM;
}

int irm__irm_result_des(buffer_t * buf)
{
        irm_msg_t * msg;
        int         err;

        msg = irm_msg__unpack(NULL, buf->len, buf->data);
        if (msg == NULL) {
                err = -EIRMD;
                goto fail_msg;
        }

        if (!msg->has_result) {
                err = -EIRMD;
                goto fail;
        }

        err = msg->result;
 fail:
        irm_msg__free_unpacked(msg, NULL);
 fail_msg:
        return err;
}
