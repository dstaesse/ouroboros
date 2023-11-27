/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Protobuf syntax conversion
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

#define _DEFAULT_SOURCE

#include <ouroboros/protobuf.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

layer_info_msg_t * layer_info_s_to_msg(const struct layer_info * s)
{
        layer_info_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        layer_info_msg__init(msg);

        msg->name = strdup(s->name);
        if (msg->name == NULL)
                goto fail_msg;

        msg->dir_hash_algo  = s->dir_hash_algo;

        return msg;

 fail_msg:
        layer_info_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

struct layer_info layer_info_msg_to_s(const layer_info_msg_t * msg)
{
        struct layer_info s;

        assert(msg != NULL);
        assert(strlen(msg->name) <= LAYER_NAME_SIZE);

        s.dir_hash_algo = msg->dir_hash_algo;
        strcpy(s.name, msg->name);

        return s;
}

dt_config_msg_t * dt_config_s_to_msg(const struct dt_config * s)
{
        dt_config_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                return NULL;

        dt_config_msg__init(msg);

        msg->addr_size    = s->addr_size;
        msg->eid_size     = s->eid_size;
        msg->max_ttl      = s->max_ttl;
        msg->routing_type = s->routing_type;

        return msg;
}

struct dt_config dt_config_msg_to_s(const dt_config_msg_t * msg)
{
        struct dt_config s;

        assert(msg != NULL);

        s.addr_size    = msg->addr_size;
        s.eid_size     = msg->eid_size;
        s.max_ttl      = msg->max_ttl;
        s.routing_type = msg->routing_type;

        return s;
}

uni_config_msg_t * uni_config_s_to_msg(const struct uni_config * s)
{
        uni_config_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        uni_config_msg__init(msg);

        msg->dt = dt_config_s_to_msg(&s->dt);
        if (msg->dt == NULL)
                goto fail_msg;

        msg->addr_auth_type = s->addr_auth_type;
        msg->cong_avoid     = s->cong_avoid;

        return msg;

 fail_msg:
        uni_config_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

struct uni_config uni_config_msg_to_s(const uni_config_msg_t * msg)
{
        struct uni_config s;

        s.dt = dt_config_msg_to_s(msg->dt);

        s.addr_auth_type  = msg->addr_auth_type;
        s.cong_avoid      = msg->cong_avoid;

        return s;
}

udp_config_msg_t * udp_config_s_to_msg(const struct udp_config * s)
{
        udp_config_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                return NULL;

        udp_config_msg__init(msg);

        msg->ip_addr  = s->ip_addr;
        msg->dns_addr = s->dns_addr;
        msg->port     = s->port;

        return msg;
}

struct udp_config udp_config_msg_to_s(const udp_config_msg_t * msg)
{
        struct udp_config s;

        assert(msg != NULL);

        s.ip_addr  = msg->ip_addr;
        s.dns_addr = msg->dns_addr;
        s.port     = msg->port;

        return s;
}

eth_config_msg_t * eth_config_s_to_msg(const struct eth_config * s)
{
        eth_config_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        eth_config_msg__init(msg);

        msg->dev = strdup(s->dev);
        if (msg->dev == NULL)
                goto fail_msg;

        msg->ethertype = s->ethertype;

        return msg;

 fail_msg:
        eth_config_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

struct eth_config eth_config_msg_to_s(const eth_config_msg_t * msg)
{
        struct eth_config s;

        assert(msg != NULL);
        assert(strlen(msg->dev) <= DEV_NAME_SIZE);

        strcpy(s.dev, msg->dev);
        s.ethertype = msg->ethertype;

        return s;
}


ipcp_config_msg_t * ipcp_config_s_to_msg(const struct ipcp_config * s)
{
        ipcp_config_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        ipcp_config_msg__init(msg);

        switch (s->type) {
        case IPCP_LOCAL:
                break;
        case IPCP_UNICAST:
                msg->unicast = uni_config_s_to_msg(&s->unicast);
                if (msg->unicast == NULL)
                        goto fail_msg;
                break;
        case IPCP_BROADCAST:
                break;
        case IPCP_ETH_LLC:
                /* FALLTHRU */
        case IPCP_ETH_DIX:
                msg->eth = eth_config_s_to_msg(&s->eth);
                if (msg->eth == NULL)
                        goto fail_msg;
                break;
        case IPCP_UDP:
                msg->udp = udp_config_s_to_msg(&s->udp);
                if (msg->udp == NULL)
                        goto fail_msg;
                break;
        default:
                /* No checks here */
                break;
        }

        msg->ipcp_type = s->type;

        msg->layer_info = layer_info_s_to_msg(&s->layer_info);
        if (msg->layer_info == NULL)
                goto fail_msg;

        return msg;

 fail_msg:
        ipcp_config_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

struct ipcp_config ipcp_config_msg_to_s(const ipcp_config_msg_t * msg)
{
        struct ipcp_config s;

        assert(msg != NULL);

        s.type = msg->ipcp_type;

        s.layer_info = layer_info_msg_to_s(msg->layer_info);

        switch(msg->ipcp_type) {
        case IPCP_LOCAL:
                break;
        case IPCP_UNICAST:
                s.unicast = uni_config_msg_to_s(msg->unicast);
                break;
        case IPCP_ETH_LLC:
                /* FALLTHRU */
        case IPCP_ETH_DIX:
                s.eth = eth_config_msg_to_s(msg->eth);
                break;
        case IPCP_UDP:
                s.udp = udp_config_msg_to_s(msg->udp);
                break;
        case IPCP_BROADCAST:
                break;
        default:
                /* No checks here */
                break;
        }

        return s;
}

qosspec_msg_t * qos_spec_s_to_msg(const struct qos_spec * s)
{
        qosspec_msg_t  * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                return NULL;

        qosspec_msg__init(msg);

        msg->delay        = s->delay;
        msg->bandwidth    = s->bandwidth;
        msg->availability = s->availability;
        msg->loss         = s->loss;
        msg->ber          = s->ber;
        msg->in_order     = s->in_order;
        msg->max_gap      = s->max_gap;
        msg->cypher_s     = s->cypher_s;
        msg->timeout      = s->timeout;

        return msg;
}

struct qos_spec qos_spec_msg_to_s(const qosspec_msg_t * msg)
{
        struct qos_spec s;

        assert(msg != NULL);

        s.delay        = msg->delay;
        s.bandwidth    = msg->bandwidth;
        s.availability = msg->availability;
        s.loss         = msg->loss;
        s.ber          = msg->ber;
        s.in_order     = msg->in_order;
        s.max_gap      = msg->max_gap;
        s.cypher_s     = msg->cypher_s;
        s.timeout      = msg->timeout;

        return s;
}

enroll_req_msg_t * enroll_req_s_to_msg(const struct enroll_req * s)
{
        enroll_req_msg_t * msg;
        uint8_t *          id;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_msg;

        id = malloc(ENROLL_ID_LEN);
        if (id == NULL)
                goto fail_id;

        memcpy(id, s->id, ENROLL_ID_LEN);

        enroll_req_msg__init(msg);

        msg->id.len  = ENROLL_ID_LEN;
        msg->id.data = id;

        return msg;

 fail_id:
        free(msg);
 fail_msg:
        return NULL;
}

struct enroll_req enroll_req_msg_to_s(const enroll_req_msg_t * msg)
{
        struct enroll_req s;

        assert(msg != NULL);

        memcpy(s.id, msg->id.data, ENROLL_ID_LEN);

        return s;
}

enroll_resp_msg_t * enroll_resp_s_to_msg(const struct enroll_resp * s)
{
        enroll_resp_msg_t * msg;
        uint8_t *           id;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_msg;

        id = malloc(ENROLL_ID_LEN);
        if (id == NULL)
                goto fail_id;

        memcpy(id, s->id, ENROLL_ID_LEN);

        enroll_resp_msg__init(msg);

        msg->id.len   = ENROLL_ID_LEN;
        msg->id.data  = id;

        msg->t_sec    = s->t.tv_sec;
        msg->t_nsec   = s->t.tv_nsec;
        msg->response = s->response;
        if (msg->response < 0)
                return msg;

        msg->conf = ipcp_config_s_to_msg(&s->conf);
        if (msg->conf == NULL)
                goto fail_id;

        return msg;

 fail_id:
        enroll_resp_msg__free_unpacked(msg, NULL);
 fail_msg:
        return NULL;
}

struct enroll_resp enroll_resp_msg_to_s(const enroll_resp_msg_t * msg)
{
        struct enroll_resp s;

        assert (msg != NULL);

        s.response = msg->response;
        if (s.response >= 0)
                s.conf = ipcp_config_msg_to_s(msg->conf);

        s.t.tv_sec  = msg->t_sec;
        s.t.tv_nsec = msg->t_nsec;

        memcpy(s.id, msg->id.data, ENROLL_ID_LEN);

        return s;
}

enroll_ack_msg_t * enroll_ack_s_to_msg(const struct enroll_ack * s)
{
        enroll_ack_msg_t * msg;
        uint8_t *          id;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_msg;

        id = malloc(ENROLL_ID_LEN);
        if (id == NULL)
                goto fail_id;

        memcpy(id, s->id, ENROLL_ID_LEN);

        enroll_ack_msg__init(msg);

        msg->id.len   = ENROLL_ID_LEN;
        msg->id.data  = id;

        msg->result = s->result;

        return msg;

 fail_id:
        enroll_ack_msg__free_unpacked(msg, NULL);
 fail_msg:
        return NULL;
}

struct enroll_ack enroll_ack_msg_to_s(const enroll_ack_msg_t * msg)
{
        struct enroll_ack s;

        assert(msg != NULL);

        memcpy(s.id, msg->id.data, ENROLL_ID_LEN);

        s.result = msg->result;

        return s;
}
