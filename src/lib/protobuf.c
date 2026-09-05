/*
 * Ouroboros - Copyright (C) 2016 - 2026
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

#include <ouroboros/errno.h>
#include <ouroboros/protobuf.h>
#include <ouroboros/crypt.h>
#include <ouroboros/proc.h>

#include <stdlib.h>
#include <string.h>
#include <time.h>

timespec_msg_t * timespec_s_to_msg(const struct timespec * s)
{
        timespec_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        timespec_msg__init(msg);

        msg->tv_sec  = s->tv_sec;
        msg->tv_nsec = s->tv_nsec;

        return msg;

 fail_malloc:
        return NULL;
}

struct timespec timespec_msg_to_s(timespec_msg_t * msg)
{
        struct timespec s;

        assert(msg != NULL);

        s.tv_sec  = msg->tv_sec;
        s.tv_nsec = msg->tv_nsec;

        return s;
}

flow_info_msg_t * flow_info_s_to_msg(const struct flow_info * s)
{
        flow_info_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        flow_info_msg__init(msg);

        msg->id       = s->id;
        msg->n_pid    = s->n_pid;
        msg->n_1_pid  = s->n_1_pid;
        msg->mpl      = s->mpl;
        msg->state    = s->state;
        msg->uid      = s->uid;
        msg->mtu      = s->mtu;
        msg->max_rtt  = s->max_rtt;
        msg->qos      = qos_spec_s_to_msg(&s->qs);
        if (msg->qos == NULL)
                goto fail_msg;

        return msg;

 fail_msg:
        flow_info_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

struct flow_info flow_info_msg_to_s(const flow_info_msg_t * msg)
{
        struct flow_info s;

        assert(msg != NULL);

        memset(&s, 0, sizeof(s));

        s.id      = msg->id;
        s.n_pid   = msg->n_pid;
        s.n_1_pid = msg->n_1_pid;
        s.mpl     = msg->mpl;
        s.state   = msg->state;
        s.uid     = msg->uid;
        s.mtu     = msg->mtu;
        s.max_rtt = msg->max_rtt;
        s.qs      = qos_spec_msg_to_s(msg->qos);

        return s;
}

name_info_msg_t * name_info_s_to_msg(const struct name_info * info)
{
        name_info_msg_t * msg;

        assert(info != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        name_info_msg__init(msg);

        msg->name = strdup(info->name);
        if (msg->name == NULL)
                goto fail_msg;

        msg->skey = strdup(info->s.key);
        if (msg->skey == NULL)
                goto fail_msg;

        msg->scrt = strdup(info->s.crt);
        if (msg->scrt == NULL)
                goto fail_msg;

        msg->ckey = strdup(info->c.key);
        if (msg->ckey == NULL)
                goto fail_msg;

        msg->ccrt = strdup(info->c.crt);
        if (msg->ccrt == NULL)
                goto fail_msg;

        msg->pol_lb  = info->pol_lb;

        return msg;

 fail_msg:
        name_info_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

struct name_info name_info_msg_to_s(const name_info_msg_t * msg)
{
        struct name_info s;

        assert(msg != NULL);
        assert(strlen(msg->name) <= NAME_SIZE);

        memset(&s, 0, sizeof(s));

        strcpy(s.name, msg->name);
        strcpy(s.s.key, msg->skey);
        strcpy(s.s.crt, msg->scrt);
        strcpy(s.c.key, msg->ckey);
        strcpy(s.c.crt, msg->ccrt);

        s.pol_lb = msg->pol_lb;

        return s;
}

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


static bool mac_is_zero(const uint8_t * mac)
{
        static const uint8_t zero[POA_MAC_SIZE] = { 0 };

        return memcmp(mac, zero, POA_MAC_SIZE) == 0;
}

poa_addr_msg_t * poa_addr_s_to_msg(const struct poa_addr * s)
{
        poa_addr_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        poa_addr_msg__init(msg);

        msg->type = s->type;

        if (s->hostname[0] != '\0') {
                msg->hostname = strdup(s->hostname);
                if (msg->hostname == NULL)
                        goto fail_msg;
        }

        switch (s->type) {
        case POA_UDP4:
                msg->has_ip4  = true;
                msg->ip4      = s->udp4.ip_addr.s_addr;
                msg->has_port = true;
                msg->port     = s->udp4.port;
                break;
        case POA_UDP6:
                msg->has_ip6  = true;
                msg->ip6.len  = sizeof(s->udp6.ip_addr);
                msg->ip6.data = malloc(msg->ip6.len);
                if (msg->ip6.data == NULL)
                        goto fail_msg;
                memcpy(msg->ip6.data, &s->udp6.ip_addr, msg->ip6.len);

                msg->has_port = true;
                msg->port     = s->udp6.port;
                break;
        case POA_ETH:
                msg->has_ethertype = true;
                msg->ethertype     = s->eth.dst.ethertype;
                msg->has_mac  = true;
                msg->mac.len  = POA_MAC_SIZE;
                msg->mac.data = malloc(POA_MAC_SIZE);
                if (msg->mac.data == NULL)
                        goto fail_msg;
                memcpy(msg->mac.data, s->eth.dst.mac, POA_MAC_SIZE);

                if (!mac_is_zero(s->eth.src.mac)) {
                        msg->has_src_mac  = true;
                        msg->src_mac.len  = POA_MAC_SIZE;
                        msg->src_mac.data = malloc(POA_MAC_SIZE);
                        if (msg->src_mac.data == NULL)
                                goto fail_msg;
                        memcpy(msg->src_mac.data, s->eth.src.mac, POA_MAC_SIZE);
                }

                if (s->eth.src.dev[0] != '\0') {
                        msg->dev = strdup(s->eth.src.dev);
                        if (msg->dev == NULL)
                                goto fail_msg;
                }
                break;
        case POA_UDP:
                msg->has_port = true;
                msg->port     = s->udp4.port;
                break;
        default:
                goto fail_msg;
        }

        return msg;

 fail_msg:
        poa_addr_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

struct poa_addr poa_addr_msg_to_s(const poa_addr_msg_t * msg)
{
        struct poa_addr s;

        assert(msg != NULL);

        memset(&s, 0, sizeof(s));

        s.type = POA_INVALID;

        if (msg->hostname != NULL) {
                if (strlen(msg->hostname) > POA_HOST_STRLEN)
                        return s;
                strcpy(s.hostname, msg->hostname);
        }

        switch (msg->type) {
        case POA_UDP4:
                if (!msg->has_ip4 || !msg->has_port)
                        return s;

                s.udp4.ip_addr.s_addr = msg->ip4;
                s.udp4.port      = msg->port;
                break;
        case POA_UDP6:
                if (!msg->has_ip6 || !msg->has_port)
                        return s;

                if (msg->ip6.len != sizeof(s.udp6.ip_addr)
                    || msg->ip6.data == NULL)
                        return s;

                memcpy(&s.udp6.ip_addr, msg->ip6.data, msg->ip6.len);

                s.udp6.port = msg->port;
                break;
        case POA_ETH:
                if (!msg->has_ethertype)
                        return s;

                s.eth.src.ethertype = msg->ethertype;
                s.eth.dst.ethertype = msg->ethertype;

                if (msg->mac.len != POA_MAC_SIZE || msg->mac.data == NULL)
                        return s;

                memcpy(s.eth.dst.mac, msg->mac.data, POA_MAC_SIZE);

                if (msg->src_mac.len == POA_MAC_SIZE)
                        memcpy(s.eth.src.mac, msg->src_mac.data, POA_MAC_SIZE);

                if (msg->dev != NULL) {
                        if (strlen(msg->dev) > DEV_NAME_SIZE)
                                return s;
                        strcpy(s.eth.src.dev, msg->dev);
                }
                break;
        case POA_UDP:
                if (msg->hostname == NULL || msg->hostname[0] == '\0'
                    || !msg->has_port)
                        return s;

                s.udp4.port = msg->port;
                break;
        default:
                return s;
        }

        s.type = msg->type;

        return s;
}

ipcp_info_msg_t * ipcp_info_s_to_msg(const struct ipcp_info * s)
{
        ipcp_info_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        ipcp_info_msg__init(msg);

        msg->name = strdup(s->name);
        if (msg->name == NULL)
                goto fail_msg;

        msg->type  = s->type;
        msg->pid   = s->pid;
        msg->state = s->state;
        msg->flags = s->flags;

        return msg;
 fail_msg:
        ipcp_info_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

struct ipcp_info ipcp_info_msg_to_s(const ipcp_info_msg_t * msg)
{
        struct ipcp_info s;

        assert(msg != NULL);
        assert(msg->name != NULL);
        assert(strlen(msg->name) <= NAME_SIZE);

        strcpy(s.name, msg->name);

        s.type  = msg->type;
        s.pid   = msg->pid;
        s.state = msg->state;
        s.flags = msg->flags;

        return s;
}

ls_config_msg_t * ls_config_s_to_msg(const struct ls_config * s)
{
        ls_config_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        ls_config_msg__init(msg);

        msg->pol      = s->pol;
        msg->t_recalc = s->t_recalc;
        msg->t_update = s->t_update;
        msg->t_timeo  = s->t_timeo;

        return msg;

 fail_malloc:
        return NULL;
}

struct ls_config ls_config_msg_to_s(const ls_config_msg_t * msg)
{
        struct ls_config s;

        assert(msg != NULL);

        s.pol      = msg->pol;
        s.t_recalc = msg->t_recalc;
        s.t_update = msg->t_update;
        s.t_timeo  = msg->t_timeo;

        return s;
}

routing_config_msg_t * routing_config_s_to_msg(const struct routing_config * s)
{
        routing_config_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                return NULL;

        routing_config_msg__init(msg);

        switch (s->pol) {
        case ROUTING_LINK_STATE:
                msg->ls = ls_config_s_to_msg(&s->ls);
                if (msg->ls == NULL)
                        goto fail_ls;
                break;
        default:
                /* No checks here */
                break;
        }

        msg->pol = s->pol;

        return msg;

 fail_ls:
        routing_config_msg__free_unpacked(msg, NULL);
        return NULL;
}

struct routing_config routing_config_msg_to_s(const routing_config_msg_t * msg)
{
        struct routing_config s;

        assert(msg != NULL);

        switch (msg->pol) {
        case ROUTING_LINK_STATE:
                s.ls = ls_config_msg_to_s(msg->ls);
                break;
        default:
                /* No checks here */
                break;
        }

        s.pol = msg->pol;

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
        msg->has_max_rtt  = true;
        msg->max_rtt      = s->max_rtt;
        msg->routing      = routing_config_s_to_msg(&s->routing);
        if (msg->routing == NULL)
                goto fail_routing;

        return msg;
 fail_routing:
        dt_config_msg__free_unpacked(msg, NULL);
        return NULL;
}

struct dt_config dt_config_msg_to_s(const dt_config_msg_t * msg)
{
        struct dt_config s;

        assert(msg != NULL);

        s.addr_size    = msg->addr_size;
        s.eid_size     = msg->eid_size;
        s.max_ttl      = msg->max_ttl;
        s.max_rtt      = msg->has_max_rtt ? msg->max_rtt : 200; /* ms       */
        s.routing      = routing_config_msg_to_s(msg->routing);

        return s;
}

dir_dht_config_msg_t * dir_dht_config_s_to_msg(const struct dir_dht_config * s)
{
        dir_dht_config_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                return NULL;

        dir_dht_config_msg__init(msg);

        msg->alpha       = s->params.alpha;
        msg->k           = s->params.k;
        msg->t_expire    = s->params.t_expire;
        msg->t_refresh   = s->params.t_refresh;
        msg->t_replicate = s->params.t_replicate;
        msg->peer        = s->peer;

        return msg;
}

struct dir_dht_config dir_dht_config_msg_to_s(const dir_dht_config_msg_t * msg)
{
        struct dir_dht_config s;

        assert(msg != NULL);

        s.params.alpha       = msg->alpha;
        s.params.k           = msg->k;
        s.params.t_expire    = msg->t_expire;
        s.params.t_refresh   = msg->t_refresh;
        s.params.t_replicate = msg->t_replicate;
        s.peer               = msg->peer;

        return s;
}

dir_config_msg_t * dir_config_s_to_msg(const struct dir_config * s)
{
        dir_config_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                return NULL;

        dir_config_msg__init(msg);

        switch (s->pol) {
        case DIR_DHT:
                msg->dht = dir_dht_config_s_to_msg(&s->dht);
                if (msg->dht == NULL)
                        goto fail_msg;
                break;
        default:
                /* No checks here */
                break;
        }

        msg->pol = s->pol;

        return msg;

 fail_msg:
        dir_config_msg__free_unpacked(msg, NULL);
        return NULL;
}

struct dir_config dir_config_msg_to_s(const dir_config_msg_t * msg)
{
        struct dir_config s;

        assert(msg != NULL);

        switch (msg->pol) {
        case DIR_DHT:
                s.dht = dir_dht_config_msg_to_s(msg->dht);
                break;
        default:
                /* No checks here */
                break;
        }

        s.pol = msg->pol;

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

        msg->dir = dir_config_s_to_msg(&s->dir);
        if (msg->dir == NULL)
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
        s.dir = dir_config_msg_to_s(msg->dir);

        s.addr_auth_type  = msg->addr_auth_type;
        s.cong_avoid      = msg->cong_avoid;

        return s;
}

udp4_poa_msg_t * udp4_poa_s_to_msg(const struct udp4_poa * s)
{
        udp4_poa_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                return NULL;

        udp4_poa_msg__init(msg);

        msg->ip_addr = s->ip_addr.s_addr;
        msg->port    = s->port;

        return msg;
}

struct udp4_poa udp4_poa_msg_to_s(const udp4_poa_msg_t * msg)
{
        struct udp4_poa s;

        assert(msg != NULL);

        s.ip_addr.s_addr = msg->ip_addr;
        s.port           = msg->port;

        return s;
}

#define IN6_LEN (size_t) sizeof(struct in6_addr)
udp6_poa_msg_t * udp6_poa_s_to_msg(const struct udp6_poa * s)
{
        udp6_poa_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        udp6_poa_msg__init(msg);

        msg->ip_addr.data = malloc(IN6_LEN);
        if (msg->ip_addr.data == NULL)
                goto fail_msg;

        msg->ip_addr.len = IN6_LEN;
        memcpy(msg->ip_addr.data, &s->ip_addr.s6_addr, IN6_LEN);

        msg->port = s->port;

        return msg;

 fail_msg:
        udp6_poa_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

struct udp6_poa udp6_poa_msg_to_s(const udp6_poa_msg_t * msg)
{
        struct udp6_poa s;

        assert(msg != NULL);

        assert(msg->ip_addr.len == IN6_LEN);

        memcpy(&s.ip_addr.s6_addr, msg->ip_addr.data, IN6_LEN);
        s.port = msg->port;

        return s;
}

eth_poa_msg_t * eth_poa_s_to_msg(const struct eth_poa * s)
{
        eth_poa_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        eth_poa_msg__init(msg);

        msg->dev = strdup(s->dev);
        if (msg->dev == NULL)
                goto fail_msg;

        msg->ethertype = s->ethertype;

        msg->has_mac = true;
        msg->mac.len = POA_MAC_SIZE;
        msg->mac.data = malloc(POA_MAC_SIZE);
        if (msg->mac.data == NULL)
                goto fail_msg;

        memcpy(msg->mac.data, s->mac, POA_MAC_SIZE);

        return msg;

 fail_msg:
        eth_poa_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

struct eth_poa eth_poa_msg_to_s(const eth_poa_msg_t * msg)
{
        struct eth_poa s;

        assert(msg != NULL);
        assert(strlen(msg->dev) <= DEV_NAME_SIZE);

        memset(&s, 0, sizeof(s));

        strcpy(s.dev, msg->dev);

        s.ethertype = msg->ethertype;

        if (msg->mac.len == POA_MAC_SIZE)
                memcpy(s.mac, msg->mac.data, POA_MAC_SIZE);

        return s;
}


poa_spec_msg_t * poa_spec_s_to_msg(const struct poa_spec * s)
{
        poa_spec_msg_t * msg;

        assert(s != NULL);

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                goto fail_malloc;

        poa_spec_msg__init(msg);

        switch (s->type) {
        case POA_UDP4:
                msg->udp4 = udp4_poa_s_to_msg(&s->udp4);
                if (msg->udp4 == NULL)
                        goto fail_msg;
                break;
        case POA_UDP6:
                msg->udp6 = udp6_poa_s_to_msg(&s->udp6);
                if (msg->udp6 == NULL)
                        goto fail_msg;
                break;
        case POA_ETH:
                msg->eth = eth_poa_s_to_msg(&s->eth);
                if (msg->eth == NULL)
                        goto fail_msg;
                break;
        default:
                goto fail_msg;
        }

        return msg;

 fail_msg:
        poa_spec_msg__free_unpacked(msg, NULL);
 fail_malloc:
        return NULL;
}

struct poa_spec poa_spec_msg_to_s(const poa_spec_msg_t * msg)
{
        struct poa_spec s;

        memset(&s, 0, sizeof(s));

        s.type = POA_INVALID;

        if (msg == NULL)
                return s;

        if (msg->udp4 != NULL) {
                s.type = POA_UDP4;
                s.udp4 = udp4_poa_msg_to_s(msg->udp4);
        } else if (msg->udp6 != NULL) {
                if (msg->udp6->ip_addr.len != IN6_LEN
                    || msg->udp6->ip_addr.data == NULL)
                        return s;

                s.type = POA_UDP6;
                s.udp6 = udp6_poa_msg_to_s(msg->udp6);
        } else if (msg->eth != NULL) {
                if (msg->eth->dev == NULL
                    || strlen(msg->eth->dev) > DEV_NAME_SIZE)
                        return s;

                s.type = POA_ETH;
                s.eth  = eth_poa_msg_to_s(msg->eth);
        }

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

        memset(&s, 0, sizeof(s));

        s.type = msg->ipcp_type;

        s.layer_info = layer_info_msg_to_s(msg->layer_info);

        switch(msg->ipcp_type) {
        case IPCP_LOCAL:
                break;
        case IPCP_UNICAST:
                s.unicast = uni_config_msg_to_s(msg->unicast);
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
        msg->service      = s->service;
        msg->max_gap      = s->max_gap;
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
        s.service      = msg->service;
        s.max_gap      = msg->max_gap;
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
