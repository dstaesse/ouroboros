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

#ifndef OUROBOROS_LIB_PROTOBUF_H
#define OUROBOROS_LIB_PROTOBUF_H

#include <ouroboros/qos.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/serdes-oep.h>

#include "ipcp_config.pb-c.h"
typedef IpcpConfigMsg ipcp_config_msg_t;
typedef LayerInfoMsg layer_info_msg_t;
typedef DtConfigMsg dt_config_msg_t;
typedef EthConfigMsg eth_config_msg_t;
typedef UdpConfigMsg udp_config_msg_t;
typedef UniConfigMsg uni_config_msg_t;

#include "ipcp.pb-c.h"
typedef IpcpMsg ipcp_msg_t;

#include "irm.pb-c.h"
typedef IpcpInfoMsg ipcp_info_msg_t;
typedef NameInfoMsg name_info_msg_t;

#include "qos.pb-c.h"
typedef QosspecMsg qosspec_msg_t;

#include "enroll.pb-c.h"
typedef EnrollReqMsg enroll_req_msg_t;
typedef EnrollRespMsg enroll_resp_msg_t;
typedef EnrollAckMsg enroll_ack_msg_t;

/* IPCP configuration */

layer_info_msg_t *  layer_info_s_to_msg(const struct layer_info * s);

struct layer_info   layer_info_msg_to_s(const layer_info_msg_t * msg);

dt_config_msg_t *   dt_config_s_to_msg(const struct dt_config * s);

struct dt_config    dt_config_msg_to_s(const dt_config_msg_t * msg);

uni_config_msg_t *  uni_config_s_to_msg(const struct uni_config * s);

struct uni_config   uni_config_msg_to_s(const uni_config_msg_t * msg);

eth_config_msg_t *  eth_config_s_to_msg(const struct eth_config * s);

struct eth_config   eth_config_msg_to_s(const eth_config_msg_t * msg);

udp_config_msg_t *  udp_config_s_to_msg(const struct udp_config * s);

struct udp_config   udp_config_msg_to_s(const udp_config_msg_t * msg);

ipcp_config_msg_t * ipcp_config_s_to_msg(const struct ipcp_config * s);

struct ipcp_config  ipcp_config_msg_to_s(const ipcp_config_msg_t * msg);

/* QoS */

qosspec_msg_t *     qos_spec_s_to_msg(const struct qos_spec * s);

struct qos_spec     qos_spec_msg_to_s(const qosspec_msg_t * msg);

/* Enrollment */

enroll_req_msg_t *  enroll_req_s_to_msg(const struct enroll_req * s);

struct enroll_req   enroll_req_msg_to_s(const enroll_req_msg_t * msg);

enroll_resp_msg_t * enroll_resp_s_to_msg(const struct enroll_resp * s);

struct enroll_resp  enroll_resp_msg_to_s(const enroll_resp_msg_t * msg);

enroll_ack_msg_t *  enroll_ack_s_to_msg(const struct enroll_ack * s);

struct enroll_ack   enroll_ack_msg_to_s(const enroll_ack_msg_t * msg);

#endif /* OUROBOROS_LIB_PROTOBUF_H */