/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Additional API for IPCPs
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

#ifndef OUROBOROS_LIB_IPCP_DEV_H
#define OUROBOROS_LIB_IPCP_DEV_H

#include <ouroboros/ipcp.h>
#include <ouroboros/qos.h>
#include <ouroboros/qoscube.h>
#include <ouroboros/ssm_pool.h>
#include <ouroboros/utils.h>

#include <stdbool.h>
#include <stdint.h>
#include <time.h>

int      ipcp_create_r(const struct ipcp_info * info);

void     ipcp_flow_set_max_rtt(uint32_t max_rtt);

int      ipcp_flow_req_arr(const buffer_t * dst,
                           qosspec_t        qs,
                           time_t           mpl,
                           uint32_t         mtu,
                           const buffer_t * data);

int      ipcp_flow_update_arr(int              flow_id,
                              const buffer_t * data);

int      ipcp_flow_alloc_reply(int              fd,
                               int              response,
                               time_t           mpl,
                               uint32_t         mtu,
                               const buffer_t * data);

int      ipcp_flow_read(int                   fd,
                        struct ssm_pk_buff ** spb);

int      ipcp_flow_write(int                  fd,
                         struct ssm_pk_buff * spb);

int      np1_flow_read(int                   fd,
                       struct ssm_pk_buff ** spb,
                       struct ssm_pool *     pool);

int      np1_flow_write(int                  fd,
                        struct ssm_pk_buff * spb,
                        struct ssm_pool *    pool);

int      ipcp_flow_dealloc(int fd);

int      ipcp_flow_fini(int fd);

int      ipcp_flow_get_qoscube(int         fd,
                               qoscube_t * cube);

/* Bytes queued in the transmit path of the flow. */
size_t   ipcp_flow_queued(int fd);

/* Mean size of a packet written to the flow, bytes. */
size_t   ipcp_flow_mean_len(int fd);

/*
 * Capacity estimator of the transmit queue behind the flow.
 * Flows attached to one point of attachment share a queue and
 * share the estimator. Armed by the IPCP; unarmed flows read 0.
 */
int      ipcp_flow_cap_arm(int fd);

void     ipcp_flow_cap_update(int    fd,
                              size_t qlen,
                              size_t len);

/* Estimated capacity of the transmit queue (bytes/s), 0 = unknown. */
uint64_t ipcp_flow_cap(int fd);

int      ipcp_spb_reserve(struct ssm_pk_buff ** spb,
                          size_t                len);

void     ipcp_spb_release(struct ssm_pk_buff * spb);

/* PoA lifecycle; an IPCP owns its PoAs, applications have none. */
int      poa_init(const char * name);

int      poa_start(void);

void     poa_stop(void);

void     poa_fini(void);

/* Also answer name queries for the layer; set at bootstrap/enroll. */
int      poa_set_layer(const char * layer);

/* Attach or release a PoA; the type in the spec picks the transport. */
int      poa_attach(const struct poa_spec * poa);

int      poa_detach(const struct poa_spec * poa);

/* The PoAs this process has attached. */
ssize_t  poa_list(struct poa_spec * specs,
                  size_t            max);

/* Allocate a flow to dst over the PoA that carries addr. */
int      poa_flow_alloc(const char *            dst,
                        const struct poa_addr * addr,
                        qosspec_t *             qs,
                        const struct timespec * timeo);

/* Resolve dst on the attached PoAs; no flow is created. */
int      poa_query(const char *            dst,
                   const struct timespec * timeo,
                   struct poa_addr *       addr);

/* PoA counterparts of the ipcp_flow_* operations */
int      poa_flow_alloc_resp(int              flow_id,
                             int              response,
                             const buffer_t * data);

int      poa_flow_update(int              flow_id,
                         const buffer_t * data);

int      poa_flow_dealloc(int flow_id);

#endif /* OUROBOROS_LIB_IPCP_DEV_H */
