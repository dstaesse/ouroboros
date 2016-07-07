/*
 * Ouroboros - Copyright (C) 2016
 *
 * Shim IPC process over Ethernet with LLC
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

#include <ouroboros/config.h>

#define _DEFAULT_SOURCE

#include "ipcp.h"
#include "flow.h"
#include <ouroboros/errno.h>
#include <ouroboros/shm_du_map.h>
#include <ouroboros/shm_ap_rbuff.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/irm_config.h>
#include <ouroboros/sockets.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/flow.h>
#include <ouroboros/dev.h>

#define OUROBOROS_PREFIX "ipcpd/shim-eth-llc"

#include <ouroboros/logs.h>

#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <poll.h>
#include <sys/mman.h>

#include "shim_eth_llc_messages.pb-c.h"

typedef ShimEthLlcMsg shim_eth_llc_msg_t;

#define THIS_TYPE IPCP_SHIM_ETH_LLC
#define MGMT_SAP 0x01
#define SHIM_ETH_LLC_MAX_SDU_SIZE 1500
#define MAC_SIZE 6
#define LLC_HEADER_SIZE 3
#define MAX_SAPS 64

/* global for trapping signal */
int irmd_api;

struct ipcp * _ipcp;

#define shim_data(type) ((struct eth_llc_ipcp_data *) type->data)

#define ipcp_flow(index) ((struct flow *) &(shim_data(_ipcp)->flows[index]))

struct eth_llc_flow {
        struct flow flow;
        uint8_t     sap;
        uint8_t     r_sap;
        uint8_t     r_addr[MAC_SIZE];
};

struct eth_llc_ipcp_data {
        /* Keep ipcp_data first for polymorphism. */
        struct ipcp_data      ipcp_data;

        struct sockaddr_ll    device;
        int                   s_fd;

        struct bmp *          indices;
        struct bmp *          saps;

        struct shm_du_map *   dum;
        struct shm_ap_rbuff * rb;

        uint8_t *             rx_ring;
        uint8_t *             tx_ring;
        int                   tx_offset;

        struct eth_llc_flow   flows[AP_MAX_FLOWS];
        pthread_rwlock_t      flows_lock;

        pthread_t             mainloop;
        pthread_t             sdu_writer;
        pthread_t             sdu_reader;
};

struct eth_llc_ipcp_data * eth_llc_ipcp_data_create()
{
        struct eth_llc_ipcp_data * eth_llc_data;
        enum ipcp_type             ipcp_type;

        eth_llc_data = malloc(sizeof(*eth_llc_data));
        if (eth_llc_data == NULL) {
                LOG_ERR("Failed to allocate.");
                return NULL;
        }

        ipcp_type = THIS_TYPE;
        if (ipcp_data_init((struct ipcp_data *) eth_llc_data,
                           ipcp_type) == NULL) {
                free(eth_llc_data);
                return NULL;
        }

        eth_llc_data->dum = shm_du_map_open();
        if (eth_llc_data->dum == NULL) {
                free(eth_llc_data);
                return NULL;
        }

        eth_llc_data->rb = shm_ap_rbuff_create();
        if (eth_llc_data->rb == NULL) {
                shm_du_map_close(eth_llc_data->dum);
                free(eth_llc_data);
                return NULL;
        }

        eth_llc_data->indices = bmp_create(AP_MAX_FLOWS, 0);
        if (eth_llc_data->indices == NULL) {
                shm_ap_rbuff_destroy(eth_llc_data->rb);
                shm_du_map_close(eth_llc_data->dum);
                free(eth_llc_data);
                return NULL;
        }

        eth_llc_data->saps = bmp_create(MAX_SAPS, 2);
        if (eth_llc_data->indices == NULL) {
                bmp_destroy(eth_llc_data->indices);
                shm_ap_rbuff_destroy(eth_llc_data->rb);
                shm_du_map_close(eth_llc_data->dum);
                free(eth_llc_data);
                return NULL;
        }

        pthread_rwlock_init(&eth_llc_data->flows_lock, NULL);

        return eth_llc_data;
}

void eth_llc_ipcp_data_destroy()
{
        int i = 0;

        if (_ipcp == NULL)
                return;

        pthread_rwlock_wrlock(&_ipcp->state_lock);

        if (_ipcp->state != IPCP_SHUTDOWN)
                LOG_WARN("Cleaning up while not in shutdown.");

        if (shim_data(_ipcp)->dum != NULL)
                shm_du_map_close_on_exit(shim_data(_ipcp)->dum);
        if (shim_data(_ipcp)->rb != NULL)
                shm_ap_rbuff_destroy(shim_data(_ipcp)->rb);
        if (shim_data(_ipcp)->indices != NULL)
                bmp_destroy(shim_data(_ipcp)->indices);
        if (shim_data(_ipcp)->saps != NULL)
                bmp_destroy(shim_data(_ipcp)->saps);

        pthread_rwlock_wrlock(&shim_data(_ipcp)->flows_lock);

        for (i = 0; i < AP_MAX_FLOWS; i ++)
                if (ipcp_flow(i)->rb != NULL)
                        shm_ap_rbuff_close(ipcp_flow(i)->rb);

        pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
        pthread_rwlock_unlock(&_ipcp->state_lock);

        free(_ipcp->data);
}

/* only call this under flows_lock */
static int port_id_to_index(int port_id)
{
        int i;

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                if (ipcp_flow(i)->port_id == port_id
                    && ipcp_flow(i)->state != FLOW_NULL)
                        return i;
        }

        return -1;
}

/* only call this under flows_lock */
static int addr_and_saps_to_index(uint8_t r_addr[MAC_SIZE],
                                  uint8_t r_sap,
                                  uint8_t sap)
{
        int i = 0;

        for (i = 0; i < AP_MAX_FLOWS; i++) {
                if (ipcp_flow(i)->state == FLOW_ALLOCATED &&
                    shim_data(_ipcp)->flows[i].r_sap == r_sap &&
                    shim_data(_ipcp)->flows[i].sap == sap &&
                    !memcmp(shim_data(_ipcp)->flows[i].r_addr,
                            r_addr,
                            MAC_SIZE)) {
                        return i;
                }
        }

        return -1;
}

/* only call this under flows_lock */
static int sap_to_index(uint8_t sap)
{
        int i = 0;

        for (i = 0; i < AP_MAX_FLOWS; i++) {
                if (shim_data(_ipcp)->flows[i].sap == sap) {
                        return i;
                }
        }

        return -1;
}

/* only call this under flows_lock */
static void destroy_ipcp_flow(int index)
{
        ipcp_flow(index)->port_id = -1;
        if (ipcp_flow(index)->rb != NULL)
                shm_ap_rbuff_close(ipcp_flow(index)->rb);
        ipcp_flow(index)->rb = NULL;
        ipcp_flow(index)->state = FLOW_NULL;
        bmp_release(shim_data(_ipcp)->indices, index);
        bmp_release(shim_data(_ipcp)->saps,
                    shim_data(_ipcp)->flows[index].sap);
}

static uint8_t reverse_bits(uint8_t b)
{
        b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
        b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
        b = (b & 0xAA) >> 1 | (b & 0x55) << 1;

        return b;
}

static int eth_llc_ipcp_send_frame(uint8_t   dst_addr[MAC_SIZE],
                                   uint8_t   dsap,
                                   uint8_t   ssap,
                                   uint8_t * payload,
                                   size_t    len)
{

        int frame_len = 0;
        uint8_t cf = 0x03;
        int fd;
        uint16_t length = 0;

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        struct pollfd pfd;
        struct tpacket_hdr * header;
        uint8_t * frame;
#else
        uint8_t frame[SHIM_ETH_LLC_MAX_SDU_SIZE];
        struct sockaddr_ll device;
#endif

        if (payload == NULL) {
                LOG_ERR("Payload was NULL.");
                return -1;
        }

        fd = (shim_data(_ipcp))->s_fd;

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        header = (void *) shim_data(_ipcp)->tx_ring +
                (shim_data(_ipcp)->tx_offset * SHM_DU_BUFF_BLOCK_SIZE);

        while (header->tp_status != TP_STATUS_AVAILABLE) {
                pfd.fd = fd;
                pfd.revents = 0;
                pfd.events = POLLIN | POLLRDNORM | POLLERR;

                if (poll(&pfd, 1, -1) <= 0) {
                        LOG_ERR("Failed to poll: %s.", strerror(errno));
                        continue;
                }

                header = (void *) shim_data(_ipcp)->tx_ring +
                        (shim_data(_ipcp)->tx_offset * SHM_DU_BUFF_BLOCK_SIZE);
        }

        frame = (void *) header + TPACKET_HDRLEN - sizeof(struct sockaddr_ll);
#endif

        length = htons(len + LLC_HEADER_SIZE);

        memcpy(frame, dst_addr, MAC_SIZE * sizeof(uint8_t));
        frame_len += MAC_SIZE;
        memcpy(frame + frame_len,
               shim_data(_ipcp)->device.sll_addr,
               MAC_SIZE * sizeof(uint8_t));
        frame_len += MAC_SIZE;
        memcpy(frame + frame_len, &length, 2 * sizeof(uint8_t));
        frame_len += 2 * sizeof(uint8_t);
        memcpy(frame + frame_len, &dsap, sizeof(uint8_t));
        frame_len += sizeof(uint8_t);
        memcpy(frame + frame_len, &ssap, sizeof(uint8_t));
        frame_len += sizeof(uint8_t);
        memcpy(frame + frame_len, &cf, sizeof(uint8_t));
        frame_len += sizeof(uint8_t);
        memcpy(frame + frame_len, payload, len);
        frame_len += len;

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        header->tp_len = frame_len;
        header->tp_status = TP_STATUS_SEND_REQUEST;

        if (send(fd, NULL, 0, 0) < 0) {
                LOG_ERR("Failed to send message.");
                return -1;
        }

        shim_data(_ipcp)->tx_offset =
                (shim_data(_ipcp)->tx_offset + 1)
                & (SHM_BLOCKS_IN_MAP -1);
#else
        device = (shim_data(_ipcp))->device;

        if (sendto(fd, frame, frame_len, 0,
                   (struct sockaddr *) &device, sizeof(device)) <= 0) {
                LOG_ERR("Failed to send message.");
                return -1;
        }
#endif

        return 0;
}

static int eth_llc_ipcp_send_mgmt_frame(shim_eth_llc_msg_t * msg,
                                        uint8_t              dst_addr[MAC_SIZE])
{
        size_t    len;
        uint8_t * buf;

        len = shim_eth_llc_msg__get_packed_size(msg);
        if (len == 0)
                return -1;

        buf = malloc(len);
        if (buf == NULL)
                return -1;

        shim_eth_llc_msg__pack(msg, buf);

        if (eth_llc_ipcp_send_frame(dst_addr, reverse_bits(MGMT_SAP),
                                    reverse_bits(MGMT_SAP), buf, len)) {
                LOG_ERR("Failed to send management frame.");
                return -1;
        }

        free(buf);

        return 0;
}

static int eth_llc_ipcp_port_alloc(uint8_t dst_addr[MAC_SIZE],
                                   uint8_t ssap,
                                   char *  dst_name,
                                   char *  src_ae_name)
{
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;

        msg.code        = SHIM_ETH_LLC_MSG_CODE__FLOW_REQ;
        msg.ssap        = ssap;
        msg.dst_name    = dst_name;
        msg.src_ae_name = src_ae_name;

        return eth_llc_ipcp_send_mgmt_frame(&msg, dst_addr);
}

static int eth_llc_ipcp_port_alloc_resp(uint8_t dst_addr[MAC_SIZE],
                                        uint8_t ssap,
                                        uint8_t dsap,
                                        int     response)
{
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;

        msg.code         = SHIM_ETH_LLC_MSG_CODE__FLOW_REPLY;
        msg.ssap         = ssap;
        msg.has_dsap     = true;
        msg.dsap         = dsap;
        msg.has_response = true;
        msg.response     = response;

        return eth_llc_ipcp_send_mgmt_frame(&msg, dst_addr);
}

static int eth_llc_ipcp_port_dealloc(uint8_t dst_addr[MAC_SIZE],
                                     uint8_t ssap)
{
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;

        msg.code = SHIM_ETH_LLC_MSG_CODE__FLOW_DEALLOC;
        msg.ssap = ssap;

        return eth_llc_ipcp_send_mgmt_frame(&msg, dst_addr);
}

static int eth_llc_ipcp_port_req(uint8_t r_sap,
                                 uint8_t r_addr[MAC_SIZE],
                                 char *  dst_name,
                                 char *  src_ae_name)
{
        int port_id;
        ssize_t index = 0;
        int i;

        pthread_rwlock_wrlock(&_ipcp->state_lock);
        pthread_rwlock_wrlock(&shim_data(_ipcp)->flows_lock);

        index = bmp_allocate(shim_data(_ipcp)->indices);
        if (index < 0) {
                pthread_rwlock_unlock(&_ipcp->state_lock);
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                LOG_ERR("Out of free indices.");
                return -1;
        }

        /* reply to IRM */
        port_id = ipcp_flow_req_arr(getpid(),
                                    dst_name,
                                    src_ae_name);

        if (port_id < 0) {
                bmp_release(shim_data(_ipcp)->indices, index);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                LOG_ERR("Could not get port id from IRMd.");
                return -1;
        }

        ipcp_flow(index)->port_id = port_id;
        ipcp_flow(index)->rb      = NULL;
        ipcp_flow(index)->state   = FLOW_PENDING;
        shim_data(_ipcp)->flows[index].r_sap = r_sap;
        for (i = 0; i < MAC_SIZE; i++) {
                shim_data(_ipcp)->flows[index].r_addr[i] = r_addr[i];
        }

        pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
        pthread_rwlock_unlock(&_ipcp->state_lock);

        LOG_DBG("New flow request, port_id %d, remote SAP %d.", port_id, r_sap);

        return 0;
}

static int eth_llc_ipcp_port_alloc_reply(uint8_t ssap,
                                         uint8_t r_addr[MAC_SIZE],
                                         int     dsap,
                                         int     response)
{
        int index = -1;
        int ret = 0;
        int port_id = -1;
        int i;

        pthread_rwlock_rdlock(&_ipcp->state_lock);
        pthread_rwlock_rdlock(&shim_data(_ipcp)->flows_lock);

        index = sap_to_index(ssap);
        if (index < 0) {
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_ERR("No flow found with that SAP.");
                return -1; /* -EFLOWNOTFOUND */
        }

        if (ipcp_flow(index)->state != FLOW_PENDING) {
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                return -1; /* -EFLOWNOTPENDING */
        }

        port_id = ipcp_flow(index)->port_id;

        if (response) {
                destroy_ipcp_flow(index);
        } else {
                ipcp_flow(index)->state = FLOW_ALLOCATED;
                shim_data(_ipcp)->flows[index].r_sap = dsap;
                for (i = 0; i < MAC_SIZE; i++) {
                        shim_data(_ipcp)->flows[index].r_addr[i] = r_addr[i];
                }
        }

        pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
        pthread_rwlock_unlock(&_ipcp->state_lock);

        LOG_DBG("Flow reply, port_id %d, remote SAP %d.", port_id, dsap);

        if ((ret = ipcp_flow_alloc_reply(getpid(),
                                         port_id,
                                         response)) < 0) {
                return -1; /* -EPIPE */
        }

        return ret;

}

static int eth_llc_ipcp_flow_dealloc_req(uint8_t ssap,
                                         uint8_t r_addr[MAC_SIZE])
{
        int port_id = -1;
        int i = 0;

        pthread_rwlock_rdlock(&_ipcp->state_lock);
        pthread_rwlock_wrlock(&shim_data(_ipcp)->flows_lock);

        i = sap_to_index(ssap);
        if (i < 0) {
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_ERR("No flow found for remote deallocation request.");
                return 0;
        }

        port_id = ipcp_flow(i)->port_id;
        destroy_ipcp_flow(i);

        pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
        pthread_rwlock_unlock(&_ipcp->state_lock);

        ipcp_flow_dealloc(0, port_id);

        LOG_DBG("Flow with port_id %d deallocated.", port_id);

        return 0;
}

static int eth_llc_ipcp_mgmt_frame(uint8_t * buf,
                                   size_t    len,
                                   uint8_t   r_addr[MAC_SIZE])
{
        shim_eth_llc_msg_t * msg = NULL;

        msg = shim_eth_llc_msg__unpack(NULL, len, buf);
        if (msg == NULL) {
                LOG_ERR("Failed to unpack.");
                return -1;
        }

        switch (msg->code) {
        case SHIM_ETH_LLC_MSG_CODE__FLOW_REQ:
                if (ipcp_data_is_in_registry(_ipcp->data,
                                             msg->dst_name)) {
                        eth_llc_ipcp_port_req(msg->ssap,
                                              r_addr,
                                              msg->dst_name,
                                              msg->src_ae_name);
                }
                break;
        case SHIM_ETH_LLC_MSG_CODE__FLOW_REPLY:
                eth_llc_ipcp_port_alloc_reply(msg->ssap,
                                              r_addr,
                                              msg->dsap,
                                              msg->response);
                break;
        case SHIM_ETH_LLC_MSG_CODE__FLOW_DEALLOC:
                eth_llc_ipcp_flow_dealloc_req(msg->ssap,
                                              r_addr);
                break;
        default:
                LOG_ERR("Unknown message received %d.",
                        msg->code);
                shim_eth_llc_msg__free_unpacked(msg, NULL);
                return -1;
        }

        shim_eth_llc_msg__free_unpacked(msg, NULL);
        return 0;
}

static void * eth_llc_ipcp_sdu_reader(void * o)
{
        ssize_t index;
        struct rb_entry e;
        uint8_t src_mac[MAC_SIZE];
        uint8_t dst_mac[MAC_SIZE];
        uint8_t br_addr[MAC_SIZE];
        int frame_len = 0;
        uint8_t ssap = 0;
        uint8_t dsap = 0;
        int i = 0;
        int j = 0;
        int eth_type = 0;

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        struct pollfd pfd;
        int offset = 0;
        struct tpacket_hdr * header;
        uint8_t * buf = NULL;
#else
        uint8_t buf[SHIM_ETH_LLC_MAX_SDU_SIZE];
#endif

        memset(br_addr, 0xff, MAC_SIZE * sizeof(uint8_t));

        while (true) {
                pthread_rwlock_rdlock(&_ipcp->state_lock);

                if (_ipcp->state != IPCP_ENROLLED) {
                        pthread_rwlock_unlock(&_ipcp->state_lock);
                        return (void *) 1; /* -ENOTENROLLED */
                }

                pthread_rwlock_unlock(&_ipcp->state_lock);

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
                header = (void *) shim_data(_ipcp)->rx_ring +
                        (offset * SHM_DU_BUFF_BLOCK_SIZE);
                while (!(header->tp_status & TP_STATUS_USER)) {
                        pfd.fd = shim_data(_ipcp)->s_fd;
                        pfd.revents = 0;
                        pfd.events = POLLIN | POLLRDNORM | POLLERR;

                        if (poll(&pfd, 1, -1) <= 0) {
                                LOG_ERR("Failed to poll: %s.", strerror(errno));
                                continue;
                        }

                        header = (void *) shim_data(_ipcp)->rx_ring +
                                (offset * SHM_DU_BUFF_BLOCK_SIZE);
                }

                buf = (void * ) header + header->tp_mac;
                frame_len = header->tp_len;
#else
                frame_len = recv(shim_data(_ipcp)->s_fd, buf,
                                 SHIM_ETH_LLC_MAX_SDU_SIZE, 0);
                if (frame_len < 0) {
                        LOG_ERR("Failed to recv frame.");
                        continue;
                }
#endif
                for (i = 0; i < MAC_SIZE; i++)
                        dst_mac[i] = buf[i];

                if (memcmp(shim_data(_ipcp)->device.sll_addr,
                           dst_mac,
                           MAC_SIZE) &&
                    memcmp(br_addr, dst_mac, MAC_SIZE)) {
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
                        offset = (offset + 1) & (SHM_BLOCKS_IN_MAP - 1);
                        header->tp_status = TP_STATUS_KERNEL;
#endif
                        continue;
                }

                for (; i < 2 * MAC_SIZE; i++)
                        src_mac[i - MAC_SIZE] = buf[i];

                eth_type = (((buf[i]) << 8) + buf[i + 1]);
                if (eth_type > SHIM_ETH_LLC_MAX_SDU_SIZE) {
                        /* Not an LLC packet. */
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
                        offset = (offset + 1) & (SHM_BLOCKS_IN_MAP - 1);
                        header->tp_status = TP_STATUS_KERNEL;
#endif
                        continue;
                }
                i += 2;

                dsap = reverse_bits(buf[i++]);
                ssap = reverse_bits(buf[i++]);
                i++;

                frame_len -= i;

                if (ssap == MGMT_SAP &&
                    dsap == MGMT_SAP) {
                        eth_llc_ipcp_mgmt_frame((uint8_t *) (buf + i),
                                                frame_len, src_mac);
                } else {
                        pthread_rwlock_rdlock(&_ipcp->state_lock);
                        pthread_rwlock_rdlock(&shim_data(_ipcp)->flows_lock);

                        j = addr_and_saps_to_index(src_mac, ssap, dsap);
                        if (j < 0) {
                                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                                pthread_rwlock_unlock(&_ipcp->state_lock);
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
                                offset = (offset + 1)
                                        & (SHM_BLOCKS_IN_MAP - 1);
                                header->tp_status = TP_STATUS_KERNEL;
#endif
                                continue;
                        }

                        while ((index = shm_du_map_write(shim_data(_ipcp)->dum,
                                                         ipcp_flow(j)->api,
                                                         0,
                                                         0,
                                                         (uint8_t *) (buf + i),
                                                         frame_len)) < 0)
                                ;

                        e.index = index;
                        e.port_id = ipcp_flow(j)->port_id;

                        while (shm_ap_rbuff_write(ipcp_flow(j)->rb, &e) < 0)
                                ;

                        pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                        pthread_rwlock_unlock(&_ipcp->state_lock);
                }
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
                offset = (offset + 1) & (SHM_BLOCKS_IN_MAP -1);
                header->tp_status = TP_STATUS_KERNEL;
#endif
        }

        return (void *) 0;
}

static void * eth_llc_ipcp_sdu_writer(void * o)
{
        while (true) {
                struct rb_entry * e;
                int i;
                int len = 0;
                uint8_t * buf;
                uint8_t ssap;
                uint8_t dsap;

                e = shm_ap_rbuff_read(shim_data(_ipcp)->rb);
                if (e == NULL) {
                        continue;
                }

                pthread_rwlock_rdlock(&_ipcp->state_lock);

                if (_ipcp->state != IPCP_ENROLLED) {
                        pthread_rwlock_unlock(&_ipcp->state_lock);
                        return (void *) 1; /* -ENOTENROLLED */
                }

                len = shm_du_map_read((uint8_t **) &buf,
                                      shim_data(_ipcp)->dum,
                                      e->index);
                if (len <= 0) {
                        pthread_rwlock_unlock(&_ipcp->state_lock);
                        free(e);
                        continue;
                }

                pthread_rwlock_rdlock(&shim_data(_ipcp)->flows_lock);

                i = port_id_to_index(e->port_id);
                if (i < 0) {
                        free(e);
                        pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                        pthread_rwlock_unlock(&_ipcp->state_lock);
                        continue;
                }

                ssap = reverse_bits(shim_data(_ipcp)->flows[i].sap);
                dsap = reverse_bits(shim_data(_ipcp)->flows[i].r_sap);

                if (eth_llc_ipcp_send_frame(shim_data(_ipcp)->flows[i].r_addr,
                                            dsap, ssap, buf, len))
                        LOG_ERR("Failed to send SDU.");

                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);

                if (shim_data(_ipcp)->dum != NULL)
                        shm_du_map_remove(shim_data(_ipcp)->dum, e->index);

                pthread_rwlock_unlock(&_ipcp->state_lock);
        }

        return (void *) 1;
}

void ipcp_sig_handler(int sig, siginfo_t * info, void * c)
{
        sigset_t  sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                if (info->si_pid == irmd_api) {
                        bool clean_threads = false;
                        LOG_DBG("Terminating by order of %d. Bye.",
                                info->si_pid);

                        pthread_rwlock_wrlock(&_ipcp->state_lock);

                        if (_ipcp->state == IPCP_ENROLLED)
                                clean_threads = true;

                        _ipcp->state = IPCP_SHUTDOWN;

                        pthread_rwlock_unlock(&_ipcp->state_lock);

                        if (clean_threads) {
                                pthread_cancel(shim_data(_ipcp)->sdu_reader);
                                pthread_cancel(shim_data(_ipcp)->sdu_writer);

                                pthread_join(shim_data(_ipcp)->sdu_writer,
                                             NULL);
                                pthread_join(shim_data(_ipcp)->sdu_reader,
                                             NULL);
                        }

                        pthread_cancel(shim_data(_ipcp)->mainloop);

                }
        default:
                return;
        }
}

static int eth_llc_ipcp_bootstrap(struct dif_config * conf)
{
        int fd = -1;
        struct ifreq ifr;
        int index;
        struct sockaddr_ll device;

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        struct tpacket_req req;
#endif

        if (conf == NULL)
                return -1; /* -EINVAL */

        if (conf->type != THIS_TYPE) {
                LOG_ERR("Config doesn't match IPCP type.");
                return -1;
        }

        if (conf->if_name == NULL) {
                LOG_ERR("Interface name is NULL.");
                return -1;
        }

        memset(&ifr, 0, sizeof(ifr));

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
                LOG_ERR("Failed to open socket.");
                return -1;
        }

        memcpy(ifr.ifr_name, conf->if_name, strlen(conf->if_name));

        if (ioctl(fd, SIOCGIFHWADDR, &ifr)) {
                close(fd);
                LOG_ERR("Failed to ioctl: %s.", strerror(errno));
                return -1;
        }

        close(fd);

        index = if_nametoindex(conf->if_name);
        if (index == 0) {
                LOG_ERR("Failed to retrieve interface index.");
                return -1;
        }

        memset(&(device), 0, sizeof(device));
        device.sll_ifindex = index;
        device.sll_family = AF_PACKET;
        memcpy(device.sll_addr,
               ifr.ifr_hwaddr.sa_data,
               MAC_SIZE * sizeof (uint8_t));
        device.sll_halen = MAC_SIZE;
        device.sll_protocol = htons(ETH_P_ALL);

        fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_802_2));
        if (fd < 0) {
                LOG_ERR("Failed to create socket: %s.", strerror(errno));
                return -1;
        }

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        if (SHIM_ETH_LLC_MAX_SDU_SIZE > SHM_DU_BUFF_BLOCK_SIZE) {
                LOG_ERR("Max SDU size is bigger than DU map block size.");
                close(fd);
                return -1;
        }

        req.tp_block_size = SHM_DU_BUFF_BLOCK_SIZE;
        req.tp_frame_size = SHM_DU_BUFF_BLOCK_SIZE;
        req.tp_block_nr = SHM_BLOCKS_IN_MAP;
        req.tp_frame_nr = SHM_BLOCKS_IN_MAP;

        if (setsockopt(fd, SOL_PACKET, PACKET_RX_RING,
                       (void *) &req, sizeof(req))) {
                LOG_ERR("Failed to set sockopt PACKET_RX_RING");
                close(fd);
                return -1;
        }

        if (setsockopt(fd, SOL_PACKET, PACKET_TX_RING,
                       (void *) &req, sizeof(req))) {
                LOG_ERR("Failed to set sockopt PACKET_TX_RING");
                close(fd);
                return -1;
        }
#endif

        if (bind(fd,(struct sockaddr *) &device,
                 sizeof(struct sockaddr_ll))) {
                LOG_ERR("Failed to bind socket to interface");
                close(fd);
                return -1;
        }

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        shim_data(_ipcp)->rx_ring = mmap(NULL,
                                         2 * SHM_DU_BUFF_BLOCK_SIZE
                                         * SHM_BLOCKS_IN_MAP,
                                         PROT_READ | PROT_WRITE, MAP_SHARED,
                                         fd, 0);
        if (shim_data(_ipcp)->rx_ring == NULL) {
                LOG_ERR("Failed to mmap");
                close(fd);
                return -1;
        }
        shim_data(_ipcp)->tx_ring = shim_data(_ipcp)->rx_ring
                + (SHM_DU_BUFF_BLOCK_SIZE * SHM_BLOCKS_IN_MAP);

#endif

        pthread_rwlock_wrlock(&_ipcp->state_lock);

        if (_ipcp->state != IPCP_INIT) {
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_ERR("IPCP in wrong state.");
                close(fd);
                return -1;
        }

        shim_data(_ipcp)->s_fd = fd;
        shim_data(_ipcp)->device = device;
        shim_data(_ipcp)->tx_offset = 0;

        _ipcp->state = IPCP_ENROLLED;

        pthread_create(&shim_data(_ipcp)->sdu_reader,
                       NULL,
                       eth_llc_ipcp_sdu_reader,
                       NULL);

        pthread_create(&shim_data(_ipcp)->sdu_writer,
                       NULL,
                       eth_llc_ipcp_sdu_writer,
                       NULL);

        pthread_rwlock_unlock(&_ipcp->state_lock);

        LOG_DBG("Bootstrapped shim IPCP over Ethernet with LLC with api %d.",
                getpid());

        return 0;
}

static int eth_llc_ipcp_name_reg(char * name)
{
        pthread_rwlock_rdlock(&_ipcp->state_lock);

        if (_ipcp->state != IPCP_ENROLLED) {
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Won't register with non-enrolled IPCP.");
                return -1; /* -ENOTENROLLED */
        }

        if (ipcp_data_add_reg_entry(_ipcp->data, name)) {
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_ERR("Failed to add %s to local registry.", name);
                return -1;
        }

        pthread_rwlock_unlock(&_ipcp->state_lock);

        LOG_DBG("Registered %s.", name);

        return 0;
}

static int eth_llc_ipcp_name_unreg(char * name)
{
        pthread_rwlock_rdlock(&_ipcp->state_lock);

        ipcp_data_del_reg_entry(_ipcp->data, name);

        pthread_rwlock_unlock(&_ipcp->state_lock);

        return 0;
}

static int eth_llc_ipcp_flow_alloc(pid_t         n_api,
                                   int           port_id,
                                   char *        dst_name,
                                   char *        src_ae_name,
                                   enum qos_cube qos)
{
        struct shm_ap_rbuff * rb;
        uint8_t ssap = 0;
        uint8_t r_addr[MAC_SIZE];
        int index = 0;

        LOG_INFO("Allocating flow to %s.", dst_name);

        if (dst_name == NULL || src_ae_name == NULL)
                return -1;

        if (qos != QOS_CUBE_BE)
                LOG_DBGF("QoS requested. Ethernet LLC can't do that. For now.");

        rb = shm_ap_rbuff_open(n_api);
        if (rb == NULL)
                return -1; /* -ENORBUFF */

        pthread_rwlock_wrlock(&_ipcp->state_lock);

        if (_ipcp->state != IPCP_ENROLLED) {
                shm_ap_rbuff_close(rb);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Won't allocate flow with non-enrolled IPCP.");
                return -1; /* -ENOTENROLLED */
        }

        index = bmp_allocate(shim_data(_ipcp)->indices);
        if (index < 0) {
                shm_ap_rbuff_close(rb);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                return -1;
        }

        pthread_rwlock_wrlock(&shim_data(_ipcp)->flows_lock);

        ssap = bmp_allocate(shim_data(_ipcp)->saps);
        if (ssap < 0) {
                shm_ap_rbuff_close(rb);
                bmp_release(shim_data(_ipcp)->indices, index);
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                return -1;
        }

        ipcp_flow(index)->port_id = port_id;
        ipcp_flow(index)->state = FLOW_PENDING;
        ipcp_flow(index)->rb = rb;
        shim_data(_ipcp)->flows[index].sap = ssap;

        pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
        pthread_rwlock_unlock(&_ipcp->state_lock);

        memset(r_addr, 0xff, MAC_SIZE * sizeof(uint8_t));

        if (eth_llc_ipcp_port_alloc(r_addr, ssap,
                                    dst_name,
                                    src_ae_name) < 0) {
                LOG_DBGF("Port alloc returned -1.");
                pthread_rwlock_wrlock(&_ipcp->state_lock);
                pthread_rwlock_wrlock(&shim_data(_ipcp)->flows_lock);
                destroy_ipcp_flow(index);
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                return -1;
        }

        LOG_DBG("Pending flow with port_id %d on SAP %d.",
                port_id, ssap);

        return index;
}

static int eth_llc_ipcp_flow_alloc_resp(pid_t n_api,
                                        int   port_id,
                                        int   response)
{
        struct shm_ap_rbuff * rb;
        int index = -1;
        uint8_t ssap = 0;

        pthread_rwlock_wrlock(&_ipcp->state_lock);
        pthread_rwlock_wrlock(&shim_data(_ipcp)->flows_lock);

        index = port_id_to_index(port_id);
        if (index < 0) {
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Could not find flow with port_id %d.", port_id);
                return -1;
        }

        if (ipcp_flow(index)->state != FLOW_PENDING) {
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Flow was not pending.");
                return -1;
        }

        rb = shm_ap_rbuff_open(n_api);
        if (rb == NULL) {
                LOG_ERR("Could not open N + 1 ringbuffer.");
                ipcp_flow(index)->state = FLOW_NULL;
                ipcp_flow(index)->port_id = -1;
                bmp_release(shim_data(_ipcp)->indices, index);
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                return -1;
        }

        ssap = bmp_allocate(shim_data(_ipcp)->saps);
        if (ssap < 0) {
                ipcp_flow(index)->state = FLOW_NULL;
                ipcp_flow(index)->port_id = -1;
                shm_ap_rbuff_close(ipcp_flow(index)->rb);
                bmp_release(shim_data(_ipcp)->indices, index);
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                return -1;
        }

        ipcp_flow(index)->state = FLOW_ALLOCATED;
        ipcp_flow(index)->rb = rb;
        shim_data(_ipcp)->flows[index].sap = ssap;

        pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
        pthread_rwlock_unlock(&_ipcp->state_lock);

        if (eth_llc_ipcp_port_alloc_resp(shim_data(_ipcp)->flows[index].r_addr,
                                         shim_data(_ipcp)->flows[index].r_sap,
                                         ssap,
                                         response) < 0) {
                pthread_rwlock_rdlock(&_ipcp->state_lock);
                pthread_rwlock_wrlock(&shim_data(_ipcp)->flows_lock);
                destroy_ipcp_flow(index);
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                pthread_rwlock_unlock(&_ipcp->state_lock);

                LOG_DBGF("Could not send response.");
                return -1;
        }

        LOG_DBG("Accepted flow, port_id %d, SAP %d.", port_id, ssap);

        return 0;
}

static int eth_llc_ipcp_flow_dealloc(int port_id)
{
        int index = -1;
        uint8_t sap;
        uint8_t addr[MAC_SIZE];
        int i;
        int ret;

        pthread_rwlock_rdlock(&_ipcp->state_lock);
        pthread_rwlock_wrlock(&shim_data(_ipcp)->flows_lock);

        index = port_id_to_index(port_id);
        if (index < 0) {
                pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);
                pthread_rwlock_unlock(&_ipcp->state_lock);
                return 0;
        }

        sap = shim_data(_ipcp)->flows[index].r_sap;
        for (i = 0; i < MAC_SIZE; i++) {
                addr[i] = shim_data(_ipcp)->flows[index].r_addr[i];
        }

        destroy_ipcp_flow(index);

        pthread_rwlock_unlock(&shim_data(_ipcp)->flows_lock);

        ret = eth_llc_ipcp_port_dealloc(addr, sap);
        pthread_rwlock_unlock(&_ipcp->state_lock);
        if (eth_llc_ipcp_port_dealloc(addr, sap) < 0)
                LOG_DBGF("Could not notify remote.");

        if (ret < 0)
                LOG_DBGF("Could not notify remote.");

        LOG_DBG("Flow with port_id %d deallocated.", port_id);

        return 0;
}

static struct ipcp_ops eth_llc_ops = {
        .ipcp_bootstrap       = eth_llc_ipcp_bootstrap,
        .ipcp_enroll          = NULL,                       /* shim */
        .ipcp_reg             = NULL,                       /* shim */
        .ipcp_unreg           = NULL,                       /* shim */
        .ipcp_name_reg        = eth_llc_ipcp_name_reg,
        .ipcp_name_unreg      = eth_llc_ipcp_name_unreg,
        .ipcp_flow_alloc      = eth_llc_ipcp_flow_alloc,
        .ipcp_flow_alloc_resp = eth_llc_ipcp_flow_alloc_resp,
        .ipcp_flow_dealloc    = eth_llc_ipcp_flow_dealloc
};

int main(int argc, char * argv[])
{
        struct sigaction sig_act;
        sigset_t  sigset;
        int i = 0;

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        if (ipcp_parse_arg(argc, argv)) {
                LOG_ERR("Failed to parse arguments.");
                exit(EXIT_FAILURE);
        }

        /* store the process id of the irmd */
        irmd_api = atoi(argv[1]);

        /* init sig_act */
        memset(&sig_act, 0, sizeof(sig_act));

        /* install signal traps */
        sig_act.sa_sigaction = &ipcp_sig_handler;
        sig_act.sa_flags     = SA_SIGINFO;

        sigaction(SIGINT,  &sig_act, NULL);
        sigaction(SIGTERM, &sig_act, NULL);
        sigaction(SIGHUP,  &sig_act, NULL);
        sigaction(SIGPIPE, &sig_act, NULL);

        _ipcp = ipcp_instance_create();
        if (_ipcp == NULL) {
                LOG_ERR("Failed to create instance.");
                close_logfile();
                exit(EXIT_FAILURE);
        }

        _ipcp->data = (struct ipcp_data *) eth_llc_ipcp_data_create();
        if (_ipcp->data == NULL) {
                LOG_ERR("Failed to create instance data.");
                free(_ipcp);
                close_logfile();
                exit(EXIT_FAILURE);
        }

        for (i = 0; i < AP_MAX_FLOWS; i++) {
                ipcp_flow(i)->rb = NULL;
                ipcp_flow(i)->port_id = -1;
                ipcp_flow(i)->state = FLOW_NULL;
        }

        _ipcp->ops = &eth_llc_ops;
        _ipcp->state = IPCP_INIT;

        pthread_rwlock_wrlock(&_ipcp->state_lock);

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        pthread_create(&shim_data(_ipcp)->mainloop, NULL,
                       ipcp_main_loop, _ipcp);

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        pthread_rwlock_unlock(&_ipcp->state_lock);

        pthread_join(shim_data(_ipcp)->mainloop, NULL);

        eth_llc_ipcp_data_destroy();

        free(_ipcp);

        close_logfile();

        exit(EXIT_SUCCESS);
}
