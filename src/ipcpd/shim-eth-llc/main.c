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

#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>

#define OUROBOROS_PREFIX "ipcpd/shim-eth-llc"

#include <ouroboros/logs.h>

#include "ipcp.h"

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

#ifdef __linux__
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif

#ifdef __FreeBSD__
#include <net/if_dl.h>
#include <netinet/if_ether.h>
#include <ifaddrs.h>
#endif

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
#define ETH_HEADER_SIZE (2 * MAC_SIZE + 2)
#define ETH_FRAME_SIZE (ETH_HEADER_SIZE + LLC_HEADER_SIZE \
                        + SHIM_ETH_LLC_MAX_SDU_SIZE)

/* global for trapping signal */
int irmd_api;

struct eth_llc_frame {
        uint8_t dst_hwaddr[MAC_SIZE];
        uint8_t src_hwaddr[MAC_SIZE];
        uint8_t length[2];
        uint8_t dsap;
        uint8_t ssap;
        uint8_t cf;
        uint8_t payload;
};

struct ef {
        int8_t  sap;
        int8_t  r_sap;
        uint8_t r_addr[MAC_SIZE];
};

struct {
#ifdef __FreeBSD__
        struct sockaddr_dl device;
#else
        struct sockaddr_ll device;
#endif
        int                s_fd;

        struct bmp *       saps;
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        uint8_t *          rx_ring;
        uint8_t *          tx_ring;
        int                tx_offset;
#endif
        int *              ef_to_fd;
        struct ef *        fd_to_ef;
        pthread_rwlock_t   flows_lock;

        pthread_t          sdu_writer;
        pthread_t          sdu_reader;
} eth_llc_data;

static int eth_llc_data_init()
{
        int i;

        eth_llc_data.fd_to_ef = malloc(sizeof(struct ef) * IRMD_MAX_FLOWS);
        if (eth_llc_data.fd_to_ef == NULL)
                return -ENOMEM;

        eth_llc_data.ef_to_fd = malloc(sizeof(struct ef) * MAX_SAPS);
        if (eth_llc_data.ef_to_fd == NULL) {
                free(eth_llc_data.fd_to_ef);
                return -ENOMEM;
        }

        eth_llc_data.saps = bmp_create(MAX_SAPS, 2);
        if (eth_llc_data.saps == NULL) {
                free(eth_llc_data.ef_to_fd);
                free(eth_llc_data.fd_to_ef);
                return -ENOMEM;
        }

        for (i = 0; i < MAX_SAPS; ++i)
                eth_llc_data.ef_to_fd[i] = -1;

        for (i = 0; i < IRMD_MAX_FLOWS; ++i) {
                eth_llc_data.fd_to_ef[i].sap   = -1;
                eth_llc_data.fd_to_ef[i].r_sap = -1;
                memset(&eth_llc_data.fd_to_ef[i].r_addr, 0, MAC_SIZE);
        }

        pthread_rwlock_init(&eth_llc_data.flows_lock, NULL);

        return 0;
}

void eth_llc_data_fini()
{
        bmp_destroy(eth_llc_data.saps);
        free(eth_llc_data.fd_to_ef);
        free(eth_llc_data.ef_to_fd);
        pthread_rwlock_destroy(&eth_llc_data.flows_lock);
}

static uint8_t reverse_bits(uint8_t b)
{
        b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
        b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
        b = (b & 0xAA) >> 1 | (b & 0x55) << 1;

        return b;
}

static int eth_llc_ipcp_send_frame(uint8_t * dst_addr,
                                   uint8_t   dsap,
                                   uint8_t   ssap,
                                   uint8_t * payload,
                                   size_t    len)
{
        int frame_len = 0;
        uint8_t cf = 0x03;
        uint16_t length;
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        struct pollfd pfd;
        struct tpacket_hdr * header;
        uint8_t * frame;
#else
        uint8_t frame[SHIM_ETH_LLC_MAX_SDU_SIZE];
#endif
        struct eth_llc_frame * llc_frame;

        if (payload == NULL) {
                LOG_ERR("Payload was NULL.");
                return -1;
        }

        if (len > SHIM_ETH_LLC_MAX_SDU_SIZE)
                return -1;

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        header = (void *) (eth_llc_data.tx_ring +
                           eth_llc_data.tx_offset * SHM_RDRB_BLOCK_SIZE);

        while (header->tp_status != TP_STATUS_AVAILABLE) {
                pfd.fd = eth_llc_data.s_fd;
                pfd.revents = 0;
                pfd.events = POLLIN | POLLRDNORM | POLLERR;

                if (poll(&pfd, 1, -1) <= 0) {
                        LOG_ERR("Failed to poll.");
                        continue;
                }

                header = (void *) (eth_llc_data.tx_ring
                                   + eth_llc_data.tx_offset
                                   * SHM_RDRB_BLOCK_SIZE);
        }

        frame = (uint8_t *) header
                + TPACKET_HDRLEN - sizeof(struct sockaddr_ll);
#endif
        llc_frame = (struct eth_llc_frame *) frame;

        memcpy(llc_frame->dst_hwaddr, dst_addr, MAC_SIZE);
        memcpy(llc_frame->src_hwaddr,
#ifdef __FreeBSD__
               LLADDR(&eth_llc_data.device),
#else
               eth_llc_data.device.sll_addr,
#endif
               MAC_SIZE);

        length = htons(LLC_HEADER_SIZE + len);
        memcpy(&llc_frame->length, &length, sizeof(length));
        llc_frame->dsap = dsap;
        llc_frame->ssap = ssap;
        llc_frame->cf   = cf;
        memcpy(&llc_frame->payload, payload, len);

        frame_len = ETH_HEADER_SIZE + LLC_HEADER_SIZE + len;

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        header->tp_len = frame_len;
        header->tp_status = TP_STATUS_SEND_REQUEST;

        if (send(eth_llc_data.s_fd, NULL, 0, MSG_DONTWAIT) < 0) {
                LOG_ERR("Failed to write frame into TX_RING.");
                return -1;
        }

        eth_llc_data.tx_offset =
                (eth_llc_data.tx_offset + 1) & (SHM_BUFFER_SIZE - 1);
#else
        if (sendto(eth_llc_data.s_fd,
                   frame,
                   frame_len,
                   0,
                   (struct sockaddr *) &eth_llc_data.device,
                   sizeof(eth_llc_data.device)) <= 0) {
                LOG_ERR("Failed to send message.");
                return -1;
        }
#endif
        return 0;
}

static int eth_llc_ipcp_send_mgmt_frame(shim_eth_llc_msg_t * msg,
                                        uint8_t *            dst_addr)
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
                free(buf);
                return -1;
        }

        free(buf);

        return 0;
}

static int eth_llc_ipcp_sap_alloc(uint8_t * dst_addr,
                                  uint8_t   ssap,
                                  char *    dst_name,
                                  char *    src_ae_name)
{
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;

        msg.code        = SHIM_ETH_LLC_MSG_CODE__FLOW_REQ;
        msg.ssap        = ssap;
        msg.dst_name    = dst_name;
        msg.src_ae_name = src_ae_name;

        return eth_llc_ipcp_send_mgmt_frame(&msg, dst_addr);
}

static int eth_llc_ipcp_sap_alloc_resp(uint8_t * dst_addr,
                                       uint8_t   ssap,
                                       uint8_t   dsap,
                                       int       response)
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

static int eth_llc_ipcp_sap_dealloc(uint8_t * dst_addr, uint8_t ssap)
{
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;

        msg.code = SHIM_ETH_LLC_MSG_CODE__FLOW_DEALLOC;
        msg.ssap = ssap;

        return eth_llc_ipcp_send_mgmt_frame(&msg, dst_addr);
}

static int eth_llc_ipcp_sap_req(uint8_t   r_sap,
                                uint8_t * r_addr,
                                char *    dst_name,
                                char *    src_ae_name)
{
        int fd;

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        /* reply to IRM */
        fd = ipcp_flow_req_arr(getpid(), dst_name, src_ae_name);
        if (fd < 0) {
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Could not get new flow from IRMd.");
                return -1;
        }

        eth_llc_data.fd_to_ef[fd].r_sap = r_sap;
        memcpy(eth_llc_data.fd_to_ef[fd].r_addr, r_addr, MAC_SIZE);

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_DBG("New flow request, fd %d, remote SAP %d.", fd, r_sap);

        return 0;
}

static int eth_llc_ipcp_sap_alloc_reply(uint8_t   ssap,
                                        uint8_t * r_addr,
                                        int       dsap,
                                        int       response)
{
        int ret = 0;
        int fd = -1;

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_rdlock(& eth_llc_data.flows_lock);

        fd = eth_llc_data.ef_to_fd[dsap];
        if (fd < 0) {
                pthread_rwlock_unlock(& eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("No flow found with that SAP.");
                return -1; /* -EFLOWNOTFOUND */
        }

        if (response) {
                bmp_release(eth_llc_data.saps, eth_llc_data.fd_to_ef[fd].sap);
        } else {
                eth_llc_data.fd_to_ef[fd].r_sap = ssap;
                memcpy(eth_llc_data.fd_to_ef[fd].r_addr, r_addr, MAC_SIZE);
        }

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_DBG("Flow reply, fd %d, SSAP %d, DSAP %d.", fd, ssap, dsap);

        if ((ret = ipcp_flow_alloc_reply(fd, response)) < 0)
                return -1;

        return ret;

}

static int eth_llc_ipcp_flow_dealloc_req(uint8_t ssap, uint8_t * r_addr)
{
        int fd = -1;

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        fd = eth_llc_data.ef_to_fd[ssap];
        if (fd < 0) {
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("No flow found for remote deallocation request.");
                return 0;
        }

        bmp_release(eth_llc_data.saps, eth_llc_data.fd_to_ef[fd].sap);

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        flow_dealloc(fd);

        LOG_DBG("Flow with fd %d deallocated.", fd);

        return 0;
}

static int eth_llc_ipcp_mgmt_frame(uint8_t * buf, size_t len, uint8_t * r_addr)
{
        shim_eth_llc_msg_t * msg = NULL;

        msg = shim_eth_llc_msg__unpack(NULL, len, buf);
        if (msg == NULL) {
                LOG_ERR("Failed to unpack.");
                return -1;
        }

        switch (msg->code) {
        case SHIM_ETH_LLC_MSG_CODE__FLOW_REQ:
                if (ipcp_data_is_in_registry(ipcpi.data, msg->dst_name)) {
                        eth_llc_ipcp_sap_req(msg->ssap,
                                             r_addr,
                                             msg->dst_name,
                                             msg->src_ae_name);
                }
                break;
        case SHIM_ETH_LLC_MSG_CODE__FLOW_REPLY:
                eth_llc_ipcp_sap_alloc_reply(msg->ssap,
                                             r_addr,
                                             msg->dsap,
                                             msg->response);
                break;
        case SHIM_ETH_LLC_MSG_CODE__FLOW_DEALLOC:
                eth_llc_ipcp_flow_dealloc_req(msg->ssap, r_addr);
                break;
        default:
                LOG_ERR("Unknown message received %d.", msg->code);
                shim_eth_llc_msg__free_unpacked(msg, NULL);
                return -1;
        }

        shim_eth_llc_msg__free_unpacked(msg, NULL);
        return 0;
}

static void * eth_llc_ipcp_sdu_reader(void * o)
{
        uint8_t br_addr[MAC_SIZE];
        uint16_t length;
        uint8_t dsap;
        uint8_t ssap;
        int fd;
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        struct pollfd pfd;
        int offset = 0;
        struct tpacket_hdr * header;
        uint8_t * buf = NULL;
#else
        uint8_t buf[ETH_FRAME_SIZE];
        int frame_len = 0;
#endif
        struct eth_llc_frame * llc_frame;

        memset(br_addr, 0xff, MAC_SIZE * sizeof(uint8_t));

        while (true) {
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
                header = (void *) (eth_llc_data.rx_ring +
                                   offset * SHM_RDRB_BLOCK_SIZE);
                while (!(header->tp_status & TP_STATUS_USER)) {
                        pfd.fd = eth_llc_data.s_fd;
                        pfd.revents = 0;
                        pfd.events = POLLIN | POLLRDNORM | POLLERR;

                        if (poll(&pfd, 1, -1) <= 0) {
                                LOG_ERR("Failed to poll.");
                                continue;
                        }

                        header = (void *) (eth_llc_data.rx_ring +
                                           offset * SHM_RDRB_BLOCK_SIZE);
                }

                buf = (uint8_t * ) header + header->tp_mac;
#else
                frame_len = recv(eth_llc_data.s_fd, buf,
                                 SHIM_ETH_LLC_MAX_SDU_SIZE, 0);
                if (frame_len < 0) {
                        LOG_ERR("Failed to receive frame.");
                        continue;
                }
#endif
                llc_frame = (struct eth_llc_frame *) buf;

#ifdef __FreeBSD__
                if (memcmp(LLADDR(&eth_llc_data.device),
#else
                if (memcmp(eth_llc_data.device.sll_addr,
#endif
                           llc_frame->dst_hwaddr,
                           MAC_SIZE) &&
                    memcmp(br_addr, llc_frame->dst_hwaddr, MAC_SIZE)) {
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
                        offset = (offset + 1) & (SHM_BUFFER_SIZE - 1);
                        header->tp_status = TP_STATUS_KERNEL;
#endif
                        continue;
                }

                memcpy(&length, &llc_frame->length, sizeof(length));
                length = ntohs(length);

                if (length > 0x05FF) { /* DIX */
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
                        offset = (offset + 1) & (SHM_BUFFER_SIZE -1);
                        header->tp_status = TP_STATUS_KERNEL;
#endif
                        continue;
                }

                length -= LLC_HEADER_SIZE;

                dsap = reverse_bits(llc_frame->dsap);
                ssap = reverse_bits(llc_frame->ssap);

                if (ssap == MGMT_SAP && dsap == MGMT_SAP) {
                        eth_llc_ipcp_mgmt_frame(&llc_frame->payload,
                                                length,
                                                llc_frame->src_hwaddr);
                } else {
                        pthread_rwlock_rdlock(&eth_llc_data.flows_lock);

                        fd = eth_llc_data.ef_to_fd[dsap];
                        if (fd < 0) {
                                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
                                offset = (offset + 1) & (SHM_BUFFER_SIZE - 1);
                                header->tp_status = TP_STATUS_KERNEL;
#endif
                                continue;
                        }

                        if (eth_llc_data.fd_to_ef[fd].r_sap != ssap
                            || memcmp(eth_llc_data.fd_to_ef[fd].r_addr,
                                      llc_frame->src_hwaddr, MAC_SIZE)) {
                                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
                                offset = (offset + 1) & (SHM_BUFFER_SIZE -1);
                                header->tp_status = TP_STATUS_KERNEL;
#endif
                                continue;
                        }

                        pthread_rwlock_unlock(&eth_llc_data.flows_lock);

                        flow_write(fd, &llc_frame->payload, length);

                }
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
                offset = (offset + 1) & (SHM_BUFFER_SIZE -1);
                header->tp_status = TP_STATUS_KERNEL;
#endif
        }

        return (void *) 0;
}

static void * eth_llc_ipcp_sdu_writer(void * o)
{
        while (true) {
                int fd;
                struct shm_du_buff * sdb;
                uint8_t ssap;
                uint8_t dsap;
                uint8_t r_addr[MAC_SIZE];

                fd = ipcp_flow_read(&sdb);
                if (fd < 0)
                        continue;

                pthread_rwlock_rdlock(&ipcpi.state_lock);
                pthread_rwlock_rdlock(&eth_llc_data.flows_lock);

                ssap = reverse_bits(eth_llc_data.fd_to_ef[fd].sap);
                dsap = reverse_bits(eth_llc_data.fd_to_ef[fd].r_sap);
                memcpy(r_addr, eth_llc_data.fd_to_ef[fd].r_addr, MAC_SIZE);

                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);

                eth_llc_ipcp_send_frame(r_addr, dsap, ssap,
                                        shm_du_buff_head(sdb),
                                        shm_du_buff_tail(sdb)
                                        - shm_du_buff_head(sdb));
                ipcp_flow_del(sdb);
        }

        return (void *) 1;
}

void ipcp_sig_handler(int sig, siginfo_t * info, void * c)
{
        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                if (info->si_pid == irmd_api) {
                        LOG_DBG("IPCP %d terminating by order of %d. Bye.",
                                getpid(), info->si_pid);

                        pthread_rwlock_wrlock(&ipcpi.state_lock);

                        ipcp_set_state(IPCP_SHUTDOWN);

                        pthread_rwlock_unlock(&ipcpi.state_lock);
                }
        default:
                return;
        }
}

static int eth_llc_ipcp_bootstrap(struct dif_config * conf)
{
        int skfd = -1;
        struct ifreq ifr;
        int idx;
#ifdef __FreeBSD__
        struct ifaddrs * ifaddr;
        struct ifaddrs * ifa;
        struct sockaddr_dl device;
#else
        struct sockaddr_ll device;
#endif

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

        memcpy(ifr.ifr_name, conf->if_name, strlen(conf->if_name));

#ifdef __FreeBSD__
        if (getifaddrs(&ifaddr) < 0)  {
                LOG_ERR("Could not get interfaces.");
                return -1;
        }

        for (ifa = ifaddr, idx = 0; ifa != NULL; ifa = ifa->ifa_next, ++idx) {
                if (strcmp(ifa->ifa_name, conf->if_name))
                        continue;
                LOG_DBG("Interface %s found.", conf->if_name);
                memcpy(&ifr.ifr_addr, ifa->ifa_addr, sizeof(*ifa->ifa_addr));
                break;
        }

        if (ifa == NULL) {
                LOG_ERR("Interface not found.");
                freeifaddrs(ifaddr);
                return -1;
        }

        freeifaddrs(ifaddr);
#else
        skfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (skfd < 0) {
                LOG_ERR("Failed to open socket.");
                return -1;
        }

        if (ioctl(skfd, SIOCGIFHWADDR, &ifr)) {
                LOG_ERR("Failed to ioctl.");
                close(skfd);
                return -1;
        }

        close(skfd);

        idx = if_nametoindex(conf->if_name);
        if (idx == 0) {
                LOG_ERR("Failed to retrieve interface index.");
                close(skfd);
                return -1;
        }
#endif
        memset(&(device), 0, sizeof(device));
#ifdef __FreeBSD__
        device.sdl_index = idx;
        device.sdl_family = AF_LINK;
        memcpy(LLADDR(&device), ifr.ifr_addr.sa_data, MAC_SIZE);
        device.sdl_alen = MAC_SIZE;
        /* TODO: replace socket calls with bpf for BSD */
        LOG_MISSING;
        skfd = socket(AF_LINK, SOCK_RAW, 0);
#else
        device.sll_ifindex = idx;
        device.sll_family = AF_PACKET;
        memcpy(device.sll_addr, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
        device.sll_halen = MAC_SIZE;
        device.sll_protocol = htons(ETH_P_ALL);

        skfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_802_2));
#endif
        if (skfd < 0) {
                LOG_ERR("Failed to create socket.");
                return -1;
        }

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        if (SHIM_ETH_LLC_MAX_SDU_SIZE > SHM_RDRB_BLOCK_SIZE) {
                LOG_ERR("Max SDU size is bigger than DU map block size.");
                close(skfd);
                return -1;
        }

        req.tp_block_size = SHM_RDRB_BLOCK_SIZE;
        req.tp_frame_size = SHM_RDRB_BLOCK_SIZE;
        req.tp_block_nr = SHM_BUFFER_SIZE;
        req.tp_frame_nr = SHM_BUFFER_SIZE;

        if (setsockopt(skfd, SOL_PACKET, PACKET_RX_RING,
                       (void *) &req, sizeof(req))) {
                LOG_ERR("Failed to set sockopt PACKET_RX_RING");
                close(skfd);
                return -1;
        }

        if (setsockopt(skfd, SOL_PACKET, PACKET_TX_RING,
                       (void *) &req, sizeof(req))) {
                LOG_ERR("Failed to set sockopt PACKET_TX_RING");
                close(skfd);
                return -1;
        }
#endif
        if (bind(skfd, (struct sockaddr *) &device, sizeof(device))) {
                LOG_ERR("Failed to bind socket to interface");
                close(skfd);
                return -1;
        }

#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        eth_llc_data.rx_ring = mmap(NULL, 2 * SHM_RDRB_BLOCK_SIZE
                                    * SHM_BUFFER_SIZE,
                                    PROT_READ | PROT_WRITE, MAP_SHARED,
                                    skfd, 0);
        if (eth_llc_data.rx_ring == NULL) {
                LOG_ERR("Failed to mmap");
                close(skfd);
                return -1;
        }

        eth_llc_data.tx_ring = eth_llc_data.rx_ring
                + SHM_RDRB_BLOCK_SIZE * SHM_BUFFER_SIZE;
#endif
        pthread_rwlock_wrlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_INIT) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("IPCP in wrong state.");
                close(skfd);
                return -1;
        }

        eth_llc_data.s_fd = skfd;
        eth_llc_data.device = device;
#if defined(PACKET_RX_RING) && defined(PACKET_TX_RING)
        eth_llc_data.tx_offset = 0;
#endif

        ipcp_set_state(IPCP_ENROLLED);

        pthread_create(&eth_llc_data.sdu_reader,
                       NULL,
                       eth_llc_ipcp_sdu_reader,
                       NULL);

        pthread_create(&eth_llc_data.sdu_writer,
                       NULL,
                       eth_llc_ipcp_sdu_writer,
                       NULL);

        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_DBG("Bootstrapped shim IPCP over Ethernet with LLC with api %d.",
                getpid());

        return 0;
}

static int eth_llc_ipcp_name_reg(char * name)
{
        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (ipcp_data_add_reg_entry(ipcpi.data, name)) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to add %s to local registry.", name);
                return -1;
        }

        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_DBG("Registered %s.", name);

        return 0;
}

static int eth_llc_ipcp_name_unreg(char * name)
{
        pthread_rwlock_rdlock(&ipcpi.state_lock);

        ipcp_data_del_reg_entry(ipcpi.data, name);

        pthread_rwlock_unlock(&ipcpi.state_lock);

        return 0;
}

static int eth_llc_ipcp_flow_alloc(int           fd,
                                   char *        dst_name,
                                   char *        src_ae_name,
                                   enum qos_cube qos)
{
        uint8_t ssap = 0;
        uint8_t r_addr[MAC_SIZE];

        LOG_INFO("Allocating flow to %s.", dst_name);

        if (dst_name == NULL || src_ae_name == NULL)
                return -1;

        if (qos != QOS_CUBE_BE)
                LOG_DBG("QoS requested. Ethernet LLC can't do that. For now.");

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_ENROLLED) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_DBG("Won't allocate flow with non-enrolled IPCP.");
                return -1; /* -ENOTENROLLED */
        }

        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        ssap = bmp_allocate(eth_llc_data.saps);
        if (ssap < 0) {
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        eth_llc_data.fd_to_ef[fd].sap = ssap;
        eth_llc_data.ef_to_fd[ssap]   = fd;

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        memset(r_addr, 0xff, MAC_SIZE);

        if (eth_llc_ipcp_sap_alloc(r_addr, ssap, dst_name, src_ae_name) < 0) {
                pthread_rwlock_rdlock(&ipcpi.state_lock);
                pthread_rwlock_wrlock(&eth_llc_data.flows_lock);
                bmp_release(eth_llc_data.saps, eth_llc_data.fd_to_ef[fd].sap);
                eth_llc_data.fd_to_ef[fd].sap = -1;
                eth_llc_data.ef_to_fd[ssap]   = -1;
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        LOG_DBG("Pending flow with fd %d on SAP %d.", fd, ssap);

        return 0;
}

static int eth_llc_ipcp_flow_alloc_resp(int fd, int response)
{
        uint8_t ssap = 0;
        uint8_t r_sap = 0;
        uint8_t r_addr[MAC_SIZE];

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        ssap = bmp_allocate(eth_llc_data.saps);
        if (ssap < 0) {
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        eth_llc_data.fd_to_ef[fd].sap = ssap;
        memcpy(r_addr, eth_llc_data.fd_to_ef[fd].r_addr, MAC_SIZE);
        r_sap = eth_llc_data.fd_to_ef[fd].r_sap;
        eth_llc_data.ef_to_fd[ssap] = fd;

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        if (eth_llc_ipcp_sap_alloc_resp(r_addr, ssap, r_sap, response) < 0) {
                pthread_rwlock_rdlock(&ipcpi.state_lock);
                pthread_rwlock_wrlock(&eth_llc_data.flows_lock);
                bmp_release(eth_llc_data.saps, eth_llc_data.fd_to_ef[fd].sap);
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        LOG_DBG("Accepted flow, fd %d, SAP %d.", fd, ssap);

        return 0;
}

static int eth_llc_ipcp_flow_dealloc(int fd)
{
        uint8_t sap;
        uint8_t r_sap;
        uint8_t addr[MAC_SIZE];
        int ret;

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        r_sap = eth_llc_data.fd_to_ef[fd].r_sap;
        sap = eth_llc_data.fd_to_ef[fd].sap;
        memcpy(addr, eth_llc_data.fd_to_ef[fd].r_addr, MAC_SIZE);

        bmp_release(eth_llc_data.saps, sap);
        eth_llc_data.fd_to_ef[fd].sap = -1;
        eth_llc_data.fd_to_ef[fd].r_sap = -1;
        memset(&eth_llc_data.fd_to_ef[fd].r_addr, 0, MAC_SIZE);

        eth_llc_data.ef_to_fd[sap] = -1;

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);

        ret = eth_llc_ipcp_sap_dealloc(addr, r_sap);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        if (ret < 0)
                LOG_DBG("Could not notify remote.");

        LOG_DBG("Flow with fd %d deallocated.", fd);

        return 0;
}

static struct ipcp_ops eth_llc_ops = {
        .ipcp_bootstrap       = eth_llc_ipcp_bootstrap,
        .ipcp_enroll          = NULL,
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

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        if (ipcp_parse_arg(argc, argv)) {
                LOG_ERR("Failed to parse arguments.");
                exit(EXIT_FAILURE);
        }

        if (eth_llc_data_init() < 0)
                exit(EXIT_FAILURE);

        if (ap_init(NULL) < 0) {
                close_logfile();
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

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (ipcp_init(THIS_TYPE, &eth_llc_ops) < 0) {
                close_logfile();
                exit(EXIT_FAILURE);
        }

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        if (ipcp_create_r(getpid())) {
                LOG_ERR("Failed to notify IRMd we are initialized.");
                close_logfile();
                exit(EXIT_FAILURE);
        }

        ipcp_fini();

        pthread_cancel(eth_llc_data.sdu_reader);
        pthread_cancel(eth_llc_data.sdu_writer);

        pthread_join(eth_llc_data.sdu_writer, NULL);
        pthread_join(eth_llc_data.sdu_reader, NULL);

        ap_fini();

        eth_llc_data_fini();

        close_logfile();

        exit(EXIT_SUCCESS);
}
