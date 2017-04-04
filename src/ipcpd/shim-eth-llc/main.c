/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Shim IPC process over Ethernet with LLC
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define _DEFAULT_SOURCE

#define OUROBOROS_PREFIX "ipcpd/shim-eth-llc"

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/logs.h>
#include <ouroboros/time_utils.h>

#include "ipcp.h"
#include "shim_eth_llc_messages.pb-c.h"

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

typedef ShimEthLlcMsg shim_eth_llc_msg_t;

#define THIS_TYPE IPCP_SHIM_ETH_LLC
#define MGMT_SAP 0x01
#define MAC_SIZE 6
#define LLC_HEADER_SIZE 3
#define MAX_SAPS 64
#define ETH_HEADER_SIZE (2 * MAC_SIZE + 2)
#define ETH_FRAME_SIZE (ETH_HEADER_SIZE + LLC_HEADER_SIZE \
                        + SHIM_ETH_LLC_MAX_SDU_SIZE)
#define SHIM_ETH_LLC_MAX_SDU_SIZE (1500 - LLC_HEADER_SIZE)

#define EVENT_WAIT_TIMEOUT 100 /* us */
#define NAME_QUERY_TIMEOUT 100000000 /* ns */
#define MGMT_TIMEOUT 100 /* ms */

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
        flow_set_t *       np1_flows;
        fqueue_t *         fq;
        int *              ef_to_fd;
        struct ef *        fd_to_ef;
        pthread_rwlock_t   flows_lock;

        pthread_t          sdu_writer;
        pthread_t          sdu_reader;

        /* Handle mgmt frames in a different thread */
        pthread_t          mgmt_handler;
        pthread_mutex_t    mgmt_lock;
        pthread_cond_t     mgmt_cond;
        uint8_t            mgmt_r_addr[MAC_SIZE];
        uint8_t            mgmt_buf[ETH_FRAME_SIZE];
        size_t             mgmt_len;
        bool               mgmt_arrived;
} eth_llc_data;

static int eth_llc_data_init(void)
{
        int i;
        int ret = -1;

        eth_llc_data.fd_to_ef = malloc(sizeof(struct ef) * IRMD_MAX_FLOWS);
        if (eth_llc_data.fd_to_ef == NULL)
                return -ENOMEM;

        eth_llc_data.ef_to_fd = malloc(sizeof(struct ef) * MAX_SAPS);
        if (eth_llc_data.ef_to_fd == NULL) {
                ret = -ENOMEM;
                goto free_fd_to_ef;
        }

        eth_llc_data.saps = bmp_create(MAX_SAPS, 2);
        if (eth_llc_data.saps == NULL) {
                ret = -ENOMEM;
                goto free_ef_to_fd;
        }

        eth_llc_data.np1_flows = flow_set_create();
        if (eth_llc_data.np1_flows == NULL) {
                ret = -ENOMEM;
                goto bmp_destroy;
        }

        eth_llc_data.fq = fqueue_create();
        if (eth_llc_data.fq == NULL) {
                ret = -ENOMEM;
                goto flow_set_destroy;
        }

        for (i = 0; i < MAX_SAPS; ++i)
                eth_llc_data.ef_to_fd[i] = -1;

        for (i = 0; i < IRMD_MAX_FLOWS; ++i) {
                eth_llc_data.fd_to_ef[i].sap   = -1;
                eth_llc_data.fd_to_ef[i].r_sap = -1;
                memset(&eth_llc_data.fd_to_ef[i].r_addr, 0, MAC_SIZE);
        }

        if (pthread_rwlock_init(&eth_llc_data.flows_lock, NULL))
                goto fqueue_destroy;

        if (pthread_mutex_init(&eth_llc_data.mgmt_lock, NULL))
                goto flow_lock_destroy;

        if (pthread_cond_init(&eth_llc_data.mgmt_cond, NULL))
                goto mgmt_lock_destroy;

        return 0;

 mgmt_lock_destroy:
        pthread_mutex_destroy(&eth_llc_data.mgmt_lock);
 flow_lock_destroy:
        pthread_rwlock_destroy(&eth_llc_data.flows_lock);
 fqueue_destroy:
        fqueue_destroy(eth_llc_data.fq);
 flow_set_destroy:
        flow_set_destroy(eth_llc_data.np1_flows);
 bmp_destroy:
        bmp_destroy(eth_llc_data.saps);
 free_ef_to_fd:
        free(eth_llc_data.ef_to_fd);
 free_fd_to_ef:
        free(eth_llc_data.fd_to_ef);

        return ret;
}

void eth_llc_data_fini(void)
{
        pthread_cond_destroy(&eth_llc_data.mgmt_cond);
        pthread_mutex_destroy(&eth_llc_data.mgmt_lock);
        pthread_rwlock_destroy(&eth_llc_data.flows_lock);
        fqueue_destroy(eth_llc_data.fq);
        flow_set_destroy(eth_llc_data.np1_flows);
        bmp_destroy(eth_llc_data.saps);
        free(eth_llc_data.fd_to_ef);
        free(eth_llc_data.ef_to_fd);
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
        uint32_t               frame_len = 0;
        uint8_t                cf = 0x03;
        uint16_t               length;
        uint8_t                frame[SHIM_ETH_LLC_MAX_SDU_SIZE];
        struct eth_llc_frame * llc_frame;

        if (payload == NULL) {
                log_err("Payload was NULL.");
                return -1;
        }

        if (len > SHIM_ETH_LLC_MAX_SDU_SIZE)
                return -1;

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

        if (sendto(eth_llc_data.s_fd,
                   frame,
                   frame_len,
                   0,
                   (struct sockaddr *) &eth_llc_data.device,
                   sizeof(eth_llc_data.device)) <= 0) {
                log_err("Failed to send message.");
                return -1;
        }

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
                log_err("Failed to send management frame.");
                free(buf);
                return -1;
        }

        free(buf);

        return 0;
}

static int eth_llc_ipcp_sap_alloc(uint8_t * dst_addr,
                                  uint8_t   ssap,
                                  char *    dst_name,
                                  qoscube_t cube)
{
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;

        msg.code        = SHIM_ETH_LLC_MSG_CODE__FLOW_REQ;
        msg.has_ssap    = true;
        msg.ssap        = ssap;
        msg.dst_name    = dst_name;
        msg.has_qoscube = true;
        msg.qoscube     = cube;

        return eth_llc_ipcp_send_mgmt_frame(&msg, dst_addr);
}

static int eth_llc_ipcp_sap_alloc_resp(uint8_t * dst_addr,
                                       uint8_t   ssap,
                                       uint8_t   dsap,
                                       int       response)
{
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;

        msg.code         = SHIM_ETH_LLC_MSG_CODE__FLOW_REPLY;
        msg.has_ssap     = true;
        msg.ssap         = ssap;
        msg.has_dsap     = true;
        msg.dsap         = dsap;
        msg.has_response = true;
        msg.response     = response;

        return eth_llc_ipcp_send_mgmt_frame(&msg, dst_addr);
}

static int eth_llc_ipcp_sap_req(uint8_t   r_sap,
                                uint8_t * r_addr,
                                char *    dst_name,
                                qoscube_t cube)
{
        int fd;

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        /* reply to IRM, called under lock to prevent race */
        fd = ipcp_flow_req_arr(getpid(), dst_name, cube);
        if (fd < 0) {
                log_err("Could not get new flow from IRMd.");
                return -1;
        }

        eth_llc_data.fd_to_ef[fd].r_sap = r_sap;
        memcpy(eth_llc_data.fd_to_ef[fd].r_addr, r_addr, MAC_SIZE);

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        log_dbg("New flow request, fd %d, remote SAP %d.", fd, r_sap);

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
        pthread_rwlock_wrlock(& eth_llc_data.flows_lock);

        fd = eth_llc_data.ef_to_fd[dsap];
        if (fd < 0) {
                pthread_rwlock_unlock(& eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_err("No flow found with that SAP.");
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

        log_dbg("Flow reply, fd %d, SSAP %d, DSAP %d.", fd, ssap, dsap);

        if ((ret = ipcp_flow_alloc_reply(fd, response)) < 0)
                return -1;

        return ret;

}

static int eth_llc_ipcp_name_query_req(char *    name,
                                       uint8_t * r_addr)
{
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;

        if (shim_data_reg_has(ipcpi.shim_data, name)) {
                msg.code     = SHIM_ETH_LLC_MSG_CODE__NAME_QUERY_REPLY;
                msg.dst_name = name;

                eth_llc_ipcp_send_mgmt_frame(&msg, r_addr);
        }

        return 0;
}

static int eth_llc_ipcp_name_query_reply(char *    name,
                                         uint8_t * r_addr)
{
        uint64_t           address = 0;
        struct list_head * pos;

        memcpy(&address, r_addr, MAC_SIZE);

        shim_data_dir_add_entry(ipcpi.shim_data, name, address);

        pthread_mutex_lock(&ipcpi.shim_data->dir_queries_lock);
        list_for_each(pos, &ipcpi.shim_data->dir_queries) {
                struct dir_query * e =
                        list_entry(pos, struct dir_query, next);
                if (strcmp(e->name, name) == 0) {
                        shim_data_dir_query_respond(e);
                }
        }
        pthread_mutex_unlock(&ipcpi.shim_data->dir_queries_lock);

        return 0;
}

static int eth_llc_ipcp_mgmt_frame(uint8_t * buf,
                                   size_t    len,
                                   uint8_t * r_addr)
{
        shim_eth_llc_msg_t * msg;

        msg = shim_eth_llc_msg__unpack(NULL, len, buf);
        if (msg == NULL) {
                log_err("Failed to unpack.");
                return -1;
        }

        switch (msg->code) {
        case SHIM_ETH_LLC_MSG_CODE__FLOW_REQ:
                if (shim_data_reg_has(ipcpi.shim_data, msg->dst_name)) {
                        eth_llc_ipcp_sap_req(msg->ssap,
                                             r_addr,
                                             msg->dst_name,
                                             msg->qoscube);
                }
                break;
        case SHIM_ETH_LLC_MSG_CODE__FLOW_REPLY:
                eth_llc_ipcp_sap_alloc_reply(msg->ssap,
                                             r_addr,
                                             msg->dsap,
                                             msg->response);
                break;
        case SHIM_ETH_LLC_MSG_CODE__NAME_QUERY_REQ:
                eth_llc_ipcp_name_query_req(msg->dst_name, r_addr);
                break;
        case SHIM_ETH_LLC_MSG_CODE__NAME_QUERY_REPLY:
                eth_llc_ipcp_name_query_reply(msg->dst_name, r_addr);
                break;
        default:
                log_err("Unknown message received %d.", msg->code);
                shim_eth_llc_msg__free_unpacked(msg, NULL);
                return -1;
        }

        shim_eth_llc_msg__free_unpacked(msg, NULL);
        return 0;
}

static void * eth_llc_ipcp_mgmt_handler(void * o)
{
        int             ret;
        struct timespec timeout = {(MGMT_TIMEOUT / 1000),
                                   (MGMT_TIMEOUT % 1000) * MILLION};

        (void) o;

        while (true) {
                ret = 0;

                pthread_rwlock_rdlock(&ipcpi.state_lock);
                if (ipcp_get_state() != IPCP_OPERATIONAL) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        return (void *) 0;
                }

                pthread_mutex_lock(&eth_llc_data.mgmt_lock);

                while (eth_llc_data.mgmt_arrived == false &&
                       ret != -ETIMEDOUT)
                        ret = -pthread_cond_timedwait(&eth_llc_data.mgmt_cond,
                                                      &eth_llc_data.mgmt_lock,
                                                      &timeout);

                if (ret == -ETIMEDOUT) {
                        pthread_mutex_unlock(&eth_llc_data.mgmt_lock);
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        continue;
                }

                eth_llc_ipcp_mgmt_frame(eth_llc_data.mgmt_buf,
                                        eth_llc_data.mgmt_len,
                                        eth_llc_data.mgmt_r_addr);
                eth_llc_data.mgmt_arrived = false;
                pthread_mutex_unlock(&eth_llc_data.mgmt_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
        }
}

static void * eth_llc_ipcp_sdu_reader(void * o)
{
        uint8_t                br_addr[MAC_SIZE];
        uint16_t               length;
        uint8_t                dsap;
        uint8_t                ssap;
        int                    fd;
        uint8_t                buf[ETH_FRAME_SIZE];
        int                    frame_len = 0;
        struct eth_llc_frame * llc_frame;

        (void) o;

        memset(br_addr, 0xff, MAC_SIZE * sizeof(uint8_t));

        while (true) {
                frame_len = recv(eth_llc_data.s_fd, buf,
                                 SHIM_ETH_LLC_MAX_SDU_SIZE, 0);
                if (frame_len < 0)
                        continue;

                pthread_rwlock_rdlock(&ipcpi.state_lock);
                if (ipcp_get_state() != IPCP_OPERATIONAL) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        return (void *) 0;
                }

                llc_frame = (struct eth_llc_frame *) buf;

#ifdef __FreeBSD__
                if (memcmp(LLADDR(&eth_llc_data.device),
#else
                if (memcmp(eth_llc_data.device.sll_addr,
#endif
                           llc_frame->dst_hwaddr,
                           MAC_SIZE) &&
                           memcmp(br_addr, llc_frame->dst_hwaddr, MAC_SIZE)) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        continue;
                }

                memcpy(&length, &llc_frame->length, sizeof(length));
                length = ntohs(length);

                if (length > 0x05FF) {  /* DIX */
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        continue;
                }

                length -= LLC_HEADER_SIZE;

                dsap = reverse_bits(llc_frame->dsap);
                ssap = reverse_bits(llc_frame->ssap);

                if (ssap == MGMT_SAP && dsap == MGMT_SAP) {
                        pthread_mutex_lock(&eth_llc_data.mgmt_lock);
                        memcpy(eth_llc_data.mgmt_buf,
                               &llc_frame->payload,
                               length);
                        memcpy(eth_llc_data.mgmt_r_addr,
                               llc_frame->src_hwaddr,
                               MAC_SIZE);
                        eth_llc_data.mgmt_len = length;
                        eth_llc_data.mgmt_arrived = true;
                        pthread_cond_signal(&eth_llc_data.mgmt_cond);
                        pthread_mutex_unlock(&eth_llc_data.mgmt_lock);
                } else {
                        pthread_rwlock_rdlock(&eth_llc_data.flows_lock);

                        fd = eth_llc_data.ef_to_fd[dsap];
                        if (fd < 0) {
                                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                                pthread_rwlock_unlock(&ipcpi.state_lock);
                                continue;
                        }

                        if (eth_llc_data.fd_to_ef[fd].r_sap != ssap
                            || memcmp(eth_llc_data.fd_to_ef[fd].r_addr,
                                      llc_frame->src_hwaddr, MAC_SIZE)) {
                                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                                pthread_rwlock_unlock(&ipcpi.state_lock);
                                continue;
                        }

                        pthread_rwlock_unlock(&eth_llc_data.flows_lock);

                        flow_write(fd, &llc_frame->payload, length);
                }

                pthread_rwlock_unlock(&ipcpi.state_lock);
        }

        return (void *) 0;
}

static void * eth_llc_ipcp_sdu_writer(void * o)
{
        int                  fd;
        struct shm_du_buff * sdb;
        uint8_t              ssap;
        uint8_t              dsap;
        uint8_t              r_addr[MAC_SIZE];
        struct timespec      timeout = {0, EVENT_WAIT_TIMEOUT * 1000};

        (void) o;

        while (flow_event_wait(eth_llc_data.np1_flows,
                               eth_llc_data.fq,
                               &timeout)) {

                pthread_rwlock_rdlock(&ipcpi.state_lock);

                if (ipcp_get_state() != IPCP_OPERATIONAL) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        return (void *) 0;
                }

                pthread_rwlock_rdlock(&eth_llc_data.flows_lock);
                while ((fd = fqueue_next(eth_llc_data.fq)) >= 0) {
                        if (ipcp_flow_read(fd, &sdb)) {
                                log_err("Bad read from fd %d.", fd);
                                continue;
                        }

                        ssap = reverse_bits(eth_llc_data.fd_to_ef[fd].sap);
                        dsap = reverse_bits(eth_llc_data.fd_to_ef[fd].r_sap);
                        memcpy(r_addr,
                               eth_llc_data.fd_to_ef[fd].r_addr,
                               MAC_SIZE);

                        eth_llc_ipcp_send_frame(r_addr, dsap, ssap,
                                                shm_du_buff_head(sdb),
                                                shm_du_buff_tail(sdb)
                                                - shm_du_buff_head(sdb));
                        ipcp_flow_del(sdb);
                }
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
        }

        return (void *) 1;
}

void ipcp_sig_handler(int         sig,
                      siginfo_t * info,
                      void *      c)
{
        (void) c;

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                if (info->si_pid == ipcpi.irmd_api) {
                        pthread_rwlock_wrlock(&ipcpi.state_lock);

                        if (ipcp_get_state() == IPCP_INIT)
                                ipcp_set_state(IPCP_NULL);

                        if (ipcp_get_state() == IPCP_OPERATIONAL)
                                ipcp_set_state(IPCP_SHUTDOWN);

                        pthread_rwlock_unlock(&ipcpi.state_lock);
                }
        default:
                return;
        }
}

static int eth_llc_ipcp_bootstrap(struct dif_config * conf)
{
        int                skfd = -1;
        struct ifreq       ifr;
        int                idx;
#ifdef __FreeBSD__
        struct ifaddrs *   ifaddr;
        struct ifaddrs *   ifa;
        struct sockaddr_dl device;
#else
        struct sockaddr_ll device;
#endif
        struct timeval tv = {0, EVENT_WAIT_TIMEOUT * 1000};

        assert(conf);
        assert(conf->type == THIS_TYPE);

        if (conf->if_name == NULL) {
                log_err("Interface name is NULL.");
                return -1;
        }

        memset(&ifr, 0, sizeof(ifr));

        memcpy(ifr.ifr_name, conf->if_name, strlen(conf->if_name));

#ifdef __FreeBSD__
        if (getifaddrs(&ifaddr) < 0)  {
                log_err("Could not get interfaces.");
                return -1;
        }

        for (ifa = ifaddr, idx = 0; ifa != NULL; ifa = ifa->ifa_next, ++idx) {
                if (strcmp(ifa->ifa_name, conf->if_name))
                        continue;
                log_dbg("Interface %s found.", conf->if_name);
                memcpy(&ifr.ifr_addr, ifa->ifa_addr, sizeof(*ifa->ifa_addr));
                break;
        }

        if (ifa == NULL) {
                log_err("Interface not found.");
                freeifaddrs(ifaddr);
                return -1;
        }

        freeifaddrs(ifaddr);
#else
        skfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (skfd < 0) {
                log_err("Failed to open socket.");
                return -1;
        }

        if (ioctl(skfd, SIOCGIFHWADDR, &ifr)) {
                log_err("Failed to ioctl.");
                close(skfd);
                return -1;
        }

        close(skfd);

        idx = if_nametoindex(conf->if_name);
        if (idx == 0) {
                log_err("Failed to retrieve interface index.");
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
                log_err("Failed to create socket.");
                return -1;
        }

        if (bind(skfd, (struct sockaddr *) &device, sizeof(device))) {
                log_err("Failed to bind socket to interface");
                close(skfd);
                return -1;
        }

        if (setsockopt(skfd, SOL_SOCKET, SO_RCVTIMEO,
                       (void *) &tv, sizeof(tv))) {
                log_err("Failed to set socket timeout");
                close(skfd);
                return -1;
        }

        pthread_rwlock_wrlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_INIT) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_err("IPCP in wrong state.");
                close(skfd);
                return -1;
        }

        eth_llc_data.s_fd = skfd;
        eth_llc_data.device = device;

        ipcp_set_state(IPCP_OPERATIONAL);

        pthread_create(&eth_llc_data.mgmt_handler,
                       NULL,
                       eth_llc_ipcp_mgmt_handler,
                       NULL);

        pthread_create(&eth_llc_data.sdu_reader,
                       NULL,
                       eth_llc_ipcp_sdu_reader,
                       NULL);

        pthread_create(&eth_llc_data.sdu_writer,
                       NULL,
                       eth_llc_ipcp_sdu_writer,
                       NULL);

        pthread_rwlock_unlock(&ipcpi.state_lock);

        log_dbg("Bootstrapped shim IPCP over Ethernet with LLC with api %d.",
                getpid());

        return 0;
}

static int eth_llc_ipcp_name_reg(char * name)
{
        char * name_dup;

        name_dup = strdup(name);
        if (name_dup == NULL) {
                log_err("Failed to duplicate name.");
                return -ENOMEM;
        }

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (shim_data_reg_add_entry(ipcpi.shim_data, name_dup)) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_err("Failed to add %s to local registry.", name);
                free(name_dup);
                return -1;
        }

        pthread_rwlock_unlock(&ipcpi.state_lock);

        log_dbg("Registered %s.", name);

        return 0;
}

static int eth_llc_ipcp_name_unreg(char * name)
{
        pthread_rwlock_rdlock(&ipcpi.state_lock);

        shim_data_reg_del_entry(ipcpi.shim_data, name);

        pthread_rwlock_unlock(&ipcpi.state_lock);

        return 0;
}

static int eth_llc_ipcp_name_query(char * name)
{
        uint8_t            r_addr[MAC_SIZE];
        struct timespec    timeout = {0, NAME_QUERY_TIMEOUT};
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;
        struct dir_query * query;
        int                ret;

        if (shim_data_dir_has(ipcpi.shim_data, name))
                return 0;

        msg.code     = SHIM_ETH_LLC_MSG_CODE__NAME_QUERY_REQ;
        msg.dst_name = name;

        memset(r_addr, 0xff, MAC_SIZE);

        query = shim_data_dir_query_create(name);
        if (query == NULL)
                return -1;

        pthread_mutex_lock(&ipcpi.shim_data->dir_queries_lock);
        list_add(&query->next, &ipcpi.shim_data->dir_queries);
        pthread_mutex_unlock(&ipcpi.shim_data->dir_queries_lock);

        eth_llc_ipcp_send_mgmt_frame(&msg, r_addr);

        ret = shim_data_dir_query_wait(query, &timeout);

        pthread_mutex_lock(&ipcpi.shim_data->dir_queries_lock);
        list_del(&query->next);
        shim_data_dir_query_destroy(query);
        pthread_mutex_unlock(&ipcpi.shim_data->dir_queries_lock);

        return ret;
}

static int eth_llc_ipcp_flow_alloc(int       fd,
                                   char *    dst_name,
                                   qoscube_t cube)
{
        uint8_t  ssap = 0;
        uint8_t  r_addr[MAC_SIZE];
        uint64_t addr = 0;

        log_dbg("Allocating flow to %s.", dst_name);

        if (dst_name == NULL)
                return -1;

        if (cube != QOS_CUBE_BE && cube != QOS_CUBE_FRC) {
                log_dbg("Unsupported QoS requested.");
                return -1;
        }

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_dbg("Won't allocate flow with non-enrolled IPCP.");
                return -1; /* -ENOTENROLLED */
        }

        if (!shim_data_dir_has(ipcpi.shim_data, dst_name)) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_err("Destination unreachable.");
                return -1;
        }
        addr = shim_data_dir_get_addr(ipcpi.shim_data, dst_name);

        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        ssap =  bmp_allocate(eth_llc_data.saps);
        if (!bmp_is_id_valid(eth_llc_data.saps, ssap)) {
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        eth_llc_data.fd_to_ef[fd].sap = ssap;
        eth_llc_data.ef_to_fd[ssap]   = fd;

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        memcpy(r_addr, &addr, MAC_SIZE);

        if (eth_llc_ipcp_sap_alloc(r_addr, ssap, dst_name, cube) < 0) {
                pthread_rwlock_rdlock(&ipcpi.state_lock);
                pthread_rwlock_wrlock(&eth_llc_data.flows_lock);
                bmp_release(eth_llc_data.saps, eth_llc_data.fd_to_ef[fd].sap);
                eth_llc_data.fd_to_ef[fd].sap = -1;
                eth_llc_data.ef_to_fd[ssap]   = -1;
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                return -1;
        }

        flow_set_add(eth_llc_data.np1_flows, fd);

        log_dbg("Pending flow with fd %d on SAP %d.", fd, ssap);

        return 0;
}

static int eth_llc_ipcp_flow_alloc_resp(int fd,
                                        int response)
{
        uint8_t ssap = 0;
        uint8_t r_sap = 0;
        uint8_t r_addr[MAC_SIZE];

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        ssap = bmp_allocate(eth_llc_data.saps);
        if (!bmp_is_id_valid(eth_llc_data.saps, ssap)) {
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

        flow_set_add(eth_llc_data.np1_flows, fd);

        log_dbg("Accepted flow, fd %d, SAP %d.", fd, (uint8_t)ssap);

        return 0;
}

static int eth_llc_ipcp_flow_dealloc(int fd)
{
        uint8_t sap;
        uint8_t addr[MAC_SIZE];

        ipcp_flow_fini(fd);

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                log_dbg("Won't register with non-enrolled IPCP.");
                return -1; /* -ENOTENROLLED */
        }

        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        flow_set_del(eth_llc_data.np1_flows, fd);

        sap = eth_llc_data.fd_to_ef[fd].sap;
        memcpy(addr, eth_llc_data.fd_to_ef[fd].r_addr, MAC_SIZE);
        bmp_release(eth_llc_data.saps, sap);
        eth_llc_data.fd_to_ef[fd].sap = -1;
        eth_llc_data.fd_to_ef[fd].r_sap = -1;
        memset(&eth_llc_data.fd_to_ef[fd].r_addr, 0, MAC_SIZE);

        eth_llc_data.ef_to_fd[sap] = -1;

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        flow_dealloc(fd);

        log_dbg("Flow with fd %d deallocated.", fd);

        return 0;
}

static struct ipcp_ops eth_llc_ops = {
        .ipcp_bootstrap       = eth_llc_ipcp_bootstrap,
        .ipcp_enroll          = NULL,
        .ipcp_name_reg        = eth_llc_ipcp_name_reg,
        .ipcp_name_unreg      = eth_llc_ipcp_name_unreg,
        .ipcp_name_query      = eth_llc_ipcp_name_query,
        .ipcp_flow_alloc      = eth_llc_ipcp_flow_alloc,
        .ipcp_flow_alloc_resp = eth_llc_ipcp_flow_alloc_resp,
        .ipcp_flow_dealloc    = eth_llc_ipcp_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        struct sigaction sig_act;
        sigset_t  sigset;

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        /* init sig_act */
        memset(&sig_act, 0, sizeof(sig_act));

        /* install signal traps */
        sig_act.sa_sigaction = &ipcp_sig_handler;
        sig_act.sa_flags     = SA_SIGINFO;

        sigaction(SIGINT,  &sig_act, NULL);
        sigaction(SIGTERM, &sig_act, NULL);
        sigaction(SIGHUP,  &sig_act, NULL);
        sigaction(SIGPIPE, &sig_act, NULL);

        if (ipcp_init(argc, argv, THIS_TYPE, &eth_llc_ops) < 0) {
                ipcp_create_r(getpid(), -1);
                exit(EXIT_FAILURE);
        }

        if (eth_llc_data_init() < 0) {
                log_err("Failed to init shim-eth-llc data.");
                ipcp_create_r(getpid(), -1);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }


        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                ipcp_create_r(getpid(), -1);
                eth_llc_data_fini();
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        if (ipcp_create_r(getpid(), 0)) {
                log_err("Failed to notify IRMd we are initialized.");
                ipcp_set_state(IPCP_NULL);
                ipcp_shutdown();
                eth_llc_data_fini();
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        ipcp_shutdown();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                pthread_join(eth_llc_data.sdu_writer, NULL);
                pthread_join(eth_llc_data.sdu_reader, NULL);
                pthread_join(eth_llc_data.mgmt_handler, NULL);
        }

        eth_llc_data_fini();

        ipcp_fini();

        exit(EXIT_SUCCESS);
}
