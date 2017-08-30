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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifdef __APPLE__
#define _BSD_SOURCE
#define _DARWIN_C_SOURCE
#else
#define _POSIX_C_SOURCE 200112L
#endif

#include "config.h"

#define OUROBOROS_PREFIX "ipcpd/shim-eth-llc"

#include <ouroboros/hash.h>
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
#include "shim-data.h"
#include "shim_eth_llc_messages.pb-c.h"

#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <net/if.h>
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

#ifdef __APPLE__
#include <net/if_dl.h>
#include <ifaddrs.h>
#endif

#include <poll.h>
#include <sys/mman.h>

#if defined(HAVE_NETMAP)
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#elif defined(HAVE_BPF)
#define BPF_DEV_MAX               256
#define BPF_BLEN                  sysconf(_SC_PAGESIZE)
#include <net/bpf.h>
#endif

#define THIS_TYPE                 IPCP_SHIM_ETH_LLC

#define MGMT_SAP                  0x01
#define MAC_SIZE                  6
#define LLC_HEADER_SIZE           3
#define MAX_SAPS                  64
#define ETH_HEADER_SIZE           (2 * MAC_SIZE + 2)
#define ETH_FRAME_SIZE            (ETH_HEADER_SIZE + LLC_HEADER_SIZE \
                                   + SHIM_ETH_LLC_MAX_SDU_SIZE)
#define SHIM_ETH_LLC_MAX_SDU_SIZE (1500 - LLC_HEADER_SIZE)
#define EVENT_WAIT_TIMEOUT        10000 /* us */
#define NAME_QUERY_TIMEOUT        2000  /* ms */
#define MGMT_TIMEOUT              100   /* ms */

typedef ShimEthLlcMsg shim_eth_llc_msg_t;

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

struct mgmt_frame {
        struct list_head next;
        uint8_t          r_addr[MAC_SIZE];
        uint8_t          buf[ETH_FRAME_SIZE];
        size_t           len;
};

struct {
        struct shim_data * shim_data;

#if defined(HAVE_NETMAP)
        struct nm_desc *   nmd;
        uint8_t            hw_addr[MAC_SIZE];
        struct pollfd      poll_in;
        struct pollfd      poll_out;
#elif defined(HAVE_BPF)
        int                bpf;
        uint8_t            hw_addr[MAC_SIZE];
#elif defined HAVE_RAW_SOCKETS
        int                s_fd;
        struct sockaddr_ll device;
#endif /* HAVE_NETMAP */

        struct bmp *       saps;
        fset_t *           np1_flows;
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
        struct list_head   mgmt_frames;

} eth_llc_data;

static int eth_llc_data_init(void)
{
        int                i;
        int                ret = -ENOMEM;
        pthread_condattr_t cattr;

        eth_llc_data.fd_to_ef =
                malloc(sizeof(*eth_llc_data.fd_to_ef) * SYS_MAX_FLOWS);
        if (eth_llc_data.fd_to_ef == NULL)
                goto fail_fd_to_ef;

        eth_llc_data.ef_to_fd =
                malloc(sizeof(*eth_llc_data.ef_to_fd) * MAX_SAPS);
        if (eth_llc_data.ef_to_fd == NULL)
                goto fail_ef_to_fd;

        eth_llc_data.saps = bmp_create(MAX_SAPS, 2);
        if (eth_llc_data.saps == NULL)
                goto fail_saps;

        eth_llc_data.np1_flows = fset_create();
        if (eth_llc_data.np1_flows == NULL)
                goto fail_np1_flows;

        eth_llc_data.fq = fqueue_create();
        if (eth_llc_data.fq == NULL)
                goto fail_fq;

        for (i = 0; i < MAX_SAPS; ++i)
                eth_llc_data.ef_to_fd[i] = -1;

        for (i = 0; i < SYS_MAX_FLOWS; ++i) {
                eth_llc_data.fd_to_ef[i].sap   = -1;
                eth_llc_data.fd_to_ef[i].r_sap = -1;
                memset(&eth_llc_data.fd_to_ef[i].r_addr, 0, MAC_SIZE);
        }

        eth_llc_data.shim_data = shim_data_create();
        if (eth_llc_data.shim_data == NULL)
                goto fail_shim_data;

        ret = -1;

        if (pthread_rwlock_init(&eth_llc_data.flows_lock, NULL))
                goto fail_flows_lock;

        if (pthread_mutex_init(&eth_llc_data.mgmt_lock, NULL))
                goto fail_mgmt_lock;

        if (pthread_condattr_init(&cattr))
                goto fail_condattr;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif

        if (pthread_cond_init(&eth_llc_data.mgmt_cond, &cattr))
                goto fail_mgmt_cond;

        pthread_condattr_destroy(&cattr);

        list_head_init(&eth_llc_data.mgmt_frames);

        return 0;

 fail_mgmt_cond:
        pthread_condattr_destroy(&cattr);
 fail_condattr:
        pthread_mutex_destroy(&eth_llc_data.mgmt_lock);
 fail_mgmt_lock:
        pthread_rwlock_destroy(&eth_llc_data.flows_lock);
 fail_flows_lock:
        shim_data_destroy(eth_llc_data.shim_data);
 fail_shim_data:
        fqueue_destroy(eth_llc_data.fq);
 fail_fq:
        fset_destroy(eth_llc_data.np1_flows);
 fail_np1_flows:
        bmp_destroy(eth_llc_data.saps);
 fail_saps:
        free(eth_llc_data.ef_to_fd);
 fail_ef_to_fd:
        free(eth_llc_data.fd_to_ef);
 fail_fd_to_ef:
        return ret;
}

void eth_llc_data_fini(void)
{
#if defined(HAVE_NETMAP)
        nm_close(eth_llc_data.nmd);
#elif defined(HAVE_BPF)
        close(eth_llc_data.bpf);
#elif defined(HAVE_RAW_SOCKETS)
        close(eth_llc_data.s_fd);
#endif
        pthread_cond_destroy(&eth_llc_data.mgmt_cond);
        pthread_mutex_destroy(&eth_llc_data.mgmt_lock);
        pthread_rwlock_destroy(&eth_llc_data.flows_lock);
        shim_data_destroy(eth_llc_data.shim_data);
        fqueue_destroy(eth_llc_data.fq);
        fset_destroy(eth_llc_data.np1_flows);
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

static int eth_llc_ipcp_send_frame(const uint8_t * dst_addr,
                                   uint8_t         dsap,
                                   uint8_t         ssap,
                                   const uint8_t * payload,
                                   size_t          len)
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
#if defined(HAVE_NETMAP) || defined(HAVE_BPF)
               eth_llc_data.hw_addr,
#elif defined(HAVE_RAW_SOCKETS)
               eth_llc_data.device.sll_addr,
#endif /* HAVE_NETMAP */
               MAC_SIZE);
        length = htons(LLC_HEADER_SIZE + len);
        memcpy(&llc_frame->length, &length, sizeof(length));
        llc_frame->dsap = dsap;
        llc_frame->ssap = ssap;
        llc_frame->cf   = cf;
        memcpy(&llc_frame->payload, payload, len);

        frame_len = ETH_HEADER_SIZE + LLC_HEADER_SIZE + len;
#if defined(HAVE_NETMAP)
        if (poll(&eth_llc_data.poll_out, 1, -1) < 0)
                return -1;

        if (nm_inject(eth_llc_data.nmd, frame, frame_len) != (int) frame_len) {
                log_dbg("Failed to send message.");
                return -1;
        }
#elif defined(HAVE_BPF)
        if (write(eth_llc_data.bpf, frame, frame_len) < 0) {
                log_dbg("Failed to send message.");
                return -1;
        }

#elif defined(HAVE_RAW_SOCKETS)
        if (sendto(eth_llc_data.s_fd,
                   frame,
                   frame_len,
                   0,
                   (struct sockaddr *) &eth_llc_data.device,
                   sizeof(eth_llc_data.device)) <= 0) {
                log_dbg("Failed to send message.");
                return -1;
        }
#endif /* HAVE_NETMAP */
        return 0;
}

static int eth_llc_ipcp_send_mgmt_frame(shim_eth_llc_msg_t * msg,
                                        const uint8_t *      dst_addr)
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

static int eth_llc_ipcp_sap_alloc(const uint8_t * dst_addr,
                                  uint8_t         ssap,
                                  const uint8_t * hash,
                                  qoscube_t       cube)
{
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;

        msg.code        = SHIM_ETH_LLC_MSG_CODE__FLOW_REQ;
        msg.has_ssap    = true;
        msg.ssap        = ssap;
        msg.has_hash    = true;
        msg.hash.len    = ipcp_dir_hash_len();
        msg.hash.data   = (uint8_t *) hash;
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

static int eth_llc_ipcp_sap_req(uint8_t         r_sap,
                                uint8_t *       r_addr,
                                const uint8_t * dst,
                                qoscube_t       cube)
{
        struct timespec ts = {0, EVENT_WAIT_TIMEOUT * 100};
        struct timespec abstime;
        int             fd;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        pthread_mutex_lock(&ipcpi.alloc_lock);

        while (ipcpi.alloc_id != -1 && ipcp_get_state() == IPCP_OPERATIONAL) {
                ts_add(&abstime, &ts, &abstime);
                pthread_cond_timedwait(&ipcpi.alloc_cond,
                                       &ipcpi.alloc_lock,
                                       &abstime);
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_dbg("Won't allocate over non-operational IPCP.");
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                return -1;
        }

        /* reply to IRM, called under lock to prevent race */
        fd = ipcp_flow_req_arr(getpid(), dst, ipcp_dir_hash_len(), cube);
        if (fd < 0) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                log_err("Could not get new flow from IRMd.");
                return -1;
        }

        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        eth_llc_data.fd_to_ef[fd].r_sap = r_sap;
        memcpy(eth_llc_data.fd_to_ef[fd].r_addr, r_addr, MAC_SIZE);

        ipcpi.alloc_id = fd;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);
        pthread_mutex_unlock(&ipcpi.alloc_lock);

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

        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        fd = eth_llc_data.ef_to_fd[dsap];
        if (fd < 0) {
                pthread_rwlock_unlock(& eth_llc_data.flows_lock);
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

        log_dbg("Flow reply, fd %d, SSAP %d, DSAP %d.", fd, ssap, dsap);

        if ((ret = ipcp_flow_alloc_reply(fd, response)) < 0)
                return -1;

        return ret;

}

static int eth_llc_ipcp_name_query_req(const uint8_t * hash,
                                       uint8_t *       r_addr)
{
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;

        if (shim_data_reg_has(eth_llc_data.shim_data, hash)) {
                msg.code      = SHIM_ETH_LLC_MSG_CODE__NAME_QUERY_REPLY;
                msg.has_hash  = true;
                msg.hash.len  = ipcp_dir_hash_len();
                msg.hash.data = (uint8_t *) hash;

                eth_llc_ipcp_send_mgmt_frame(&msg, r_addr);
        }

        return 0;
}

static int eth_llc_ipcp_name_query_reply(const uint8_t * hash,
                                         uint8_t *       r_addr)
{
        uint64_t address = 0;

        memcpy(&address, r_addr, MAC_SIZE);

        shim_data_dir_add_entry(eth_llc_data.shim_data, hash, address);

        shim_data_dir_query_respond(eth_llc_data.shim_data, hash);

        return 0;
}

static int eth_llc_ipcp_mgmt_frame(const uint8_t * buf,
                                   size_t          len,
                                   uint8_t *       r_addr)
{
        shim_eth_llc_msg_t * msg;

        msg = shim_eth_llc_msg__unpack(NULL, len, buf);
        if (msg == NULL) {
                log_err("Failed to unpack.");
                return -1;
        }

        switch (msg->code) {
        case SHIM_ETH_LLC_MSG_CODE__FLOW_REQ:
                if (shim_data_reg_has(eth_llc_data.shim_data, msg->hash.data)) {
                        eth_llc_ipcp_sap_req(msg->ssap,
                                             r_addr,
                                             msg->hash.data,
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
                eth_llc_ipcp_name_query_req(msg->hash.data, r_addr);
                break;
        case SHIM_ETH_LLC_MSG_CODE__NAME_QUERY_REPLY:
                eth_llc_ipcp_name_query_reply(msg->hash.data, r_addr);
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
        int                 ret;
        struct timespec     timeout = {(MGMT_TIMEOUT / 1000),
                                       (MGMT_TIMEOUT % 1000) * MILLION};
        struct timespec     abstime;
        struct mgmt_frame * frame;

        (void) o;

        while (true) {
                ret = 0;

                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        return (void *) 0;

                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, &timeout, &abstime);

                pthread_mutex_lock(&eth_llc_data.mgmt_lock);

                while (list_is_empty(&eth_llc_data.mgmt_frames) &&
                       ret != -ETIMEDOUT)
                        ret = -pthread_cond_timedwait(&eth_llc_data.mgmt_cond,
                                                      &eth_llc_data.mgmt_lock,
                                                      &abstime);

                if (ret == -ETIMEDOUT) {
                        pthread_mutex_unlock(&eth_llc_data.mgmt_lock);
                        continue;
                }

                frame = list_first_entry((&eth_llc_data.mgmt_frames),
                                         struct mgmt_frame, next);
                if (frame == NULL) {
                        pthread_mutex_unlock(&eth_llc_data.mgmt_lock);
                        continue;
                }

                list_del(&frame->next);
                pthread_mutex_unlock(&eth_llc_data.mgmt_lock);

                eth_llc_ipcp_mgmt_frame(frame->buf, frame->len, frame->r_addr);
                free(frame);
        }
}

static void * eth_llc_ipcp_sdu_reader(void * o)
{
        uint8_t                br_addr[MAC_SIZE];
        uint16_t               length;
        uint8_t                dsap;
        uint8_t                ssap;
        int                    fd;
#if defined(HAVE_NETMAP)
        uint8_t *              buf;
        struct nm_pkthdr       hdr;
#elif defined(HAVE_BPF)
        uint8_t                buf[BPF_BLEN];
#elif defined(HAVE_RAW_SOCKETS)
        uint8_t                buf[ETH_FRAME_SIZE];
#endif
        int                    frame_len = 0;
        struct eth_llc_frame * llc_frame;
        struct mgmt_frame *    frame;

        (void) o;

        memset(br_addr, 0xff, MAC_SIZE * sizeof(uint8_t));

        while (true) {
                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        return (void *) 0;
#if defined(HAVE_NETMAP)
                if (poll(&eth_llc_data.poll_in, 1, EVENT_WAIT_TIMEOUT / 1000) < 0)
                        continue;
                if (eth_llc_data.poll_in.revents == 0) /* TIMED OUT */
                        continue;

                buf = nm_nextpkt(eth_llc_data.nmd, &hdr);
                if (buf == NULL) {
                        log_err("Bad read from netmap device.");
                        continue;
                }
#elif defined(HAVE_BPF)
                frame_len = read(eth_llc_data.bpf, buf, BPF_BLEN);
#elif defined(HAVE_RAW_SOCKETS)
                frame_len = recv(eth_llc_data.s_fd, buf,
                                 SHIM_ETH_LLC_MAX_SDU_SIZE, 0);
#endif
                if (frame_len <= 0)
                        continue;

#if defined(HAVE_BPF) && !defined(HAVE_NETMAP)
                llc_frame = (struct eth_llc_frame *)
                        (buf + ((struct bpf_hdr *) buf)->bh_hdrlen);
#else
                llc_frame = (struct eth_llc_frame *) buf;
#endif
                assert(llc_frame->dst_hwaddr);

#if !defined(HAVE_BPF)
    #if defined(HAVE_NETMAP)
                if (memcmp(eth_llc_data.hw_addr,
    #elif defined(HAVE_RAW_SOCKETS)
                if (memcmp(eth_llc_data.device.sll_addr,
    #endif /* HAVE_NETMAP */
                           llc_frame->dst_hwaddr,
                           MAC_SIZE) &&
                    memcmp(br_addr, llc_frame->dst_hwaddr, MAC_SIZE)) {
                }
#endif
                memcpy(&length, &llc_frame->length, sizeof(length));
                length = ntohs(length);

                if (length > 0x05FF) /* DIX */
                        continue;

                length -= LLC_HEADER_SIZE;

                dsap = reverse_bits(llc_frame->dsap);
                ssap = reverse_bits(llc_frame->ssap);

                if (ssap == MGMT_SAP && dsap == MGMT_SAP) {
                        pthread_mutex_lock(&eth_llc_data.mgmt_lock);

                        frame = malloc(sizeof(*frame));
                        if (frame == NULL) {
                                pthread_mutex_unlock(&eth_llc_data.mgmt_lock);
                                continue;
                        }

                        memcpy(frame->buf, &llc_frame->payload, length);
                        memcpy(frame->r_addr, llc_frame->src_hwaddr, MAC_SIZE);
                        frame->len = length;
                        list_add(&frame->next, &eth_llc_data.mgmt_frames);
                        pthread_cond_signal(&eth_llc_data.mgmt_cond);
                        pthread_mutex_unlock(&eth_llc_data.mgmt_lock);
                } else {
                        pthread_rwlock_rdlock(&eth_llc_data.flows_lock);

                        fd = eth_llc_data.ef_to_fd[dsap];
                        if (fd < 0) {
                                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                                continue;
                        }

                        if (eth_llc_data.fd_to_ef[fd].r_sap != ssap
                            || memcmp(eth_llc_data.fd_to_ef[fd].r_addr,
                                      llc_frame->src_hwaddr, MAC_SIZE)) {
                                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                                continue;
                        }

                        pthread_rwlock_unlock(&eth_llc_data.flows_lock);

                        flow_write(fd, &llc_frame->payload, length);
                }
        }

        return (void *) 0;
}

static void * eth_llc_ipcp_sdu_writer(void * o)
{
        struct timespec      timeout = {0, EVENT_WAIT_TIMEOUT * 1000};
        int                  fd;
        struct shm_du_buff * sdb;
        uint8_t              ssap;
        uint8_t              dsap;
        uint8_t              r_addr[MAC_SIZE];

        (void) o;

        while (fevent(eth_llc_data.np1_flows, eth_llc_data.fq, &timeout)) {
                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        return (void *) 0;

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
                        ipcp_sdb_release(sdb);
                }
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
        }

        return (void *) 1;
}

#if defined (HAVE_BPF) && !defined(HAVE_NETMAP)
static int open_bpf_device(void)
{
        char   dev[32];
        size_t i = 0;

        for (i = 0; i < BPF_DEV_MAX; i++) {
                int fd = -1;

                snprintf(dev, sizeof(dev), "/dev/bpf%zu", i);

                fd = open(dev, O_RDWR);
                if (fd > -1)
                        return fd;
        }

        return -1;
}
#endif

static int eth_llc_ipcp_bootstrap(const struct ipcp_config * conf)
{
        int              idx;
        struct ifreq     ifr;
#if defined(HAVE_NETMAP)
        char             ifn[IFNAMSIZ];
#elif defined(HAVE_BPF)
        int              enable  = 1;
        int              disable = 0;
        int              blen;
        struct timeval   tv = {0, EVENT_WAIT_TIMEOUT};
#elif defined(HAVE_RAW_SOCKETS)
        struct timeval   tv = {0, EVENT_WAIT_TIMEOUT};
#endif /* HAVE_NETMAP */

#if defined(__FreeBSD__) || defined(__APPLE__)
        struct ifaddrs * ifaddr;
        struct ifaddrs * ifa;
#elif defined(__linux__)
        int              skfd;
#endif
        assert(conf);
        assert(conf->type == THIS_TYPE);

        if (conf->if_name == NULL) {
                log_err("Interface name is NULL.");
                return -1;
        }

        memset(&ifr, 0, sizeof(ifr));
        memcpy(ifr.ifr_name, conf->if_name, strlen(conf->if_name));

#if defined(__FreeBSD__) || defined(__APPLE__)
        if (getifaddrs(&ifaddr) < 0)  {
                log_err("Could not get interfaces.");
                return -1;
        }

        for (ifa = ifaddr, idx = 0; ifa != NULL; ifa = ifa->ifa_next, ++idx) {
                if (strcmp(ifa->ifa_name, conf->if_name))
                        continue;
                log_dbg("Interface %s found.", conf->if_name);

    #if defined(HAVE_NETMAP) || defined(HAVE_BPF)
                memcpy(eth_llc_data.hw_addr,
                       LLADDR((struct sockaddr_dl *) (ifa)->ifa_addr),
                       MAC_SIZE);
    #elif defined (HAVE_RAW_SOCKETS)
                memcpy(&ifr.ifr_addr, ifa->ifa_addr, sizeof(*ifa->ifa_addr));
    #endif
                break;
        }

        if (ifa == NULL) {
                log_err("Interface not found.");
                freeifaddrs(ifaddr);
                return -1;
        }

        freeifaddrs(ifaddr);
#elif defined(__linux__)
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
#endif /* __FreeBSD__ */

#if defined(HAVE_NETMAP)
        strcpy(ifn, "netmap:");
        strcat(ifn, conf->if_name);

        eth_llc_data.nmd = nm_open(ifn, NULL, 0, NULL);
        if (eth_llc_data.nmd == NULL) {
                log_err("Failed to open netmap device.");
                return -1;
        }

        memset(&eth_llc_data.poll_in, 0, sizeof(eth_llc_data.poll_in));
        memset(&eth_llc_data.poll_out, 0, sizeof(eth_llc_data.poll_out));

        eth_llc_data.poll_in.fd      = NETMAP_FD(eth_llc_data.nmd);
        eth_llc_data.poll_in.events  = POLLIN;
        eth_llc_data.poll_out.fd     = NETMAP_FD(eth_llc_data.nmd);
        eth_llc_data.poll_out.events = POLLOUT;

        log_info("Using netmap device.");
#elif defined(HAVE_BPF) /* !HAVE_NETMAP */
        eth_llc_data.bpf = open_bpf_device();
        if (eth_llc_data.bpf < 0) {
                log_err("Failed to open bpf device.");
                return -1;
        }

        ioctl(eth_llc_data.bpf, BIOCGBLEN, &blen);
        if (BPF_BLEN < blen) {
                log_err("BPF buffer too small (is: %ld must be: %d).",
                        BPF_BLEN, blen);
                close(eth_llc_data.bpf);
                return -1;
        }

        if (ioctl(eth_llc_data.bpf, BIOCSETIF, &ifr) < 0) {
                log_err("Failed to set interface.");
                close(eth_llc_data.bpf);
                return -1;
        }

        if (ioctl(eth_llc_data.bpf, BIOCSHDRCMPLT, &enable) < 0) {
                log_err("Failed to set BIOCSHDRCMPLT.");
                close(eth_llc_data.bpf);
                return -1;
        }

        if (ioctl(eth_llc_data.bpf, BIOCSSEESENT, &disable) < 0) {
                log_err("Failed to set BIOCSSEESENT.");
                close(eth_llc_data.bpf);
                return -1;
        }

        if (ioctl(eth_llc_data.bpf, BIOCSRTIMEOUT, &tv) < 0) {
                log_err("Failed to set BIOCSRTIMEOUT.");
                close(eth_llc_data.bpf);
                return -1;
        }

        if (ioctl(eth_llc_data.bpf, BIOCIMMEDIATE, &enable) < 0) {
                log_err("Failed to set BIOCIMMEDIATE.");
                close(eth_llc_data.bpf);
                return -1;
        }

        log_info("Using Berkeley Packet Filter.");
#elif defined(HAVE_RAW_SOCKETS)
        memset(&(eth_llc_data.device), 0, sizeof(eth_llc_data.device));
        eth_llc_data.device.sll_ifindex  = idx;
        eth_llc_data.device.sll_family   = AF_PACKET;
        memcpy(eth_llc_data.device.sll_addr, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
        eth_llc_data.device.sll_halen    = MAC_SIZE;
        eth_llc_data.device.sll_protocol = htons(ETH_P_ALL);
        eth_llc_data.s_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_802_2));

        log_info("Using raw socket device.");

        if (eth_llc_data.s_fd < 0) {
                log_err("Failed to create socket.");
                return -1;
        }

        if (bind(eth_llc_data.s_fd, (struct sockaddr *) &eth_llc_data.device,
                sizeof(eth_llc_data.device))) {
                log_err("Failed to bind socket to interface");
                close(eth_llc_data.s_fd);
                return -1;
        }

        if (setsockopt(eth_llc_data.s_fd, SOL_SOCKET, SO_RCVTIMEO,
                       &tv, sizeof(tv))) {
                log_err("Failed to set socket timeout: %s.", strerror(errno));
                close(eth_llc_data.s_fd);
                return -1;
        }

#endif /* HAVE_NETMAP */
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

        log_dbg("Bootstrapped shim IPCP over Ethernet with LLC with api %d.",
                getpid());

        return 0;
}

static int eth_llc_ipcp_reg(const uint8_t * hash)
{
        if (shim_data_reg_add_entry(eth_llc_data.shim_data, hash)) {
                log_err("Failed to add " HASH_FMT " to local registry.",
                        HASH_VAL(hash));
                return -1;
        }

        log_dbg("Registered " HASH_FMT ".", HASH_VAL(hash));

        return 0;
}

static int eth_llc_ipcp_unreg(const uint8_t * hash)
{
        shim_data_reg_del_entry(eth_llc_data.shim_data, hash);

        return 0;
}

static int eth_llc_ipcp_query(const uint8_t * hash)
{
        uint8_t            r_addr[MAC_SIZE];
        struct timespec    timeout = {(NAME_QUERY_TIMEOUT / 1000),
                                      (NAME_QUERY_TIMEOUT % 1000) * MILLION};
        shim_eth_llc_msg_t msg = SHIM_ETH_LLC_MSG__INIT;
        struct dir_query * query;
        int                ret;

        if (shim_data_dir_has(eth_llc_data.shim_data, hash))
                return 0;

        msg.code      = SHIM_ETH_LLC_MSG_CODE__NAME_QUERY_REQ;
        msg.has_hash  = true;
        msg.hash.len  = ipcp_dir_hash_len();
        msg.hash.data = (uint8_t *) hash;

        memset(r_addr, 0xff, MAC_SIZE);

        query = shim_data_dir_query_create(eth_llc_data.shim_data, hash);
        if (query == NULL)
                return -1;

        eth_llc_ipcp_send_mgmt_frame(&msg, r_addr);

        ret = shim_data_dir_query_wait(query, &timeout);

        shim_data_dir_query_destroy(eth_llc_data.shim_data, query);

        return ret;
}

static int eth_llc_ipcp_flow_alloc(int             fd,
                                   const uint8_t * hash,
                                   qoscube_t       cube)
{
        uint8_t  ssap = 0;
        uint8_t  r_addr[MAC_SIZE];
        uint64_t addr = 0;

        log_dbg("Allocating flow to " HASH_FMT ".", HASH_VAL(hash));

        assert(hash);

        if (cube != QOS_CUBE_BE) {
                log_dbg("Unsupported QoS requested.");
                return -1;
        }

        if (!shim_data_dir_has(eth_llc_data.shim_data, hash)) {
                log_err("Destination unreachable.");
                return -1;
        }
        addr = shim_data_dir_get_addr(eth_llc_data.shim_data, hash);

        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        ssap =  bmp_allocate(eth_llc_data.saps);
        if (!bmp_is_id_valid(eth_llc_data.saps, ssap)) {
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                return -1;
        }

        eth_llc_data.fd_to_ef[fd].sap = ssap;
        eth_llc_data.ef_to_fd[ssap]   = fd;

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);

        memcpy(r_addr, &addr, MAC_SIZE);

        if (eth_llc_ipcp_sap_alloc(r_addr, ssap, hash, cube) < 0) {
                pthread_rwlock_wrlock(&eth_llc_data.flows_lock);
                bmp_release(eth_llc_data.saps, eth_llc_data.fd_to_ef[fd].sap);
                eth_llc_data.fd_to_ef[fd].sap = -1;
                eth_llc_data.ef_to_fd[ssap]   = -1;
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                return -1;
        }

        fset_add(eth_llc_data.np1_flows, fd);

        log_dbg("Pending flow with fd %d on SAP %d.", fd, ssap);

        return 0;
}

static int eth_llc_ipcp_flow_alloc_resp(int fd,
                                        int response)
{
        struct timespec ts    = {0, EVENT_WAIT_TIMEOUT * 100};
        struct timespec abstime;
        uint8_t         ssap  = 0;
        uint8_t         r_sap = 0;
        uint8_t         r_addr[MAC_SIZE];

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        pthread_mutex_lock(&ipcpi.alloc_lock);

        while (ipcpi.alloc_id != fd && ipcp_get_state() == IPCP_OPERATIONAL) {
                ts_add(&abstime, &ts, &abstime);
                pthread_cond_timedwait(&ipcpi.alloc_cond,
                                       &ipcpi.alloc_lock,
                                       &abstime);
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                return -1;
        }

        ipcpi.alloc_id = -1;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        ssap = bmp_allocate(eth_llc_data.saps);
        if (!bmp_is_id_valid(eth_llc_data.saps, ssap)) {
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                return -1;
        }

        eth_llc_data.fd_to_ef[fd].sap = ssap;
        memcpy(r_addr, eth_llc_data.fd_to_ef[fd].r_addr, MAC_SIZE);
        r_sap = eth_llc_data.fd_to_ef[fd].r_sap;
        eth_llc_data.ef_to_fd[ssap] = fd;

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);

        if (eth_llc_ipcp_sap_alloc_resp(r_addr, ssap, r_sap, response) < 0) {
                pthread_rwlock_wrlock(&eth_llc_data.flows_lock);
                bmp_release(eth_llc_data.saps, eth_llc_data.fd_to_ef[fd].sap);
                pthread_rwlock_unlock(&eth_llc_data.flows_lock);
                return -1;
        }

        fset_add(eth_llc_data.np1_flows, fd);

        log_dbg("Accepted flow, fd %d, SAP %d.", fd, (uint8_t)ssap);

        return 0;
}

static int eth_llc_ipcp_flow_dealloc(int fd)
{
        uint8_t sap;
        uint8_t addr[MAC_SIZE];

        ipcp_flow_fini(fd);

        pthread_rwlock_wrlock(&eth_llc_data.flows_lock);

        fset_del(eth_llc_data.np1_flows, fd);

        sap = eth_llc_data.fd_to_ef[fd].sap;
        memcpy(addr, eth_llc_data.fd_to_ef[fd].r_addr, MAC_SIZE);
        bmp_release(eth_llc_data.saps, sap);
        eth_llc_data.fd_to_ef[fd].sap = -1;
        eth_llc_data.fd_to_ef[fd].r_sap = -1;
        memset(&eth_llc_data.fd_to_ef[fd].r_addr, 0, MAC_SIZE);

        eth_llc_data.ef_to_fd[sap] = -1;

        pthread_rwlock_unlock(&eth_llc_data.flows_lock);

        flow_dealloc(fd);

        log_dbg("Flow with fd %d deallocated.", fd);

        return 0;
}

static struct ipcp_ops eth_llc_ops = {
        .ipcp_bootstrap       = eth_llc_ipcp_bootstrap,
        .ipcp_enroll          = NULL,
        .ipcp_connect         = NULL,
        .ipcp_disconnect      = NULL,
        .ipcp_reg             = eth_llc_ipcp_reg,
        .ipcp_unreg           = eth_llc_ipcp_unreg,
        .ipcp_query           = eth_llc_ipcp_query,
        .ipcp_flow_alloc      = eth_llc_ipcp_flow_alloc,
        .ipcp_flow_alloc_resp = eth_llc_ipcp_flow_alloc_resp,
        .ipcp_flow_dealloc    = eth_llc_ipcp_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        if (ipcp_init(argc, argv, THIS_TYPE, &eth_llc_ops) < 0)
                goto fail_init;

        if (eth_llc_data_init() < 0) {
                log_err("Failed to init shim-eth-llc data.");
                goto fail_data_init;
        }

        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                goto fail_boot;
        }

        if (ipcp_create_r(getpid(), 0)) {
                log_err("Failed to notify IRMd we are initialized.");
                ipcp_set_state(IPCP_NULL);
                goto fail_create_r;
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

 fail_create_r:
        ipcp_shutdown();
 fail_boot:
        eth_llc_data_fini();
 fail_data_init:
        ipcp_fini();
 fail_init:
        ipcp_create_r(getpid(), -1);
        exit(EXIT_FAILURE);

}
