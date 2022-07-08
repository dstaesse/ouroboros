/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * IPC processes over Ethernet
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

#if !defined(BUILD_ETH_DIX) && !defined(BUILD_ETH_LLC)
#error Define BUILD_ETH_DIX or BUILD_ETH_LLC to build an Ethernet IPCP
#endif

#if defined(__APPLE__)
#define _BSD_SOURCE
#define _DARWIN_C_SOURCE
#elif defined(__FreeBSD__)
#define __BSD_VISIBLE 1
#elif defined (__linux__) || defined (__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200112L
#endif

#include "config.h"

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
#include <ouroboros/fccntl.h>
#include <ouroboros/pthread.h>

#include "ipcp.h"
#include "shim-data.h"

#include <signal.h>
#include <stdlib.h>
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
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
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
#define BPF_DEV_MAX          256
#define BPF_BLEN             sysconf(_SC_PAGESIZE)
#include <net/bpf.h>
#endif

#ifdef __linux__
#ifndef ETH_MAX_MTU          /* In if_ether.h as of Linux 4.10. */
#define ETH_MAX_MTU          0xFFFFU
#endif /* ETH_MAX_MTU */
#ifdef BUILD_ETH_DIX
#define ETH_MTU              eth_data.mtu
#define ETH_MTU_MAX          ETH_MAX_MTU
#else
#define ETH_MTU              eth_data.mtu
#define ETH_MTU_MAX          1500
#endif /* BUILD_ETH_DIX */
#else /* __linux__ */
#define ETH_MTU              1500
#define ETH_MTU_MAX          ETH_MTU
#endif /* __linux__ */

#define MAC_SIZE             6
#define ETH_TYPE_LENGTH_SIZE sizeof(uint16_t)
#define ETH_HEADER_SIZE      (2 * MAC_SIZE + ETH_TYPE_LENGTH_SIZE)

#if defined(BUILD_ETH_DIX)
#define THIS_TYPE            IPCP_ETH_DIX
#define MGMT_EID             0
#define DIX_EID_SIZE         sizeof(uint16_t)
#define DIX_LENGTH_SIZE      sizeof(uint16_t)
#define DIX_HEADER_SIZE      (DIX_EID_SIZE + DIX_LENGTH_SIZE)
#define ETH_HEADER_TOT_SIZE  (ETH_HEADER_SIZE + DIX_HEADER_SIZE)
#define MAX_EIDS             (1 << (8 * DIX_EID_SIZE))
#define ETH_MAX_PACKET_SIZE  (ETH_MTU - DIX_HEADER_SIZE)
#define ETH_FRAME_SIZE       (ETH_HEADER_SIZE + ETH_MTU_MAX)
#elif defined(BUILD_ETH_LLC)
#define THIS_TYPE            IPCP_ETH_LLC
#define MGMT_SAP             0x01
#define LLC_HEADER_SIZE      3
#define ETH_HEADER_TOT_SIZE  (ETH_HEADER_SIZE + LLC_HEADER_SIZE)
#define MAX_SAPS             64
#define ETH_MAX_PACKET_SIZE  (ETH_MTU - LLC_HEADER_SIZE)
#define ETH_FRAME_SIZE       (ETH_HEADER_SIZE + ETH_MTU_MAX)
#endif

#define ALLOC_TIMEO          10    /* ms */
#define NAME_QUERY_TIMEO     2000  /* ms */
#define MGMT_TIMEO           100   /* ms */
#define MGMT_FRAME_SIZE      2048

#define FLOW_REQ             0
#define FLOW_REPLY           1
#define NAME_QUERY_REQ       2
#define NAME_QUERY_REPLY     3

struct ipcp ipcpi;

struct mgmt_msg {
#if defined(BUILD_ETH_DIX)
        uint16_t seid;
        uint16_t deid;
#elif defined(BUILD_ETH_LLC)
        uint8_t  ssap;
        uint8_t  dsap;
        /* QoS here for alignment */
        uint8_t  code;
        uint8_t  availability;
#endif
        /* QoS parameters from spec, aligned */
        uint32_t loss;
        uint64_t bandwidth;
        uint32_t ber;
        uint32_t max_gap;
        uint32_t delay;
        uint32_t timeout;
        uint16_t cypher_s;
        uint8_t  in_order;
#if defined (BUILD_ETH_DIX)
        uint8_t  code;
        uint8_t  availability;
#endif
        int8_t   response;
} __attribute__((packed));

struct eth_frame {
        uint8_t  dst_hwaddr[MAC_SIZE];
        uint8_t  src_hwaddr[MAC_SIZE];
#if defined(BUILD_ETH_DIX)
        uint16_t ethertype;
        uint16_t eid;
        uint16_t length;
#elif defined(BUILD_ETH_LLC)
        uint16_t length;
        uint8_t  dsap;
        uint8_t  ssap;
        uint8_t  cf;
#endif
        uint8_t  payload;
} __attribute__((packed));

struct ef {
#if defined(BUILD_ETH_DIX)
        int32_t r_eid;
#elif defined(BUILD_ETH_LLC)
        int8_t  sap;
        int8_t  r_sap;
#endif
        uint8_t r_addr[MAC_SIZE];
};

struct mgmt_frame {
        struct list_head next;
        uint8_t          r_addr[MAC_SIZE];
        uint8_t          buf[MGMT_FRAME_SIZE];
        size_t           len;
};

struct {
        struct shim_data * shim_data;
#ifdef __linux__
        int                mtu;
        int                if_idx;
#endif
#if defined(HAVE_NETMAP)
        struct nm_desc *   nmd;
        uint8_t            hw_addr[MAC_SIZE];
        struct pollfd      poll_in;
        struct pollfd      poll_out;
#elif defined(HAVE_BPF)
        int                bpf;
        uint8_t            hw_addr[MAC_SIZE];
#elif defined(HAVE_RAW_SOCKETS)
        int                s_fd;
        struct sockaddr_ll device;
#endif /* HAVE_NETMAP */
#if defined (BUILD_ETH_DIX)
        uint16_t           ethertype;
#elif defined(BUILD_ETH_LLC)
        struct bmp *       saps;
        int *              ef_to_fd;
#endif
        struct ef *        fd_to_ef;
        fset_t *           np1_flows;
        pthread_rwlock_t   flows_lock;

        pthread_t          packet_writer[IPCP_ETH_WR_THR];
        pthread_t          packet_reader[IPCP_ETH_RD_THR];

#ifdef __linux__
        pthread_t          if_monitor;
#endif

        /* Handle mgmt frames in a different thread */
        pthread_t          mgmt_handler;
        pthread_mutex_t    mgmt_lock;
        pthread_cond_t     mgmt_cond;
        struct list_head   mgmt_frames;
} eth_data;

static int eth_data_init(void)
{
        int                i;
        int                ret = -ENOMEM;
        pthread_condattr_t cattr;

        eth_data.fd_to_ef =
                malloc(sizeof(*eth_data.fd_to_ef) * SYS_MAX_FLOWS);
        if (eth_data.fd_to_ef == NULL)
                goto fail_fd_to_ef;

#ifdef BUILD_ETH_LLC
        eth_data.ef_to_fd =
                malloc(sizeof(*eth_data.ef_to_fd) * MAX_SAPS);
        if (eth_data.ef_to_fd == NULL)
                goto fail_ef_to_fd;

        for (i = 0; i < MAX_SAPS; ++i)
                eth_data.ef_to_fd[i] = -1;

        eth_data.saps = bmp_create(MAX_SAPS, 2);
        if (eth_data.saps == NULL)
                goto fail_saps;
#endif
        eth_data.np1_flows = fset_create();
        if (eth_data.np1_flows == NULL)
                goto fail_np1_flows;

        for (i = 0; i < SYS_MAX_FLOWS; ++i) {
#if defined(BUILD_ETH_DIX)
                eth_data.fd_to_ef[i].r_eid = -1;
#elif defined(BUILD_ETH_LLC)
                eth_data.fd_to_ef[i].sap   = -1;
                eth_data.fd_to_ef[i].r_sap = -1;
#endif
                memset(&eth_data.fd_to_ef[i].r_addr, 0, MAC_SIZE);
        }

        eth_data.shim_data = shim_data_create();
        if (eth_data.shim_data == NULL)
                goto fail_shim_data;

        ret = -1;

        if (pthread_rwlock_init(&eth_data.flows_lock, NULL))
                goto fail_flows_lock;

        if (pthread_mutex_init(&eth_data.mgmt_lock, NULL))
                goto fail_mgmt_lock;

        if (pthread_condattr_init(&cattr))
                goto fail_condattr;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif

        if (pthread_cond_init(&eth_data.mgmt_cond, &cattr))
                goto fail_mgmt_cond;

        pthread_condattr_destroy(&cattr);

        list_head_init(&eth_data.mgmt_frames);

        return 0;

 fail_mgmt_cond:
        pthread_condattr_destroy(&cattr);
 fail_condattr:
        pthread_mutex_destroy(&eth_data.mgmt_lock);
 fail_mgmt_lock:
        pthread_rwlock_destroy(&eth_data.flows_lock);
 fail_flows_lock:
        shim_data_destroy(eth_data.shim_data);
 fail_shim_data:
        fset_destroy(eth_data.np1_flows);
 fail_np1_flows:
#ifdef BUILD_ETH_LLC
        bmp_destroy(eth_data.saps);
 fail_saps:
        free(eth_data.ef_to_fd);
 fail_ef_to_fd:
#endif
        free(eth_data.fd_to_ef);
 fail_fd_to_ef:
        return ret;
}

static void eth_data_fini(void)
{
#if defined(HAVE_NETMAP)
        nm_close(eth_data.nmd);
#elif defined(HAVE_BPF)
        close(eth_data.bpf);
#elif defined(HAVE_RAW_SOCKETS)
        close(eth_data.s_fd);
#endif
        pthread_cond_destroy(&eth_data.mgmt_cond);
        pthread_mutex_destroy(&eth_data.mgmt_lock);
        pthread_rwlock_destroy(&eth_data.flows_lock);
        shim_data_destroy(eth_data.shim_data);
        fset_destroy(eth_data.np1_flows);
#ifdef BUILD_ETH_LLC
        bmp_destroy(eth_data.saps);
        free(eth_data.ef_to_fd);
#endif
        free(eth_data.fd_to_ef);
}

#ifdef BUILD_ETH_LLC
static uint8_t reverse_bits(uint8_t b)
{
        b = (b & 0xF0) >> 4 | (b & 0x0F) << 4;
        b = (b & 0xCC) >> 2 | (b & 0x33) << 2;
        b = (b & 0xAA) >> 1 | (b & 0x55) << 1;

        return b;
}
#endif

/* Pass a buffer that contains space for the header. */
static int eth_ipcp_send_frame(const uint8_t * dst_addr,
#if defined(BUILD_ETH_DIX)
                               uint16_t        deid,
#elif defined(BUILD_ETH_LLC)
                               uint8_t         dsap,
                               uint8_t         ssap,
#endif
                               const uint8_t * frame,
                               size_t          len)
{
        uint32_t           frame_len = 0;
#ifdef BUILD_ETH_LLC
        uint8_t            cf = 0x03;
#endif
        struct eth_frame * e_frame;
#ifdef HAVE_RAW_SOCKETS
        fd_set             fds;

        FD_ZERO(&fds);
#endif

        assert(frame);

        if (len > (size_t) ETH_MAX_PACKET_SIZE)
                return -1;

        e_frame = (struct eth_frame *) frame;

        memcpy(e_frame->dst_hwaddr, dst_addr, MAC_SIZE);
        memcpy(e_frame->src_hwaddr,
#if defined(HAVE_NETMAP) || defined(HAVE_BPF)
               eth_data.hw_addr,
#elif defined(HAVE_RAW_SOCKETS)
               eth_data.device.sll_addr,
#endif /* HAVE_NETMAP */
               MAC_SIZE);
#if defined(BUILD_ETH_DIX)
        e_frame->ethertype = eth_data.ethertype;
        e_frame->eid = htons(deid);
        e_frame->length = htons(len);
        frame_len = ETH_HEADER_TOT_SIZE + len;
#elif defined(BUILD_ETH_LLC)
        e_frame->length = htons(LLC_HEADER_SIZE + len);
        e_frame->dsap = dsap;
        e_frame->ssap = ssap;
        e_frame->cf   = cf;
        frame_len = ETH_HEADER_TOT_SIZE + len;
#endif

#if defined(HAVE_NETMAP)
        if (poll(&eth_data.poll_out, 1, -1) < 0)
                return -1;

        if (nm_inject(eth_data.nmd, frame, frame_len) != (int) frame_len) {
                log_dbg("Failed to send message.");
                return -1;
        }
#elif defined(HAVE_BPF)
        if (write(eth_data.bpf, frame, frame_len) < 0) {
                log_dbg("Failed to send message.");
                return -1;
        }

#elif defined(HAVE_RAW_SOCKETS)
        FD_SET(eth_data.s_fd, &fds);
        if (select(eth_data.s_fd + 1, NULL, &fds, NULL, NULL) < 0) {
                log_dbg("Select() failed: %s.", strerror(errno));
                return -1;
        }
        assert(FD_ISSET(eth_data.s_fd, &fds));

        if (sendto(eth_data.s_fd,
                   frame,
                   frame_len,
                   0,
                   (struct sockaddr *) &eth_data.device,
                   sizeof(eth_data.device)) <= 0) {
                log_dbg("Failed to send message: %s.", strerror(errno));
                return -1;
        }
#endif /* HAVE_NETMAP */

        return 0;
}

static int eth_ipcp_alloc(const uint8_t * dst_addr,
#if defined(BUILD_ETH_DIX)
                          uint16_t        eid,
#elif defined(BUILD_ETH_LLC)
                          uint8_t         ssap,
#endif
                          const uint8_t * hash,
                          qosspec_t       qs,
                          const void *    data,
                          size_t          dlen)
{
        uint8_t *         buf;
        struct mgmt_msg * msg;
        size_t            len;
        int               ret;

        len = sizeof(*msg) + ipcp_dir_hash_len();

        buf = malloc(len + ETH_HEADER_TOT_SIZE + dlen);
        if (buf == NULL)
                return -1;

        msg          = (struct mgmt_msg *) (buf + ETH_HEADER_TOT_SIZE);
        msg->code    = FLOW_REQ;
#if defined(BUILD_ETH_DIX)
        msg->seid    = htons(eid);
#elif defined(BUILD_ETH_LLC)
        msg->ssap    = ssap;
#endif

        msg->delay        = hton32(qs.delay);
        msg->bandwidth    = hton64(qs.bandwidth);
        msg->availability = qs.availability;
        msg->loss         = hton32(qs.loss);
        msg->ber          = hton32(qs.ber);
        msg->in_order     = qs.in_order;
        msg->max_gap      = hton32(qs.max_gap);
        msg->cypher_s     = hton16(qs.cypher_s);
        msg->timeout      = hton32(qs.timeout);

        memcpy(msg + 1, hash, ipcp_dir_hash_len());
        if (dlen > 0)
                memcpy(buf + len + ETH_HEADER_TOT_SIZE, data, dlen);

        ret = eth_ipcp_send_frame(dst_addr,
#if defined(BUILD_ETH_DIX)
                                  MGMT_EID,
#elif defined(BUILD_ETH_LLC)
                                  reverse_bits(MGMT_SAP),
                                  reverse_bits(MGMT_SAP),
#endif
                                  buf, len + dlen);
        free(buf);

        return ret;
}

static int eth_ipcp_alloc_resp(uint8_t *    dst_addr,
#if defined(BUILD_ETH_DIX)
                               uint16_t     seid,
                               uint16_t     deid,
#elif defined(BUILD_ETH_LLC)
                               uint8_t      ssap,
                               uint8_t      dsap,
#endif
                               int          response,
                               const void * data,
                               size_t       len)
{
        struct mgmt_msg * msg;
        uint8_t *         buf;

        buf = malloc(sizeof(*msg) + ETH_HEADER_TOT_SIZE + len);
        if (buf == NULL)
                return -1;

        msg = (struct mgmt_msg *) (buf + ETH_HEADER_TOT_SIZE);

        msg->code     = FLOW_REPLY;
#if defined(BUILD_ETH_DIX)
        msg->seid     = htons(seid);
        msg->deid     = htons(deid);
#elif defined(BUILD_ETH_LLC)
        msg->ssap     = ssap;
        msg->dsap     = dsap;
#endif
        msg->response = response;

        if (len > 0)
                memcpy(msg + 1, data, len);

        if (eth_ipcp_send_frame(dst_addr,
#if defined(BUILD_ETH_DIX)
                                MGMT_EID,
#elif defined(BUILD_ETH_LLC)
                                reverse_bits(MGMT_SAP),
                                reverse_bits(MGMT_SAP),
#endif
                                buf, sizeof(*msg) + len)) {
                free(buf);
                return -1;
        }

        free(buf);

        return 0;
}

static int eth_ipcp_req(uint8_t *       r_addr,
#if defined(BUILD_ETH_DIX)
                        uint16_t        r_eid,
#elif defined(BUILD_ETH_LLC)
                        uint8_t         r_sap,
#endif
                        const uint8_t * dst,
                        qosspec_t       qs,
                        const void *    data,
                        size_t          len)
{
        struct timespec ts = {0, ALLOC_TIMEO * MILLION};
        struct timespec abstime;
        int             fd;
        time_t          mpl = IPCP_ETH_MPL;

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
        fd = ipcp_flow_req_arr(dst, ipcp_dir_hash_len(), qs, mpl, data, len);
        if (fd < 0) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                log_err("Could not get new flow from IRMd.");
                return -1;
        }

        pthread_rwlock_wrlock(&eth_data.flows_lock);
#if defined(BUILD_ETH_DIX)
        eth_data.fd_to_ef[fd].r_eid = r_eid;
#elif defined(BUILD_ETH_LLC)
        eth_data.fd_to_ef[fd].r_sap = r_sap;
#endif
        memcpy(eth_data.fd_to_ef[fd].r_addr, r_addr, MAC_SIZE);

        pthread_rwlock_unlock(&eth_data.flows_lock);

        ipcpi.alloc_id = fd;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

#if defined(BUILD_ETH_DIX)
        log_dbg("New flow request, fd %d, remote endpoint %d.", fd, r_eid);
#elif defined(BUILD_ETH_LLC)
        log_dbg("New flow request, fd %d, remote SAP %d.", fd, r_sap);
#endif
        return 0;
}

static int eth_ipcp_alloc_reply(uint8_t *    r_addr,
#if defined(BUILD_ETH_DIX)
                                uint16_t     seid,
                                uint16_t     deid,
#elif defined(BUILD_ETH_LLC)
                                uint8_t      ssap,
                                int          dsap,
#endif
                                int          response,
                                const void * data,
                                size_t       len)
{
        int    ret = 0;
        int    fd  = -1;
        time_t mpl = IPCP_ETH_MPL;

        pthread_rwlock_wrlock(&eth_data.flows_lock);

#if defined(BUILD_ETH_DIX)
        fd = deid;
#elif defined(BUILD_ETH_LLC)
        fd = eth_data.ef_to_fd[dsap];
#endif
        if (fd < 0) {
                pthread_rwlock_unlock(& eth_data.flows_lock);
                log_err("No flow found with that SAP.");
                return -1; /* -EFLOWNOTFOUND */
        }

        if (response) {
#ifdef BUILD_ETH_LLC
                bmp_release(eth_data.saps, eth_data.fd_to_ef[fd].sap);
#endif
        } else {
#if defined(BUILD_ETH_DIX)
                eth_data.fd_to_ef[fd].r_eid = seid;
#elif defined(BUILD_ETH_LLC)
                eth_data.fd_to_ef[fd].r_sap = ssap;
#endif
                memcpy(eth_data.fd_to_ef[fd].r_addr, r_addr, MAC_SIZE);
        }

        pthread_rwlock_unlock(&eth_data.flows_lock);

#if defined(BUILD_ETH_DIX)
        log_dbg("Flow reply, fd %d, src eid %d, dst eid %d.", fd, seid, deid);
#elif defined(BUILD_ETH_LLC)
        log_dbg("Flow reply, fd %d, SSAP %d, DSAP %d.", fd, ssap, dsap);
#endif
        if ((ret = ipcp_flow_alloc_reply(fd, response, mpl, data, len)) < 0)
                return -1;

        return ret;

}

static int eth_ipcp_name_query_req(const uint8_t * hash,
                                   uint8_t *       r_addr)
{
        uint8_t *         buf;
        struct mgmt_msg * msg;
        size_t            len;

        if (shim_data_reg_has(eth_data.shim_data, hash)) {
                len = sizeof(*msg) + ipcp_dir_hash_len();

                buf = malloc(len + ETH_HEADER_TOT_SIZE);
                if (buf == NULL)
                        return -1;

                msg       = (struct mgmt_msg *) (buf + ETH_HEADER_TOT_SIZE);
                msg->code = NAME_QUERY_REPLY;

                memcpy(msg + 1, hash, ipcp_dir_hash_len());

                if (eth_ipcp_send_frame(r_addr,
#if defined(BUILD_ETH_DIX)
                                        MGMT_EID,
#elif defined(BUILD_ETH_LLC)
                                        reverse_bits(MGMT_SAP),
                                        reverse_bits(MGMT_SAP),
#endif
                                        buf, len)) {
                        log_err("Failed to send management frame.");
                        free(buf);
                        return -1;
                }

                free(buf);
        }

        return 0;
}

static int eth_ipcp_name_query_reply(const uint8_t * hash,
                                     uint8_t *       r_addr)
{
        uint64_t address = 0;

        memcpy(&address, r_addr, MAC_SIZE);

        shim_data_dir_add_entry(eth_data.shim_data, hash, address);

        shim_data_dir_query_respond(eth_data.shim_data, hash);

        return 0;
}

static int eth_ipcp_mgmt_frame(const uint8_t * buf,
                               size_t          len,
                               uint8_t *       r_addr)
{
        struct mgmt_msg * msg;
        size_t            msg_len;
        qosspec_t         qs;

        msg = (struct mgmt_msg *) buf;

        switch (msg->code) {
        case FLOW_REQ:
                msg_len = sizeof(*msg) + ipcp_dir_hash_len();

                assert(len >= msg_len);

                qs.delay = ntoh32(msg->delay);
                qs.bandwidth = ntoh64(msg->bandwidth);
                qs.availability = msg->availability;
                qs.loss = ntoh32(msg->loss);
                qs.ber = ntoh32(msg->ber);
                qs.in_order = msg->in_order;
                qs.max_gap = ntoh32(msg->max_gap);
                qs.cypher_s = ntoh16(msg->cypher_s);
                qs.timeout = ntoh32(msg->timeout);

                if (shim_data_reg_has(eth_data.shim_data,
                                      buf + sizeof(*msg))) {
                        eth_ipcp_req(r_addr,
#if defined(BUILD_ETH_DIX)
                                     ntohs(msg->seid),
#elif defined(BUILD_ETH_LLC)
                                     msg->ssap,
#endif
                                     buf + sizeof(*msg),
                                     qs,
                                     buf + msg_len,
                                     len - msg_len);
                }
                break;
        case FLOW_REPLY:
                assert(len >= sizeof(*msg));

                eth_ipcp_alloc_reply(r_addr,
#if defined(BUILD_ETH_DIX)
                                     ntohs(msg->seid),
                                     ntohs(msg->deid),
#elif defined(BUILD_ETH_LLC)
                                     msg->ssap,
                                     msg->dsap,
#endif
                                     msg->response,
                                     buf + sizeof(*msg),
                                     len - sizeof(*msg));
                break;
        case NAME_QUERY_REQ:
                eth_ipcp_name_query_req(buf + sizeof(*msg), r_addr);
                break;
        case NAME_QUERY_REPLY:
                eth_ipcp_name_query_reply(buf + sizeof(*msg), r_addr);
                break;
        default:
                log_err("Unknown message received %d.", msg->code);
                return -1;
        }

        return 0;
}

static void * eth_ipcp_mgmt_handler(void * o)
{
        (void) o;

        while (true) {
                int                 ret = 0;
                struct timespec     timeout = {(MGMT_TIMEO / 1000),
                                               (MGMT_TIMEO % 1000) * MILLION};
                struct timespec     abstime;
                struct mgmt_frame * frame = NULL;

                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, &timeout, &abstime);

                pthread_mutex_lock(&eth_data.mgmt_lock);
                pthread_cleanup_push(__cleanup_mutex_unlock,
                                     &eth_data.mgmt_lock);

                while (list_is_empty(&eth_data.mgmt_frames) &&
                       ret != -ETIMEDOUT)
                        ret = -pthread_cond_timedwait(&eth_data.mgmt_cond,
                                                      &eth_data.mgmt_lock,
                                                      &abstime);
                if (ret != -ETIMEDOUT)
                        frame = list_first_entry((&eth_data.mgmt_frames),
                                                 struct mgmt_frame, next);
                if (frame != NULL)
                        list_del(&frame->next);

                pthread_cleanup_pop(true);

                if (frame == NULL)
                        continue;

                eth_ipcp_mgmt_frame(frame->buf, frame->len, frame->r_addr);

                free(frame);
        }

        return (void *) 0;
}

static void * eth_ipcp_packet_reader(void * o)
{
        uint8_t              br_addr[MAC_SIZE];
#if defined(BUILD_ETH_DIX)
        uint16_t             deid;
#elif defined(BUILD_ETH_LLC)
        uint8_t              dsap;
        uint8_t              ssap;
#endif
        uint16_t             length;
        int                  fd;
        uint8_t *            buf;
#if defined(HAVE_NETMAP)
        struct nm_pkthdr     hdr;
#else
        struct shm_du_buff * sdb;
        fd_set               fds;
        int                  frame_len;
#endif
        struct eth_frame *   e_frame;
        struct mgmt_frame *  frame;

        (void) o;

        ipcp_lock_to_core();

        memset(br_addr, 0xff, MAC_SIZE * sizeof(uint8_t));

        while (true) {
#if defined(HAVE_NETMAP)
                if (poll(&eth_data.poll_in, 1, -1) < 0)
                        continue;
                if (eth_data.poll_in.revents == 0) /* TIMED OUT */
                        continue;

                buf = nm_nextpkt(eth_data.nmd, &hdr);
                if (buf == NULL) {
                        log_err("Bad read from netmap device.");
                        continue;
                }
#else
                FD_ZERO(&fds);
    #if defined(HAVE_BPF)
                FD_SET(eth_data.bpf, &fds);
                if (select(eth_data.bpf + 1, &fds, NULL, NULL, NULL))
                        continue;
                assert(FD_ISSET(eth_data.bpf, &fds));
                if (ipcp_sdb_reserve(&sdb, BPF_LEN))
                        continue;
                buf = shm_du_buff_head(sdb);
                frame_len = read(eth_data.bpf, buf, BPF_BLEN);
    #elif defined(HAVE_RAW_SOCKETS)
                FD_SET(eth_data.s_fd, &fds);
                if (select(eth_data.s_fd + 1, &fds, NULL, NULL, NULL) < 0)
                        continue;
                assert(FD_ISSET(eth_data.s_fd, &fds));
                if (ipcp_sdb_reserve(&sdb, ETH_MTU))
                        continue;
                buf = shm_du_buff_head_alloc(sdb, ETH_HEADER_TOT_SIZE);
                if (buf == NULL) {
                        log_dbg("Failed to allocate header.");
                        ipcp_sdb_release(sdb);
                        continue;
                }
                frame_len = recv(eth_data.s_fd, buf,
                                 ETH_MTU + ETH_HEADER_TOT_SIZE, 0);
    #endif
                if (frame_len <= 0) {
                        ipcp_sdb_release(sdb);
                        continue;
                }
#endif

#if defined(HAVE_BPF) && !defined(HAVE_NETMAP)
                e_frame = (struct eth_frame *)
                        (buf + ((struct bpf_hdr *) buf)->bh_hdrlen);
#else
                e_frame = (struct eth_frame *) buf;
#endif
                assert(e_frame->dst_hwaddr);

#if !defined(HAVE_BPF)
    #if defined(HAVE_NETMAP)
                if (memcmp(eth_data.hw_addr,
    #elif defined(HAVE_RAW_SOCKETS)
                if (memcmp(eth_data.device.sll_addr,
    #endif /* HAVE_NETMAP */
                           e_frame->dst_hwaddr,
                           MAC_SIZE) &&
                    memcmp(br_addr, e_frame->dst_hwaddr, MAC_SIZE)) {
                }
#endif
                length = ntohs(e_frame->length);
#if defined(BUILD_ETH_DIX)
                if (e_frame->ethertype != eth_data.ethertype) {
#ifndef HAVE_NETMAP
                        ipcp_sdb_release(sdb);
#endif
                        continue;
                }

                deid = ntohs(e_frame->eid);
                if (deid == MGMT_EID) {
#elif defined (BUILD_ETH_LLC)
                if (length > 0x05FF) { /* DIX */
#ifndef HAVE_NETMAP
                        ipcp_sdb_release(sdb);
#endif
                        continue;
                }

                length -= LLC_HEADER_SIZE;

                dsap = reverse_bits(e_frame->dsap);
                ssap = reverse_bits(e_frame->ssap);

                if (ssap == MGMT_SAP && dsap == MGMT_SAP) {
#endif
                        frame = malloc(sizeof(*frame));
                        if (frame == NULL) {
#ifndef HAVE_NETMAP
                                ipcp_sdb_release(sdb);
#endif
                                continue;
                        }

                        memcpy(frame->buf, &e_frame->payload, length);
                        memcpy(frame->r_addr, e_frame->src_hwaddr, MAC_SIZE);
                        frame->len = length;

                        pthread_mutex_lock(&eth_data.mgmt_lock);
                        list_add(&frame->next, &eth_data.mgmt_frames);
                        pthread_cond_signal(&eth_data.mgmt_cond);
                        pthread_mutex_unlock(&eth_data.mgmt_lock);

#ifndef HAVE_NETMAP
                        ipcp_sdb_release(sdb);
#endif
                } else {
                        pthread_rwlock_rdlock(&eth_data.flows_lock);

#if defined(BUILD_ETH_DIX)
                        fd = deid;
#elif defined(BUILD_ETH_LLC)
                        fd = eth_data.ef_to_fd[dsap];
#endif
                        if (fd < 0) {
                                pthread_rwlock_unlock(&eth_data.flows_lock);
#ifndef HAVE_NETMAP
                                ipcp_sdb_release(sdb);
#endif
                                continue;
                        }

#ifdef BUILD_ETH_LLC
                        if (eth_data.fd_to_ef[fd].r_sap != ssap
                            || memcmp(eth_data.fd_to_ef[fd].r_addr,
                                      e_frame->src_hwaddr, MAC_SIZE)) {
                                pthread_rwlock_unlock(&eth_data.flows_lock);
#ifndef HAVE_NETMAP
                                ipcp_sdb_release(sdb);
#endif
                                continue;
                        }
#endif
                        pthread_rwlock_unlock(&eth_data.flows_lock);

#ifndef HAVE_NETMAP
                        shm_du_buff_head_release(sdb, ETH_HEADER_TOT_SIZE);
                        shm_du_buff_truncate(sdb, length);
#else
                        if (ipcp_sdb_reserve(&sdb, length))
                                continue;

                        buf = shm_du_buff_head(sdb);
                        memcpy(buf, &e_frame->payload, length);
#endif
                        if (np1_flow_write(fd, sdb) < 0)
                                ipcp_sdb_release(sdb);
                }
        }

        return (void *) 0;
}

static void cleanup_writer(void * o)
{
        fqueue_destroy((fqueue_t *) o);
}

static void * eth_ipcp_packet_writer(void * o)
{
        int                  fd;
        struct shm_du_buff * sdb;
        size_t               len;
#if defined(BUILD_ETH_DIX)
        uint16_t             deid;
#elif defined(BUILD_ETH_LLC)
        uint8_t              dsap;
        uint8_t              ssap;
#endif
        uint8_t              r_addr[MAC_SIZE];

        fqueue_t *           fq;

        fq = fqueue_create();
        if (fq == NULL)
                return (void *) -1;

        (void) o;

        pthread_cleanup_push(cleanup_writer, fq);

        ipcp_lock_to_core();

        while (true) {
                fevent(eth_data.np1_flows, fq, NULL);
                while ((fd = fqueue_next(fq)) >= 0) {
                        if (fqueue_type(fq) != FLOW_PKT)
                                continue;

                        if (np1_flow_read(fd, &sdb)) {
                                log_dbg("Bad read from fd %d.", fd);
                                continue;
                        }

                        len = shm_du_buff_len(sdb);

                        if (shm_du_buff_head_alloc(sdb, ETH_HEADER_TOT_SIZE)
                            == NULL) {
                                log_dbg("Failed to allocate header.");
                                ipcp_sdb_release(sdb);
                        }

                        pthread_rwlock_rdlock(&eth_data.flows_lock);
#if defined(BUILD_ETH_DIX)
                        deid = eth_data.fd_to_ef[fd].r_eid;
#elif defined(BUILD_ETH_LLC)
                        dsap = reverse_bits(eth_data.fd_to_ef[fd].r_sap);
                        ssap = reverse_bits(eth_data.fd_to_ef[fd].sap);
#endif
                        memcpy(r_addr,
                               eth_data.fd_to_ef[fd].r_addr,
                               MAC_SIZE);

                        pthread_rwlock_unlock(&eth_data.flows_lock);

                        eth_ipcp_send_frame(r_addr,
#if defined(BUILD_ETH_DIX)
                                            deid,
#elif defined(BUILD_ETH_LLC)
                                            dsap, ssap,
#endif
                                            shm_du_buff_head(sdb),
                                            len);
                        ipcp_sdb_release(sdb);
                }
        }

        pthread_cleanup_pop(true);

        return (void *) 1;
}

#ifdef __linux__
static int open_netlink_socket(void)
{
        struct sockaddr_nl sa;
        int                fd;

        memset(&sa, 0, sizeof(sa));
        sa.nl_family = AF_NETLINK;
        sa.nl_pid = getpid();
        sa.nl_groups = RTMGRP_LINK;

        fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (fd < 0)
                return -1;

        if (bind(fd, (struct sockaddr *) &sa, sizeof(sa))) {
                close(fd);
                return -1;
        }

        return fd;
}

static void change_flows_state(bool up)
{
        int      i;
        uint32_t flags;

        pthread_rwlock_rdlock(&eth_data.flows_lock);

#if defined(BUILD_ETH_DIX)
        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                if (eth_data.fd_to_ef[i].r_eid != -1) {
                        fccntl(i, FLOWGFLAGS, &flags);
                        if (up)
                                fccntl(i, FLOWSFLAGS, flags & ~FLOWFDOWN);
                        else
                                fccntl(i, FLOWSFLAGS, flags | FLOWFDOWN);
                }
#elif defined(BUILD_ETH_LLC)
        for (i = 0; i < MAX_SAPS; i++)
                if (eth_data.ef_to_fd[i] != -1) {
                        fccntl(eth_data.ef_to_fd[i], FLOWGFLAGS, &flags);
                        if (up)
                                fccntl(eth_data.ef_to_fd[i],
                                       FLOWSFLAGS, flags & ~FLOWFDOWN);
                        else
                                fccntl(eth_data.ef_to_fd[i],
                                       FLOWSFLAGS, flags | FLOWFDOWN);
                }
#endif

        pthread_rwlock_unlock(&eth_data.flows_lock);
}

static void * eth_ipcp_if_monitor(void * o)
{
        int                fd;
        int                status;
        char               buf[4096];
        struct iovec       iov = {buf, sizeof(buf)};
        struct sockaddr_nl snl;
        struct msghdr      msg = {(void *) &snl, sizeof(snl),
                                  &iov, 1, NULL, 0, 0};
        struct nlmsghdr *  h;
        struct ifinfomsg * ifi;

        (void ) o;

        fd = open_netlink_socket();
        if (fd < 0) {
                log_err("Failed to open socket.");
                return (void *) -1;
        }

        pthread_cleanup_push(__cleanup_close_ptr, &fd);

        while (true) {
                status = recvmsg(fd, &msg, 0);
                if (status < 0)
                        continue;

                for (h = (struct nlmsghdr *) buf;
                     NLMSG_OK(h, (unsigned int) status);
                     h = NLMSG_NEXT(h, status)) {

                        /* Finish reading */
                        if (h->nlmsg_type == NLMSG_DONE)
                                break;

                        /* Message is some kind of error */
                        if (h->nlmsg_type == NLMSG_ERROR)
                                continue;

                        /* Only interested in link up/down */
                        if (h->nlmsg_type != RTM_NEWLINK)
                                continue;

                        ifi = NLMSG_DATA(h);

                        /* Not our interface */
                        if (ifi->ifi_index != eth_data.if_idx)
                                continue;

                        if (ifi->ifi_flags & IFF_UP) {
                                change_flows_state(true);
                                log_dbg("Interface up.");
                        } else {
                                change_flows_state(false);
                                log_dbg("Interface down.");
                        }
                }
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}
#endif

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

static int eth_ipcp_bootstrap(const struct ipcp_config * conf)
{
        int              idx;
        struct ifreq     ifr;
#if defined(HAVE_NETMAP)
        char             ifn[IFNAMSIZ];
#elif defined(HAVE_BPF)
        int              enable  = 1;
        int              disable = 0;
        int              blen;
#endif /* HAVE_NETMAP */

#if defined(__FreeBSD__) || defined(__APPLE__)
        struct ifaddrs * ifaddr;
        struct ifaddrs * ifa;
#elif defined(__linux__)
        int              skfd;
#endif
#ifndef SHM_RDRB_MULTI_BLOCK
        size_t           maxsz;
#endif
#if defined(HAVE_RAW_SOCKETS)
    #if defined(IPCP_ETH_QDISC_BYPASS)
        int              qdisc_bypass = 1;
    #endif /* ENABLE_QDISC_BYPASS */
        int              flags;
#endif
        assert(conf);
        assert(conf->type == THIS_TYPE);

        ipcpi.dir_hash_algo = conf->layer_info.dir_hash_algo;
        ipcpi.layer_name = strdup(conf->layer_info.layer_name);
        if (ipcpi.layer_name == NULL) {
                log_err("Failed to set layer name");
                return -ENOMEM;
        }

        if (conf->dev == NULL) {
                log_err("Device name is NULL.");
                return -1;
        }

        if (strlen(conf->dev) >= IFNAMSIZ) {
                log_err("Invalid device name: %s.", conf->dev);
                return -1;
        }

        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, conf->dev);

#ifdef BUILD_ETH_DIX
        if (conf->ethertype < 0x0600 || conf->ethertype == 0xFFFF) {
                log_err("Invalid Ethertype.");
                return -1;
        }
        eth_data.ethertype = htons(conf->ethertype);
#endif

#if defined(__FreeBSD__) || defined(__APPLE__)
        if (getifaddrs(&ifaddr) < 0)  {
                log_err("Could not get interfaces.");
                return -1;
        }

        for (ifa = ifaddr, idx = 0; ifa != NULL; ifa = ifa->ifa_next, ++idx) {
                if (strcmp(ifa->ifa_name, conf->dev))
                        continue;
                log_dbg("Interface %s found.", conf->dev);

    #if defined(HAVE_NETMAP) || defined(HAVE_BPF)
                memcpy(eth_data.hw_addr,
                       LLADDR((struct sockaddr_dl *) (ifa)->ifa_addr),
                       MAC_SIZE);
    #elif defined (HAVE_RAW_SOCKETS)
                memcpy(&ifr.ifr_addr, ifa->ifa_addr, sizeof(*ifa->ifa_addr));
    #endif
                break;
        }

        freeifaddrs(ifaddr);

        if (ifa == NULL) {
                log_err("Interface not found.");
                return -1;
        }

#elif defined(__linux__)
        skfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (skfd < 0) {
                log_err("Failed to open socket.");
                return -1;
        }

        if (ioctl(skfd, SIOCGIFMTU, &ifr)) {
                log_err("Failed to get MTU.");
                close(skfd);
                return -1;
        }

        log_dbg("Device MTU is %d.", ifr.ifr_mtu);

        eth_data.mtu = MIN((int) ETH_MTU_MAX, ifr.ifr_mtu);
        if (memcmp(conf->dev, "lo", 2) == 0 && eth_data.mtu > IPCP_ETH_LO_MTU) {
                log_dbg("Using loopback interface. MTU restricted to %d.",
                         IPCP_ETH_LO_MTU);
                eth_data.mtu = IPCP_ETH_LO_MTU;
        }

#ifndef SHM_RDRB_MULTI_BLOCK
        maxsz = SHM_RDRB_BLOCK_SIZE - 5 * sizeof(size_t) -
                (DU_BUFF_HEADSPACE + DU_BUFF_TAILSPACE);
        if ((size_t) eth_data.mtu > maxsz ) {
                log_dbg("Layer MTU truncated to shm block size.");
                eth_data.mtu = maxsz;
        }
#endif
        log_dbg("Layer MTU is %d.", eth_data.mtu);

        if (ioctl(skfd, SIOCGIFHWADDR, &ifr)) {
                log_err("Failed to get hwaddr.");
                close(skfd);
                return -1;
        }

        close(skfd);

        idx = if_nametoindex(conf->dev);
        if (idx == 0) {
                log_err("Failed to retrieve interface index.");
                return -1;
        }
        eth_data.if_idx = idx;
#endif /* __FreeBSD__ */

#if defined(HAVE_NETMAP)
        strcpy(ifn, "netmap:");
        strcat(ifn, conf->dev);

        eth_data.nmd = nm_open(ifn, NULL, 0, NULL);
        if (eth_data.nmd == NULL) {
                log_err("Failed to open netmap device.");
                return -1;
        }

        memset(&eth_data.poll_in, 0, sizeof(eth_data.poll_in));
        memset(&eth_data.poll_out, 0, sizeof(eth_data.poll_out));

        eth_data.poll_in.fd      = NETMAP_FD(eth_data.nmd);
        eth_data.poll_in.events  = POLLIN;
        eth_data.poll_out.fd     = NETMAP_FD(eth_data.nmd);
        eth_data.poll_out.events = POLLOUT;

        log_info("Using netmap device.");
#elif defined(HAVE_BPF) /* !HAVE_NETMAP */
        eth_data.bpf = open_bpf_device();
        if (eth_data.bpf < 0) {
                log_err("Failed to open bpf device.");
                return -1;
        }

        ioctl(eth_data.bpf, BIOCGBLEN, &blen);
        if (BPF_BLEN < blen) {
                log_err("BPF buffer too small (is: %ld must be: %d).",
                        BPF_BLEN, blen);
                goto fail_device;
        }

        if (ioctl(eth_data.bpf, BIOCSETIF, &ifr) < 0) {
                log_err("Failed to set interface.");
                goto fail_device;
        }

        if (ioctl(eth_data.bpf, BIOCSHDRCMPLT, &enable) < 0) {
                log_err("Failed to set BIOCSHDRCMPLT.");
                goto fail_device;
        }

        if (ioctl(eth_data.bpf, BIOCSSEESENT, &disable) < 0) {
                log_err("Failed to set BIOCSSEESENT.");
                goto fail_device;
        }

        if (ioctl(eth_data.bpf, BIOCIMMEDIATE, &enable) < 0) {
                log_err("Failed to set BIOCIMMEDIATE.");
                goto fail_device;
        }

        log_info("Using Berkeley Packet Filter.");
#elif defined(HAVE_RAW_SOCKETS)
        memset(&(eth_data.device), 0, sizeof(eth_data.device));
        eth_data.device.sll_ifindex  = idx;
        eth_data.device.sll_family   = AF_PACKET;
        memcpy(eth_data.device.sll_addr, ifr.ifr_hwaddr.sa_data, MAC_SIZE);
        eth_data.device.sll_halen    = MAC_SIZE;
        eth_data.device.sll_protocol = htons(ETH_P_ALL);

    #if defined (BUILD_ETH_DIX)
        eth_data.s_fd = socket(AF_PACKET, SOCK_RAW, eth_data.ethertype);
    #elif defined (BUILD_ETH_LLC)
        eth_data.s_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_802_2));
    #endif

        log_info("Using raw socket device.");

        if (eth_data.s_fd < 0) {
                log_err("Failed to create socket.");
                return -1;
        }

        flags = fcntl(eth_data.s_fd, F_GETFL, 0);
        if (flags < 0) {
                log_err("Failed to get flags.");
                goto fail_device;
        }

        if (fcntl(eth_data.s_fd, F_SETFL, flags | O_NONBLOCK)) {
                log_err("Failed to set socket non-blocking.");
                goto fail_device;
        }

    #if defined(IPCP_ETH_QDISC_BYPASS)
        if (setsockopt(eth_data.s_fd, SOL_PACKET, PACKET_QDISC_BYPASS,
                       &qdisc_bypass, sizeof(qdisc_bypass))) {
                log_info("Qdisc bypass not supported.");
        }
    #endif

        if (bind(eth_data.s_fd, (struct sockaddr *) &eth_data.device,
                sizeof(eth_data.device))) {
                log_err("Failed to bind socket to interface.");
                goto fail_device;
        }

#endif /* HAVE_NETMAP */
        ipcp_set_state(IPCP_OPERATIONAL);

#if defined(__linux__)
        if (pthread_create(&eth_data.if_monitor,
                           NULL,
                           eth_ipcp_if_monitor,
                           NULL)) {
                ipcp_set_state(IPCP_INIT);
                goto fail_device;
        }
#endif

        if (pthread_create(&eth_data.mgmt_handler,
                           NULL,
                           eth_ipcp_mgmt_handler,
                           NULL)) {
                ipcp_set_state(IPCP_INIT);
                goto fail_mgmt_handler;
        }

        for (idx = 0; idx < IPCP_ETH_RD_THR; ++idx) {
                if (pthread_create(&eth_data.packet_reader[idx],
                                   NULL,
                                   eth_ipcp_packet_reader,
                                   NULL)) {
                        ipcp_set_state(IPCP_INIT);
                        goto fail_packet_reader;
                }
        }

        for (idx = 0; idx < IPCP_ETH_WR_THR; ++idx) {
                if (pthread_create(&eth_data.packet_writer[idx],
                                   NULL,
                                   eth_ipcp_packet_writer,
                                   NULL)) {
                        ipcp_set_state(IPCP_INIT);
                        goto fail_packet_writer;
                }
        }

#if defined(BUILD_ETH_DIX)
        log_dbg("Bootstrapped IPCP over DIX Ethernet with pid %d "
                "and Ethertype 0x%X.", getpid(), conf->ethertype);
#elif defined(BUILD_ETH_LLC)
        log_dbg("Bootstrapped IPCP over Ethernet with LLC with pid %d.",
                getpid());
#endif

        return 0;

 fail_packet_writer:
        while (idx > 0) {
                pthread_cancel(eth_data.packet_writer[--idx]);
                pthread_join(eth_data.packet_writer[idx], NULL);
        }
        idx = IPCP_ETH_RD_THR;
 fail_packet_reader:
        while (idx > 0) {
                pthread_cancel(eth_data.packet_reader[--idx]);
                pthread_join(eth_data.packet_reader[idx], NULL);
        }
        pthread_cancel(eth_data.mgmt_handler);
        pthread_join(eth_data.mgmt_handler, NULL);
 fail_mgmt_handler:
#if defined(__linux__)
        pthread_cancel(eth_data.if_monitor);
        pthread_join(eth_data.if_monitor, NULL);
#endif
#if defined(__linux__) || !defined(HAVE_NETMAP)
 fail_device:
#endif
#if defined(HAVE_NETMAP)
        nm_close(eth_data.nmd);
#elif defined(HAVE_BPF)
        close(eth_data.bpf);
#elif defined(HAVE_RAW_SOCKETS)
        close(eth_data.s_fd);
#endif
        return -1;
}

static int eth_ipcp_reg(const uint8_t * hash)
{
        if (shim_data_reg_add_entry(eth_data.shim_data, hash)) {
                log_err("Failed to add " HASH_FMT " to local registry.",
                        HASH_VAL(hash));
                return -1;
        }

        log_dbg("Registered " HASH_FMT ".", HASH_VAL(hash));

        return 0;
}

static int eth_ipcp_unreg(const uint8_t * hash)
{
        shim_data_reg_del_entry(eth_data.shim_data, hash);

        return 0;
}

static int eth_ipcp_query(const uint8_t * hash)
{
        uint8_t            r_addr[MAC_SIZE];
        struct timespec    timeout = {(NAME_QUERY_TIMEO / 1000),
                                      (NAME_QUERY_TIMEO % 1000) * MILLION};
        struct dir_query * query;
        int                ret;
        uint8_t *          buf;
        struct mgmt_msg *  msg;
        size_t             len;

        if (shim_data_dir_has(eth_data.shim_data, hash))
                return 0;

        len = sizeof(*msg) + ipcp_dir_hash_len();

        buf = malloc(len + ETH_HEADER_TOT_SIZE);
        if (buf == NULL)
                return -1;

        msg       = (struct mgmt_msg *) (buf + ETH_HEADER_TOT_SIZE);
        msg->code = NAME_QUERY_REQ;

        memcpy(msg + 1, hash, ipcp_dir_hash_len());

        memset(r_addr, 0xff, MAC_SIZE);

        query = shim_data_dir_query_create(eth_data.shim_data, hash);
        if (query == NULL) {
                free(buf);
                return -1;
        }

        if (eth_ipcp_send_frame(r_addr,
#if defined(BUILD_ETH_DIX)
                                MGMT_EID,
#elif defined(BUILD_ETH_LLC)
                                reverse_bits(MGMT_SAP),
                                reverse_bits(MGMT_SAP),
#endif
                                buf, len)) {
                log_err("Failed to send management frame.");
                shim_data_dir_query_destroy(eth_data.shim_data, query);
                free(buf);
                return -1;
        }

        free(buf);

        ret = shim_data_dir_query_wait(query, &timeout);

        shim_data_dir_query_destroy(eth_data.shim_data, query);

        return ret;
}

static int eth_ipcp_flow_alloc(int             fd,
                               const uint8_t * hash,
                               qosspec_t       qs,
                               const void *    data,
                               size_t          len)
{
#ifdef BUILD_ETH_LLC
        uint8_t  ssap = 0;
#endif
        uint8_t  r_addr[MAC_SIZE];
        uint64_t addr = 0;

        log_dbg("Allocating flow to " HASH_FMT ".", HASH_VAL(hash));

        assert(hash);

        if (!shim_data_dir_has(eth_data.shim_data, hash)) {
                log_err("Destination unreachable.");
                return -1;
        }
        addr = shim_data_dir_get_addr(eth_data.shim_data, hash);

        pthread_rwlock_wrlock(&eth_data.flows_lock);
#ifdef BUILD_ETH_LLC
        ssap = bmp_allocate(eth_data.saps);
        if (!bmp_is_id_valid(eth_data.saps, ssap)) {
                pthread_rwlock_unlock(&eth_data.flows_lock);
                return -1;
        }

        eth_data.fd_to_ef[fd].sap = ssap;
        eth_data.ef_to_fd[ssap]   = fd;
#endif
        pthread_rwlock_unlock(&eth_data.flows_lock);

        memcpy(r_addr, &addr, MAC_SIZE);

        if (eth_ipcp_alloc(r_addr,
#if defined(BUILD_ETH_DIX)
                           fd,
#elif defined(BUILD_ETH_LLC)
                           ssap,
#endif
                           hash,
                           qs,
                           data,
                           len) < 0) {
#ifdef BUILD_ETH_LLC
                pthread_rwlock_wrlock(&eth_data.flows_lock);
                bmp_release(eth_data.saps, eth_data.fd_to_ef[fd].sap);
                eth_data.fd_to_ef[fd].sap = -1;
                eth_data.ef_to_fd[ssap]   = -1;
                pthread_rwlock_unlock(&eth_data.flows_lock);
#endif
                return -1;
        }

        fset_add(eth_data.np1_flows, fd);
#if defined(BUILD_ETH_DIX)
        log_dbg("Pending flow with fd %d.", fd);
#elif defined(BUILD_ETH_LLC)
        log_dbg("Pending flow with fd %d on SAP %d.", fd, ssap);
#endif
        return 0;
}

static int eth_ipcp_flow_alloc_resp(int          fd,
                                    int          response,
                                    const void * data,
                                    size_t       len)
{
        struct timespec ts    = {0, ALLOC_TIMEO * MILLION};
        struct timespec abstime;
#if defined(BUILD_ETH_DIX)
        uint16_t        r_eid;
#elif defined(BUILD_ETH_LLC)
        uint8_t         ssap;
        uint8_t         r_sap;
#endif
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

        pthread_rwlock_wrlock(&eth_data.flows_lock);
#if defined(BUILD_ETH_DIX)
        r_eid = eth_data.fd_to_ef[fd].r_eid;
#elif defined(BUILD_ETH_LLC)
        ssap = bmp_allocate(eth_data.saps);
        if (!bmp_is_id_valid(eth_data.saps, ssap)) {
                pthread_rwlock_unlock(&eth_data.flows_lock);
                return -1;
        }

        eth_data.fd_to_ef[fd].sap = ssap;
        r_sap = eth_data.fd_to_ef[fd].r_sap;
        eth_data.ef_to_fd[ssap] = fd;
#endif
        memcpy(r_addr, eth_data.fd_to_ef[fd].r_addr, MAC_SIZE);

        pthread_rwlock_unlock(&eth_data.flows_lock);

        if (eth_ipcp_alloc_resp(r_addr,
#if defined(BUILD_ETH_DIX)
                                fd, r_eid,
#elif defined(BUILD_ETH_LLC)
                                ssap, r_sap,
#endif
                                response,
                                data,
                                len) < 0) {
#ifdef BUILD_ETH_LLC
                pthread_rwlock_wrlock(&eth_data.flows_lock);
                bmp_release(eth_data.saps, eth_data.fd_to_ef[fd].sap);
                pthread_rwlock_unlock(&eth_data.flows_lock);
#endif
                return -1;
        }

        fset_add(eth_data.np1_flows, fd);
#if defined(BUILD_ETH_DIX)
        log_dbg("Accepted flow, fd %d.", fd);
#elif defined(BUILD_ETH_LLC)
        log_dbg("Accepted flow, fd %d, SAP %d.", fd, (uint8_t)ssap);
#endif
        return 0;
}

static int eth_ipcp_flow_dealloc(int fd)
{
#ifdef BUILD_ETH_LLC
        uint8_t sap;
#endif
        ipcp_flow_fini(fd);

        fset_del(eth_data.np1_flows, fd);

        pthread_rwlock_wrlock(&eth_data.flows_lock);

#if defined(BUILD_ETH_DIX)
        eth_data.fd_to_ef[fd].r_eid = -1;
#elif defined BUILD_ETH_LLC
        sap = eth_data.fd_to_ef[fd].sap;
        bmp_release(eth_data.saps, sap);
        eth_data.fd_to_ef[fd].sap = -1;
        eth_data.fd_to_ef[fd].r_sap = -1;
        eth_data.ef_to_fd[sap] = -1;
#endif
        memset(&eth_data.fd_to_ef[fd].r_addr, 0, MAC_SIZE);

        pthread_rwlock_unlock(&eth_data.flows_lock);

        flow_dealloc(fd);

        log_dbg("Flow with fd %d deallocated.", fd);

        return 0;
}

static struct ipcp_ops eth_ops = {
        .ipcp_bootstrap       = eth_ipcp_bootstrap,
        .ipcp_enroll          = NULL,
        .ipcp_connect         = NULL,
        .ipcp_disconnect      = NULL,
        .ipcp_reg             = eth_ipcp_reg,
        .ipcp_unreg           = eth_ipcp_unreg,
        .ipcp_query           = eth_ipcp_query,
        .ipcp_flow_alloc      = eth_ipcp_flow_alloc,
        .ipcp_flow_join       = NULL,
        .ipcp_flow_alloc_resp = eth_ipcp_flow_alloc_resp,
        .ipcp_flow_dealloc    = eth_ipcp_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        int i;

        if (ipcp_init(argc, argv, &eth_ops, THIS_TYPE) < 0)
                goto fail_init;

        if (eth_data_init() < 0) {
#if defined(BUILD_ETH_DIX)
                log_err("Failed to init eth-llc data.");
#elif defined(BUILD_ETH_LLC)
                log_err("Failed to init eth-dix data.");
#endif
                goto fail_data_init;
        }

        if (ipcp_start() < 0) {
                log_err("Failed to start IPCP.");
                goto fail_start;
        }

        ipcp_sigwait();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                for (i = 0; i < IPCP_ETH_WR_THR; ++i)
                        pthread_cancel(eth_data.packet_writer[i]);
                for (i = 0; i < IPCP_ETH_RD_THR; ++i)
                        pthread_cancel(eth_data.packet_reader[i]);

                pthread_cancel(eth_data.mgmt_handler);
#ifdef __linux__
                pthread_cancel(eth_data.if_monitor);
#endif
                for (i = 0; i < IPCP_ETH_WR_THR; ++i)
                        pthread_join(eth_data.packet_writer[i], NULL);
                for (i = 0; i < IPCP_ETH_RD_THR; ++i)
                        pthread_join(eth_data.packet_reader[i], NULL);

                pthread_join(eth_data.mgmt_handler, NULL);
#ifdef __linux__
                pthread_join(eth_data.if_monitor, NULL);
#endif
        }

        ipcp_stop();

        ipcp_fini();

        eth_data_fini();

        exit(EXIT_SUCCESS);

 fail_start:
        eth_data_fini();
 fail_data_init:
        ipcp_fini();
 fail_init:
        exit(EXIT_FAILURE);
}
