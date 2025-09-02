/*
 * Ouroboros - Copyright (C) 2016 - 2024
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

#include <ouroboros/endian.h>
#include <ouroboros/hash.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/logs.h>
#include <ouroboros/time.h>
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
  #define BPF_DEV_MAX        256
  #define BPF_BLEN           sysconf(_SC_PAGESIZE)
  #include <net/bpf.h>
#endif

#define MAC_FMT "%02x:%02x:%02x:%02x:%02x:%02x"
#define MAC_VAL(a)                                         \
        (uint8_t)(a)[0], (uint8_t)(a)[1], (uint8_t)(a)[2], \
        (uint8_t)(a)[3], (uint8_t)(a)[4], (uint8_t)(a)[5]


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

#define NAME_QUERY_TIMEO     2000  /* ms */
#define MGMT_TIMEO           100   /* ms */
#define MGMT_FRAME_SIZE      2048

#define FLOW_REQ             0
#define FLOW_REPLY           1
#define NAME_QUERY_REQ       2
#define NAME_QUERY_REPLY     3

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
        int32_t  response;
        uint8_t  in_order;
#if defined (BUILD_ETH_DIX)
        uint8_t  code;
        uint8_t  availability;
#endif
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

        int                mtu;
#ifdef __linux__
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

static int eth_ipcp_alloc(const uint8_t *  dst_addr,
#if defined(BUILD_ETH_DIX)
                          uint16_t         eid,
#elif defined(BUILD_ETH_LLC)
                          uint8_t          ssap,
#endif
                          const uint8_t *  hash,
                          qosspec_t        qs,
                          const buffer_t * data)
{
        uint8_t *         buf;
        struct mgmt_msg * msg;
        size_t            len;
        int               ret;

        len = sizeof(*msg) + ipcp_dir_hash_len();

        buf = malloc(len + ETH_HEADER_TOT_SIZE + data->len);
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
        msg->timeout      = hton32(qs.timeout);

        memcpy(msg + 1, hash, ipcp_dir_hash_len());
        if (data->len > 0)
                memcpy(buf + len + ETH_HEADER_TOT_SIZE, data->data, data->len);

        ret = eth_ipcp_send_frame(dst_addr,
#if defined(BUILD_ETH_DIX)
                                  MGMT_EID,
#elif defined(BUILD_ETH_LLC)
                                  reverse_bits(MGMT_SAP),
                                  reverse_bits(MGMT_SAP),
#endif
                                  buf, len + data->len);
        free(buf);

        return ret;
}

static int eth_ipcp_alloc_resp(uint8_t *        dst_addr,
#if defined(BUILD_ETH_DIX)
                               uint16_t         seid,
                               uint16_t         deid,
#elif defined(BUILD_ETH_LLC)
                               uint8_t          ssap,
                               uint8_t          dsap,
#endif
                               int              response,
                               const buffer_t * data)
{
        struct mgmt_msg * msg;
        uint8_t *         buf;

        buf = malloc(sizeof(*msg) + ETH_HEADER_TOT_SIZE + data->len);
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
        msg->response = hton32(response);

        if (data->len > 0)
                memcpy(msg + 1, data->data, data->len);

        if (eth_ipcp_send_frame(dst_addr,
#if defined(BUILD_ETH_DIX)
                                MGMT_EID,
#elif defined(BUILD_ETH_LLC)
                                reverse_bits(MGMT_SAP),
                                reverse_bits(MGMT_SAP),
#endif
                                buf, sizeof(*msg) + data->len)) {
                free(buf);
                return -1;
        }

        free(buf);

        return 0;
}

static int eth_ipcp_req(uint8_t *        r_addr,
#if defined(BUILD_ETH_DIX)
                        uint16_t         r_eid,
#elif defined(BUILD_ETH_LLC)
                        uint8_t          r_sap,
#endif
                        const uint8_t *  dst,
                        qosspec_t        qs,
                        const buffer_t * data)
{
        int fd;

        fd = ipcp_wait_flow_req_arr(dst, qs, IPCP_ETH_MPL, data);
        if (fd < 0) {
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

#if defined(BUILD_ETH_DIX)
        log_dbg("New flow request, fd %d, remote endpoint %d.", fd, r_eid);
#elif defined(BUILD_ETH_LLC)
        log_dbg("New flow request, fd %d, remote SAP %d.", fd, r_sap);
#endif
        return 0;
}

static int eth_ipcp_alloc_reply(uint8_t *        r_addr,
#if defined(BUILD_ETH_DIX)
                                uint16_t         seid,
                                uint16_t         deid,
#elif defined(BUILD_ETH_LLC)
                                uint8_t          ssap,
                                int              dsap,
#endif
                                int              response,
                                const buffer_t * data)
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
        if ((ret = ipcp_flow_alloc_reply(fd, response, mpl, data)) < 0) {
                log_err("Failed to reply to flow allocation.");
                return -1;
        }

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
        struct addr addr;

        memcpy(&addr.mac, r_addr, MAC_SIZE);

        shim_data_dir_add_entry(eth_data.shim_data, hash, addr);

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
        buffer_t          data;

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
                qs.timeout = ntoh32(msg->timeout);

                data.data = (uint8_t *) buf + msg_len;
                data.len  = len - msg_len;

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
                                     &data);
                }
                break;
        case FLOW_REPLY:
                assert(len >= sizeof(*msg));

                data.data = (uint8_t *) buf + sizeof(*msg);
                data.len  = len - sizeof(*msg);

                eth_ipcp_alloc_reply(r_addr,
#if defined(BUILD_ETH_DIX)
                                     ntohs(msg->seid),
                                     ntohs(msg->deid),
#elif defined(BUILD_ETH_LLC)
                                     msg->ssap,
                                     msg->dsap,
#endif
                                     ntoh32(msg->response),
                                     &data);
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

        pthread_cleanup_push(__cleanup_mutex_unlock, &eth_data.mgmt_lock);

        while (true) {
                int                 ret = 0;
                struct timespec     timeout = TIMESPEC_INIT_MS(MGMT_TIMEO);
                struct timespec     abstime;
                struct mgmt_frame * frame = NULL;

                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, &timeout, &abstime);

                pthread_mutex_lock(&eth_data.mgmt_lock);

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

                pthread_mutex_unlock(&eth_data.mgmt_lock);

                if (frame == NULL)
                        continue;

                eth_ipcp_mgmt_frame(frame->buf, frame->len, frame->r_addr);

                free(frame);
        }

        pthread_cleanup_pop(false);

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
                        log_dbg("Bad read from netmap device.");
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
                        log_dbg("Failed to receive frame.");
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
                if (e_frame->ethertype != eth_data.ethertype)
                        goto fail_frame;

                deid = ntohs(e_frame->eid);
                if (deid == MGMT_EID) {
#elif defined (BUILD_ETH_LLC)
                if (length > 0x05FF) /* DIX */
                        goto fail_frame;

                length -= LLC_HEADER_SIZE;

                dsap = reverse_bits(e_frame->dsap);
                ssap = reverse_bits(e_frame->ssap);

                if (ssap == MGMT_SAP && dsap == MGMT_SAP) {
#endif
                        ipcp_sdb_release(sdb); /* No need for the N+1 buffer. */

                        frame = malloc(sizeof(*frame));
                        if (frame == NULL) {
                                log_err("Failed to allocate frame.");
                                goto fail_frame;
                        }

                        memcpy(frame->buf, &e_frame->payload, length);
                        memcpy(frame->r_addr, e_frame->src_hwaddr, MAC_SIZE);
                        frame->len = length;

                        pthread_mutex_lock(&eth_data.mgmt_lock);
                        list_add(&frame->next, &eth_data.mgmt_frames);
                        pthread_cond_signal(&eth_data.mgmt_cond);
                        pthread_mutex_unlock(&eth_data.mgmt_lock);
                } else {
                        pthread_rwlock_rdlock(&eth_data.flows_lock);

#if defined(BUILD_ETH_DIX)
                        fd = deid;
#elif defined(BUILD_ETH_LLC)
                        fd = eth_data.ef_to_fd[dsap];
#endif
                        if (fd < 0) {
                                pthread_rwlock_unlock(&eth_data.flows_lock);
                                goto fail_frame;
                        }

#ifdef BUILD_ETH_LLC
                        if (eth_data.fd_to_ef[fd].r_sap != ssap
                            || memcmp(eth_data.fd_to_ef[fd].r_addr,
                                      e_frame->src_hwaddr, MAC_SIZE)) {
                                pthread_rwlock_unlock(&eth_data.flows_lock);
                                goto fail_frame;
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

                        continue;
 fail_frame:
#ifndef HAVE_NETMAP
                        ipcp_sdb_release(sdb);
#endif
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

        ipcp_lock_to_core();

        pthread_cleanup_push(cleanup_writer, fq);

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
                                continue;
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

                        if (eth_ipcp_send_frame(r_addr,
#if defined(BUILD_ETH_DIX)
                                            deid,
#elif defined(BUILD_ETH_LLC)
                                            dsap, ssap,
#endif
                                            shm_du_buff_head(sdb),
                                            len))
                                log_dbg("Failed to send frame.");
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

#if defined(__FreeBSD__) || defined(__APPLE__)
static int ifr_hwaddr_from_ifaddrs(struct ifreq * ifr)
{
        struct ifaddrs * ifaddr;
        struct ifaddrs * ifa;
        int              idx;

        if (getifaddrs(&ifaddr) < 0)  {
                log_err("Could not get interfaces.");
                goto fail_ifaddrs;
        }

        for (ifa = ifaddr, idx = 0; ifa != NULL; ifa = ifa->ifa_next, ++idx) {
                if (strcmp(ifa->ifa_name, ifr->ifr_name) == 0)
                        break;
        }

        if (ifa == NULL) {
                log_err("Interface not found.");
                goto fail_ifa;
        }

        memcpy(&ifr->ifr_addr, ifa->ifa_addr, sizeof(*ifa->ifa_addr));

        log_dbg("Interface %s hwaddr " MAC_FMT ".", ifr->ifr_name,
                MAC_VAL(ifr->ifr_addr.sa_data));

        freeifaddrs(ifaddr);

        return 0;
 fail_ifa:
         freeifaddrs(ifaddr);
 fail_ifaddrs:
        return -1;

}
#elif defined(__linux__)
static int ifr_hwaddr_from_socket(struct ifreq * ifr)
{
        int skfd;

        skfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (skfd < 0) {
                log_err("Failed to open socket.");
                goto fail_socket;
        }

        if (ioctl(skfd, SIOCGIFHWADDR, ifr)) {
                log_err("Failed to get hwaddr.");
                goto fail_ifr;
        }

        log_dbg("Interface %s hwaddr " MAC_FMT ".", ifr->ifr_name,
                MAC_VAL(ifr->ifr_hwaddr.sa_data));

        close(skfd);

        return 0;

 fail_ifr:
        close(skfd);
 fail_socket:
        return -1;
}
#endif

static int eth_ifr_hwaddr(struct ifreq * ifr)
{
#if defined(__FreeBSD__) || defined(__APPLE__)
        return ifr_hwaddr_from_ifaddrs(ifr);
#elif defined(__linux__)
        return ifr_hwaddr_from_socket(ifr);
#else
        return -1;
#endif
}

static int eth_ifr_mtu(struct ifreq * ifr)
{
        int skfd;

        skfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (skfd < 0) {
                log_err("Failed to open socket.");
                goto fail_socket;
        }

        if (ioctl(skfd, SIOCGIFMTU, ifr) < 0) {
                log_err("Failed to get MTU.");
                goto fail_mtu;
        }
        close(skfd);

        return 0;

 fail_mtu:
        close(skfd);
 fail_socket:
        return -1;
}

static int eth_set_mtu(struct ifreq * ifr)
{
        if (eth_ifr_mtu(ifr) < 0) {
                log_err("Failed to get interface MTU.");
                return -1;
        }

        log_dbg("Device MTU is %d.", ifr->ifr_mtu);

        eth_data.mtu = MIN((int) ETH_MTU_MAX, ifr->ifr_mtu);
        if (memcmp(ifr->ifr_name, "lo", 2) == 0 &&
                   eth_data.mtu > IPCP_ETH_LO_MTU) {
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

        return 0;
}
#if defined(HAVE_NETMAP)
static int eth_init_nmd(struct ifreq * ifr)
{
        strcpy(ifn, "netmap:");
        strcat(ifn, ifr->ifr_name);

        eth_data.nmd = nm_open(ifn, NULL, 0, NULL);
        if (eth_data.nmd == NULL) {
                log_err("Failed to open netmap device.");
                goto fail_nmd;
        }

        memset(&eth_data.poll_in, 0, sizeof(eth_data.poll_in));
        memset(&eth_data.poll_out, 0, sizeof(eth_data.poll_out));

        eth_data.poll_in.fd      = NETMAP_FD(eth_data.nmd);
        eth_data.poll_in.events  = POLLIN;
        eth_data.poll_out.fd     = NETMAP_FD(eth_data.nmd);
        eth_data.poll_out.events = POLLOUT;

        log_info("Using netmap device.");

        return 0;
 fail_nmd:
        return -1;
}
#elif defined (HAVE_BPF)
static int eth_init_bpf(struct ifreq * ifr)
{
        int enable  = 1;
        int disable = 0;
        int blen;

        eth_data.bpf = open_bpf_device();
        if (eth_data.bpf < 0) {
                log_err("Failed to open bpf device.");
                goto fail_bpf;
        }

        ioctl(eth_data.bpf, BIOCGBLEN, &blen);
        if (BPF_BLEN < blen) {
                log_err("BPF buffer too small (is: %ld must be: %d).",
                        BPF_BLEN, blen);
                goto fail_device;
        }

        if (ioctl(eth_data.bpf, BIOCSETIF, ifr) < 0) {
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

        return 0;

 fail_device:
        close(eth_data.bpf);
 fail_bpf:
        return -1;
}
#elif defined(HAVE_RAW_SOCKETS)
static int eth_init_raw_socket(struct ifreq * ifr)
{
        int idx;
        int flags;
#if defined(IPCP_ETH_QDISC_BYPASS)
        int              qdisc_bypass = 1;
#endif /* ENABLE_QDISC_BYPASS */

        idx = if_nametoindex(ifr->ifr_name);
        if (idx == 0) {
                log_err("Failed to retrieve interface index.");
                return -1;
        }
        memset(&(eth_data.device), 0, sizeof(eth_data.device));
        eth_data.device.sll_ifindex  = idx;
        eth_data.device.sll_family   = AF_PACKET;
        memcpy(eth_data.device.sll_addr, ifr->ifr_hwaddr.sa_data, MAC_SIZE);
        eth_data.device.sll_halen    = MAC_SIZE;
        eth_data.device.sll_protocol = htons(ETH_P_ALL);
#if defined (BUILD_ETH_DIX)
        eth_data.s_fd = socket(AF_PACKET, SOCK_RAW, eth_data.ethertype);
#elif defined (BUILD_ETH_LLC)
        eth_data.s_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_802_2));
#endif
        if (eth_data.s_fd < 0) {
                log_err("Failed to create socket.");
                goto fail_socket;
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
                 sizeof(eth_data.device)) < 0) {
                log_err("Failed to bind socket to interface.");
                goto fail_device;
        }
#ifdef __linux__
        eth_data.if_idx = idx;
#endif
        log_info("Using raw socket device.");

        return 0;
 fail_device:
        close(eth_data.s_fd);
 fail_socket:
        return -1;
}
#endif

static int eth_ipcp_bootstrap(struct ipcp_config * conf)
{
        struct ifreq     ifr;
        int              i;
#if defined(HAVE_NETMAP)
        char             ifn[IFNAMSIZ];
#endif /* HAVE_NETMAP */

#ifndef SHM_RDRB_MULTI_BLOCK
        size_t           maxsz;
#endif
        assert(conf);
        assert(conf->type == THIS_TYPE);

        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, conf->eth.dev);

        if (strlen(conf->eth.dev) >= IFNAMSIZ) {
                log_err("Invalid device name: %s.", conf->eth.dev);
                return -1;
        }
#ifdef BUILD_ETH_DIX
        if (conf->eth.ethertype < 0x0600 || conf->eth.ethertype == 0xFFFF) {
                log_err("Invalid Ethertype: %d.", conf->eth.ethertype);
                return -1;
        }
        eth_data.ethertype = htons(conf->eth.ethertype);
#endif
        if (eth_set_mtu(&ifr) < 0) {
                log_err("Failed to set MTU.");
                return -1;
        }

        if (eth_ifr_hwaddr(&ifr) < 0) {
                log_err("Failed to get hardware addr.");
                return -1;
        }
#if defined(HAVE_NETMAP) || defined(HAVE_BPF)
        memcpy(eth_data.hw_addr, LLADDR((struct sockaddr_dl *) &ifr.ifr_addr),
               MAC_SIZE);
#endif
#if defined(HAVE_NETMAP)
        if (eth_init_nmd(&ifr) < 0) {
                log_err("Failed to initialize netmap device.");
                return -1;
        }
#elif defined(HAVE_BPF) /* !HAVE_NETMAP */
        if (eth_init_bpf(&ifr) < 0) {
                log_err("Failed to initialize BPF device.");
                return -1;
        }
#elif defined(HAVE_RAW_SOCKETS)
        if (eth_init_raw_socket(&ifr) < 0) {
                log_err("Failed to initialize raw socket device.");
                return -1;
        }
#endif /* HAVE_NETMAP */
#if defined(__linux__)
        if (pthread_create(&eth_data.if_monitor, NULL,
                           eth_ipcp_if_monitor, NULL)) {
                log_err("Failed to create monitor thread: %s.",
                        strerror(errno));
                goto fail_monitor;
        }
#endif
        if (pthread_create(&eth_data.mgmt_handler, NULL,
                           eth_ipcp_mgmt_handler, NULL)) {
                log_err("Failed to create mgmt handler thread: %s.",
                        strerror(errno));
                goto fail_mgmt_handler;
        }

        for (i = 0; i < IPCP_ETH_RD_THR; i++) {
                if (pthread_create(&eth_data.packet_reader[i], NULL,
                                   eth_ipcp_packet_reader, NULL)) {
                        log_err("Failed to create packet reader thread: %s",
                                strerror(errno));
                        goto fail_packet_reader;
                }
        }

        for (i = 0; i < IPCP_ETH_WR_THR; i++) {
                if (pthread_create(&eth_data.packet_writer[i], NULL,
                                   eth_ipcp_packet_writer, NULL)) {
                        log_err("Failed to create packet writer thread: %s",
                                strerror(errno));
                        goto fail_packet_writer;
                }
        }

#if defined(BUILD_ETH_DIX)
        log_dbg("Bootstrapped IPCP over DIX Ethernet with pid %d "
                "and Ethertype 0x%X.", getpid(), conf->eth.ethertype);
#elif defined(BUILD_ETH_LLC)
        log_dbg("Bootstrapped IPCP over Ethernet with LLC with pid %d.",
                getpid());
#endif
        return 0;

 fail_packet_writer:
        while (i-- > 0) {
                pthread_cancel(eth_data.packet_writer[i]);
                pthread_join(eth_data.packet_writer[i], NULL);
        }
        i = IPCP_ETH_RD_THR;
 fail_packet_reader:
        while (i-- > 0) {
                pthread_cancel(eth_data.packet_reader[i]);
                pthread_join(eth_data.packet_reader[i], NULL);
        }
        pthread_cancel(eth_data.mgmt_handler);
        pthread_join(eth_data.mgmt_handler, NULL);
 fail_mgmt_handler:
#if defined(__linux__)
        pthread_cancel(eth_data.if_monitor);
        pthread_join(eth_data.if_monitor, NULL);
#endif
#if defined(__linux__)
 fail_monitor:
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
                log_err("Failed to add " HASH_FMT32 " to local registry.",
                        HASH_VAL32(hash));
                return -1;
        }

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
        struct timespec    timeout = TIMESPEC_INIT_MS(NAME_QUERY_TIMEO);
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

static int eth_ipcp_flow_alloc(int              fd,
                               const uint8_t *  hash,
                               qosspec_t        qs,
                               const buffer_t * data)
{
#ifdef BUILD_ETH_LLC
        uint8_t  ssap = 0;
#endif
        uint8_t  r_addr[MAC_SIZE];
        struct addr addr;

        assert(hash);

        if (!shim_data_dir_has(eth_data.shim_data, hash)) {
                log_err("Destination "HASH_FMT32 "unreachable.",
                        HASH_VAL32(hash));
                return -1;
        }

        addr = shim_data_dir_get_addr(eth_data.shim_data, hash);
        memcpy(r_addr, &addr.mac, MAC_SIZE);

#ifdef BUILD_ETH_LLC
        pthread_rwlock_wrlock(&eth_data.flows_lock);
        ssap = bmp_allocate(eth_data.saps);
        if (!bmp_is_id_valid(eth_data.saps, ssap)) {
                pthread_rwlock_unlock(&eth_data.flows_lock);
                log_err("Failed to allocate SSAP.");
                return -1;
        }

        eth_data.fd_to_ef[fd].sap = ssap;
        eth_data.ef_to_fd[ssap]   = fd;
        pthread_rwlock_unlock(&eth_data.flows_lock);
#endif

        if (eth_ipcp_alloc(r_addr,
#if defined(BUILD_ETH_DIX)
                           fd,
#elif defined(BUILD_ETH_LLC)
                           ssap,
#endif
                           hash,
                           qs,
                           data) < 0) {
#ifdef BUILD_ETH_LLC
                pthread_rwlock_wrlock(&eth_data.flows_lock);
                bmp_release(eth_data.saps, eth_data.fd_to_ef[fd].sap);
                eth_data.fd_to_ef[fd].sap = -1;
                eth_data.ef_to_fd[ssap]   = -1;
                pthread_rwlock_unlock(&eth_data.flows_lock);
                log_err("Failed to allocate with peer.");
#endif
                return -1;
        }

        fset_add(eth_data.np1_flows, fd);
#if defined(BUILD_ETH_LLC)
        log_dbg("Assigned SAP %d for fd %d.", ssap, fd);
#endif
        return 0;
}

static int eth_ipcp_flow_alloc_resp(int              fd,
                                    int              response,
                                    const buffer_t * data)
{
#if defined(BUILD_ETH_DIX)
        uint16_t        r_eid;
#elif defined(BUILD_ETH_LLC)
        uint8_t         ssap;
        uint8_t         r_sap;
#endif
        uint8_t         r_addr[MAC_SIZE];

        if (ipcp_wait_flow_resp(fd) < 0) {
                log_err("Failed to wait for flow response.");
                return -1;
        }

        pthread_rwlock_wrlock(&eth_data.flows_lock);
#if defined(BUILD_ETH_DIX)
        r_eid = eth_data.fd_to_ef[fd].r_eid;
#elif defined(BUILD_ETH_LLC)
        ssap = bmp_allocate(eth_data.saps);
        if (!bmp_is_id_valid(eth_data.saps, ssap)) {
                pthread_rwlock_unlock(&eth_data.flows_lock);
                log_err("Failed to allocate SSAP.");
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
                                data) < 0) {
#ifdef BUILD_ETH_LLC
                pthread_rwlock_wrlock(&eth_data.flows_lock);
                bmp_release(eth_data.saps, eth_data.fd_to_ef[fd].sap);
                pthread_rwlock_unlock(&eth_data.flows_lock);
#endif
                log_err("Failed to respond to peer.");
                return -1;
        }

        fset_add(eth_data.np1_flows, fd);
#if defined(BUILD_ETH_LLC)
        log_dbg("Assigned SAP %d for fd %d.", ssap, fd);
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

        ipcp_flow_dealloc(fd);

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

        if (eth_data_init() < 0) {
#if defined(BUILD_ETH_DIX)
                log_err("Failed to init eth-llc data.");
#elif defined(BUILD_ETH_LLC)
                log_err("Failed to init eth-dix data.");
#endif
                goto fail_data_init;
        }

        if (ipcp_init(argc, argv, &eth_ops, THIS_TYPE) < 0) {
                log_err("Failed to initialize IPCP.");
                goto fail_init;
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
        ipcp_fini();
 fail_init:
        eth_data_fini();
 fail_data_init:
        exit(EXIT_FAILURE);
}
