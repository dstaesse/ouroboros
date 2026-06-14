/*
 * Ouroboros - Copyright (C) 2016 - 2026
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

#include <ouroboros/atomics.h>
#include <ouroboros/endian.h>
#include <ouroboros/hash.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/crc8.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/logs.h>
#include <ouroboros/np1_flow.h>
#include <ouroboros/time.h>
#include <ouroboros/fccntl.h>
#include <ouroboros/pthread.h>
#include <ouroboros/rib.h>

#ifndef IPCP_ETH_FLOW_STATS
#undef  FETCH_ADD_RELAXED
#define FETCH_ADD_RELAXED(p, v) ((void) 0)
#undef  FETCH_SUB_RELAXED
#define FETCH_SUB_RELAXED(p, v) ((void) 0)
#endif

#include "ipcp.h"
#include "np1.h"
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
#define DIX_HCS_SIZE         CRC8_HASH_LEN
#define DIX_HEADER_SIZE      (DIX_EID_SIZE + DIX_LENGTH_SIZE + DIX_HCS_SIZE)
#define ETH_HEADER_TOT_SIZE  (ETH_HEADER_SIZE + DIX_HEADER_SIZE)
#define MAX_EIDS             (1 << (8 * DIX_EID_SIZE))
#define ETH_MAX_PACKET_SIZE  (ETH_MTU - DIX_HEADER_SIZE)
#define ETH_FRAME_SIZE       (ETH_HEADER_SIZE + ETH_MTU_MAX)
#elif defined(BUILD_ETH_LLC)
#define THIS_TYPE            IPCP_ETH_LLC
#define MGMT_SAP             0x01
#define LLC_FIELDS_SIZE      3
#define LLC_HCS_SIZE         CRC8_HASH_LEN
#define LLC_HEADER_SIZE      (LLC_FIELDS_SIZE + LLC_HCS_SIZE)
#define ETH_HEADER_TOT_SIZE  (ETH_HEADER_SIZE + LLC_HEADER_SIZE)
#define MAX_SAPS             64
#define ETH_MAX_PACKET_SIZE  (ETH_MTU - LLC_HEADER_SIZE)
#define ETH_FRAME_SIZE       (ETH_HEADER_SIZE + ETH_MTU_MAX)
#endif

#define NAME_QUERY_TIMEO     1900  /* ms total budget               */
#define NAME_QUERY_RETRIES   3     /* retransmits, 4 attempts total */
#define MGMT_TIMEO           100   /* ms                            */
#define MGMT_FRAME_SIZE      IPCP_ETH_MGMT_FRAME_SIZE
#define ETH_RIB_PATH         "eth"

#define FLOW_REQ             0
#define FLOW_REPLY           1
#define NAME_QUERY_REQ       2
#define NAME_QUERY_REPLY     3
#define FLOW_IRM_UPDATE      4

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
        uint8_t  service;
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
        uint8_t  hcs;
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
#ifdef IPCP_ETH_FLOW_STATS
        struct {
                time_t stamp;
                size_t p_rcv;
                size_t b_rcv;
                size_t p_dlv_f;
                size_t p_snd;
                size_t b_snd;
                size_t p_snd_f;
        } stat;
#endif
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
#ifdef IPCP_ETH_FLOW_STATS
        struct {
                size_t n_flows;
                size_t n_rcv;
                size_t n_snd;
                size_t n_mgmt_rcv;
                size_t n_mgmt_snd;
                size_t n_bad_id;
                size_t n_dlv_f;
                size_t n_buf_f;
                size_t n_rcv_f;
                size_t n_snd_f;
                size_t kern_rcv;
                size_t kern_drp;
        } stat;
#endif

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
#ifdef IPCP_ETH_FLOW_STATS
                memset(&eth_data.fd_to_ef[i].stat, 0,
                       sizeof(eth_data.fd_to_ef[i].stat));
#endif
        }
#ifdef IPCP_ETH_FLOW_STATS
        memset(&eth_data.stat, 0, sizeof(eth_data.stat));
#endif

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

#ifdef IPCP_ETH_FLOW_STATS
static int eth_rib_read(const char * path,
                        char *       buf,
                        size_t       len)
{
        struct ef * flow;
        int         fd;
        char        tmstr[RIB_TM_STRLEN];
        struct tm * tm;
        time_t      stamp;
        char *      entry;

        entry = strstr(path, RIB_SEPARATOR) + 1;
        assert(entry);

        if (len < 2048)
                return 0;

        buf[0] = '\0';

        if (strcmp(entry, "summary") == 0) {
                int n;
#if defined(HAVE_RAW_SOCKETS)
                int       rcvbuf = 0;
                int       sndbuf = 0;
                int       queued = 0;
                socklen_t optlen = sizeof(rcvbuf);
#  if defined(__linux__)
                struct tpacket_stats tp_stats;
                socklen_t            tp_len = sizeof(tp_stats);
#  endif

                getsockopt(eth_data.s_fd, SOL_SOCKET,
                           SO_RCVBUF, &rcvbuf, &optlen);
                optlen = sizeof(sndbuf);
                getsockopt(eth_data.s_fd, SOL_SOCKET,
                           SO_SNDBUF, &sndbuf, &optlen);
                ioctl(eth_data.s_fd, FIONREAD, &queued);
#  if defined(__linux__)
                if (getsockopt(eth_data.s_fd, SOL_PACKET,
                               PACKET_STATISTICS,
                               &tp_stats, &tp_len) == 0) {
                        FETCH_ADD_RELAXED(&eth_data.stat.kern_rcv,
                                          tp_stats.tp_packets);
                        FETCH_ADD_RELAXED(&eth_data.stat.kern_drp,
                                          tp_stats.tp_drops);
                }
#  endif
#endif
                n = sprintf(buf,
                        "Active flows:                    %20zu\n"
                        "Total frames received:           %20zu\n"
                        "Total frames sent:               %20zu\n"
                        "Management frames received:      %20zu\n"
                        "Management frames sent:          %20zu\n"
                        "Bad EID/SAP frames:              %20zu\n"
                        "Delivery (N+1) failures:         %20zu\n"
                        "Buffer alloc failures:           %20zu\n"
                        "Frame read failures:             %20zu\n"
                        "Frame send failures:             %20zu\n",
                        LOAD_RELAXED(&eth_data.stat.n_flows),
                        LOAD_RELAXED(&eth_data.stat.n_rcv),
                        LOAD_RELAXED(&eth_data.stat.n_snd),
                        LOAD_RELAXED(&eth_data.stat.n_mgmt_rcv),
                        LOAD_RELAXED(&eth_data.stat.n_mgmt_snd),
                        LOAD_RELAXED(&eth_data.stat.n_bad_id),
                        LOAD_RELAXED(&eth_data.stat.n_dlv_f),
                        LOAD_RELAXED(&eth_data.stat.n_buf_f),
                        LOAD_RELAXED(&eth_data.stat.n_rcv_f),
                        LOAD_RELAXED(&eth_data.stat.n_snd_f));
#if defined(HAVE_RAW_SOCKETS)
                n += sprintf(buf + n,
                        "Socket rcvbuf (bytes):           %20d\n"
                        "Socket sndbuf (bytes):           %20d\n"
                        "Socket queued (bytes):           %20d\n",
                        rcvbuf, sndbuf, queued);
#  if defined(__linux__)
                n += sprintf(buf + n,
                        "Kernel frames received:          %20zu\n"
                        "Kernel frames dropped:           %20zu\n",
                        LOAD_RELAXED(&eth_data.stat.kern_rcv),
                        LOAD_RELAXED(&eth_data.stat.kern_drp));
#  endif
#endif
                return n;
        }

        fd = atoi(entry);

        if (fd < 0 || fd >= SYS_MAX_FLOWS)
                return -1;

        flow = &eth_data.fd_to_ef[fd];

        pthread_rwlock_rdlock(&eth_data.flows_lock);

        stamp = flow->stat.stamp;
        if (stamp == 0) {
                pthread_rwlock_unlock(&eth_data.flows_lock);
                return 0;
        }

        pthread_rwlock_unlock(&eth_data.flows_lock);

        tm = gmtime(&stamp);
        strftime(tmstr, sizeof(tmstr), RIB_TM_FORMAT, tm);

        sprintf(buf,
                "Flow established at:             %20s\n"
                "Sent (packets):                  %20zu\n"
                "Sent (bytes):                    %20zu\n"
                "Send failed (packets):           %20zu\n"
                "Received (packets):              %20zu\n"
                "Received (bytes):                %20zu\n"
                "Delivery (N+1) failures:         %20zu\n",
                tmstr,
                LOAD_RELAXED(&flow->stat.p_snd),
                LOAD_RELAXED(&flow->stat.b_snd),
                LOAD_RELAXED(&flow->stat.p_snd_f),
                LOAD_RELAXED(&flow->stat.p_rcv),
                LOAD_RELAXED(&flow->stat.b_rcv),
                LOAD_RELAXED(&flow->stat.p_dlv_f));

        return strlen(buf);
}

static int eth_rib_readdir(char *** buf)
{
        char   entry[RIB_PATH_LEN + 1];
        size_t i;
        int    idx = 0;
        int    n_entries;

        pthread_rwlock_rdlock(&eth_data.flows_lock);

        n_entries = (int) LOAD_RELAXED(&eth_data.stat.n_flows) + 1;

        *buf = malloc(sizeof(**buf) * n_entries);
        if (*buf == NULL)
                goto fail_entries;

        (*buf)[idx] = malloc(strlen("summary") + 1);
        if ((*buf)[idx] == NULL)
                goto fail_entry;

        strcpy((*buf)[idx++], "summary");

        for (i = 0; i < SYS_MAX_FLOWS && idx < n_entries; ++i) {
                if (eth_data.fd_to_ef[i].stat.stamp == 0)
                        continue;

                sprintf(entry, "%zu", i);

                (*buf)[idx] = malloc(strlen(entry) + 1);
                if ((*buf)[idx] == NULL)
                        goto fail_entry;

                strcpy((*buf)[idx++], entry);
        }

        pthread_rwlock_unlock(&eth_data.flows_lock);

        return idx;

 fail_entry:
        while (idx-- > 0)
                free((*buf)[idx]);
        free(*buf);
 fail_entries:
        pthread_rwlock_unlock(&eth_data.flows_lock);
        return -ENOMEM;
}

static int eth_rib_getattr(const char *      path,
                           struct rib_attr * attr)
{
        int         fd;
        char *      entry;
        struct ef * flow;

        entry = strstr(path, RIB_SEPARATOR) + 1;
        assert(entry);

        if (strcmp(entry, "summary") == 0) {
                attr->size  = 2048;
                attr->mtime = 0;
                return 0;
        }

        fd = atoi(entry);

        if (fd < 0 || fd >= SYS_MAX_FLOWS) {
                attr->size  = 0;
                attr->mtime = 0;
                return 0;
        }

        flow = &eth_data.fd_to_ef[fd];

        pthread_rwlock_rdlock(&eth_data.flows_lock);

        if (flow->stat.stamp != 0) {
                attr->size  = 2048;
                attr->mtime = flow->stat.stamp;
        } else {
                attr->size  = 0;
                attr->mtime = 0;
        }

        pthread_rwlock_unlock(&eth_data.flows_lock);

        return 0;
}

static struct rib_ops eth_r_ops = {
        .read    = eth_rib_read,
        .readdir = eth_rib_readdir,
        .getattr = eth_rib_getattr
};
#endif /* IPCP_ETH_FLOW_STATS */

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
        mem_hash(HASH_CRC8, &e_frame->hcs,
                 (uint8_t *) &e_frame->eid,
                 DIX_EID_SIZE + DIX_LENGTH_SIZE);
        frame_len = ETH_HEADER_TOT_SIZE + len;
#elif defined(BUILD_ETH_LLC)
        e_frame->length = htons(LLC_HEADER_SIZE + len);
        e_frame->dsap = dsap;
        e_frame->ssap = ssap;
        e_frame->cf   = cf;
        mem_hash(HASH_CRC8, &e_frame->hcs,
                 (uint8_t *) &e_frame->dsap,
                 LLC_FIELDS_SIZE);
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

        if (sendto(eth_data.s_fd, frame, frame_len, 0,
                   (struct sockaddr *) &eth_data.device,
                   sizeof(eth_data.device)) <= 0) {
                log_dbg("Failed to send message: %s.", strerror(errno));
                return -1;
        }
#endif /* HAVE_NETMAP */

        FETCH_ADD_RELAXED(&eth_data.stat.n_snd, 1);

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

        memset(buf, 0, len + ETH_HEADER_TOT_SIZE + data->len);

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
        msg->service      = qs.service;
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

        if (ret == 0)
                FETCH_ADD_RELAXED(&eth_data.stat.n_mgmt_snd, 1);

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

        memset(buf, 0, sizeof(*msg) + ETH_HEADER_TOT_SIZE + data->len);

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

        FETCH_ADD_RELAXED(&eth_data.stat.n_mgmt_snd, 1);

        free(buf);

        return 0;
}

static int eth_ipcp_flow_update(int              fd,
                                const buffer_t * data)
{
        struct mgmt_msg * msg;
        struct ef *       flow;
        uint8_t *         buf;
        uint8_t           r_addr[MAC_SIZE];
        int               ret;

        buf = malloc(sizeof(*msg) + ETH_HEADER_TOT_SIZE + data->len);
        if (buf == NULL)
                return -1;

        memset(buf, 0, sizeof(*msg) + ETH_HEADER_TOT_SIZE + data->len);

        msg = (struct mgmt_msg *) (buf + ETH_HEADER_TOT_SIZE);

        msg->code = FLOW_IRM_UPDATE;

        pthread_rwlock_rdlock(&eth_data.flows_lock);

        flow = &eth_data.fd_to_ef[fd];
#if defined(BUILD_ETH_DIX)
        msg->seid = htons((uint16_t) fd);
        msg->deid = htons((uint16_t) flow->r_eid);
#elif defined(BUILD_ETH_LLC)
        msg->ssap = flow->sap;
        msg->dsap = (uint8_t) flow->r_sap;
#endif
        memcpy(r_addr, flow->r_addr, MAC_SIZE);

        pthread_rwlock_unlock(&eth_data.flows_lock);

        if (data->len > 0)
                memcpy(msg + 1, data->data, data->len);

        ret = eth_ipcp_send_frame(r_addr,
#if defined(BUILD_ETH_DIX)
                                  MGMT_EID,
#elif defined(BUILD_ETH_LLC)
                                  reverse_bits(MGMT_SAP),
                                  reverse_bits(MGMT_SAP),
#endif
                                  buf, sizeof(*msg) + data->len);
        free(buf);

        if (ret == 0)
                FETCH_ADD_RELAXED(&eth_data.stat.n_mgmt_snd, 1);

        return ret;
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

        fd = ipcp_wait_flow_req_arr(dst, qs, IPCP_ETH_MPL,
                                    ETH_MAX_PACKET_SIZE, data);
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
                pthread_rwlock_unlock(&eth_data.flows_lock);
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
        if ((ret = ipcp_flow_alloc_reply(fd, response, mpl,
                                         ETH_MAX_PACKET_SIZE, data)) < 0) {
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

                memset(buf, 0, len + ETH_HEADER_TOT_SIZE);

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

                FETCH_ADD_RELAXED(&eth_data.stat.n_mgmt_snd, 1);

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

static int eth_ipcp_flow_update_arr(const uint8_t * buf,
                                    size_t          len)
{
        struct mgmt_msg * msg;
        buffer_t          data;
        int               fd;
        int               flow_id;

        msg = (struct mgmt_msg *) buf;

        data.data = (uint8_t *) buf + sizeof(*msg);
        data.len  = len - sizeof(*msg);

        pthread_rwlock_rdlock(&eth_data.flows_lock);
#if defined(BUILD_ETH_DIX)
        fd = ntohs(msg->deid);
#elif defined(BUILD_ETH_LLC)
        fd = eth_data.ef_to_fd[msg->dsap];
#endif
        pthread_rwlock_unlock(&eth_data.flows_lock);

        if (fd < 0 || fd >= SYS_MAX_FLOWS) {
                log_err("Flow update for unknown endpoint.");
                return -1;
        }

        flow_id = np1_flow_id(fd);
        if (flow_id < 0)
                return -1;

        if (ipcp_flow_update_arr(flow_id, &data) < 0) {
                log_err("Failed to relay flow update on fd %d.", fd);
                return -1;
        }

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

        if (len < sizeof(*msg))
                return -1;

        msg = (struct mgmt_msg *) buf;

        switch (msg->code) {
        case FLOW_REQ:
                msg_len = sizeof(*msg) + ipcp_dir_hash_len();

                if (len < msg_len)
                        return -1;

                qs.delay = ntoh32(msg->delay);
                qs.bandwidth = ntoh64(msg->bandwidth);
                qs.availability = msg->availability;
                qs.loss = ntoh32(msg->loss);
                qs.ber = ntoh32(msg->ber);
                qs.service = msg->service;
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
        case FLOW_IRM_UPDATE:
                eth_ipcp_flow_update_arr(buf, len);
                break;
        case NAME_QUERY_REQ:
                if (len < sizeof(*msg) + ipcp_dir_hash_len())
                        return -1;
                eth_ipcp_name_query_req(buf + sizeof(*msg), r_addr);
                break;
        case NAME_QUERY_REPLY:
                if (len < sizeof(*msg) + ipcp_dir_hash_len())
                        return -1;
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
        struct ssm_pk_buff * spb;
        fd_set               fds;
        int                  frame_len;
#endif
#if defined(HAVE_RAW_SOCKETS)
        struct sockaddr_ll   src;
        socklen_t            slen;
#endif
        size_t               eth_len;
        uint8_t              hcs;
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
                if (ipcp_spb_reserve(&spb, BPF_LEN))
                        continue;
                buf = ssm_pk_buff_head(spb);
                frame_len = read(eth_data.bpf, buf, BPF_BLEN);
    #elif defined(HAVE_RAW_SOCKETS)
                FD_SET(eth_data.s_fd, &fds);
                if (select(eth_data.s_fd + 1, &fds, NULL, NULL, NULL) < 0)
                        continue;
                assert(FD_ISSET(eth_data.s_fd, &fds));
                if (ipcp_spb_reserve(&spb, ETH_MTU)) {
                        FETCH_ADD_RELAXED(&eth_data.stat.n_buf_f, 1);
                        continue;
                }
                buf = ssm_pk_buff_push(spb, ETH_HEADER_TOT_SIZE);
                if (buf == NULL) {
                        log_dbg("Failed to allocate header.");
                        ipcp_spb_release(spb);
                        FETCH_ADD_RELAXED(&eth_data.stat.n_buf_f, 1);
                        continue;
                }
                slen = sizeof(src);
                /* MSG_DONTWAIT: RD_THR>1 race-loser bails with EAGAIN. */
                frame_len = recvfrom(eth_data.s_fd, buf,
                                     ETH_MTU + ETH_HEADER_TOT_SIZE,
                                     MSG_DONTWAIT,
                                     (struct sockaddr *) &src, &slen);
    #endif
                if (frame_len == 0) {
                        ipcp_spb_release(spb);
                        continue; /* Spurious */
                }

                if (frame_len < 0) {
                        ipcp_spb_release(spb);

                        if (errno == EAGAIN || errno == EWOULDBLOCK)
                                continue;

                        log_dbg("Failed to rcv frame: %s.", strerror(errno));
                        FETCH_ADD_RELAXED(&eth_data.stat.n_rcv_f, 1);
                        continue;
                }
#endif

#if defined(HAVE_NETMAP)
                eth_len = hdr.len;
#elif defined(HAVE_BPF)
                eth_len = ((struct bpf_hdr *) buf)->bh_caplen;
#else
                eth_len = (size_t) frame_len;
#endif
                /* Defense in depth: reject before parsing dereferences. */
                if (eth_len < ETH_HEADER_TOT_SIZE)
                        goto fail_frame;

#if defined(HAVE_RAW_SOCKETS)
                /* Drop our own egress. */
                if (src.sll_pkttype == PACKET_OUTGOING)
                        goto fail_frame;
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
                        FETCH_ADD_RELAXED(&eth_data.stat.n_bad_id, 1);
                        goto fail_frame;
                }
#endif
                length = ntohs(e_frame->length);
#if defined(BUILD_ETH_DIX)
                if (e_frame->ethertype != eth_data.ethertype)
                        goto fail_frame;

                if (length > ETH_MTU)
                        goto fail_frame;

                deid = ntohs(e_frame->eid);
#elif defined (BUILD_ETH_LLC)
                if (length > 0x05FF) /* DIX */
                        goto fail_frame;

                if (length < LLC_HEADER_SIZE || length > ETH_MTU)
                        goto fail_frame;

                length -= LLC_HEADER_SIZE;

                dsap = reverse_bits(e_frame->dsap);
                ssap = reverse_bits(e_frame->ssap);
#endif

                if (eth_len < ETH_HEADER_TOT_SIZE + (size_t) length)
                        goto fail_frame;

#if defined(BUILD_ETH_DIX)
                mem_hash(HASH_CRC8, &hcs,
                         (uint8_t *) &e_frame->eid,
                         DIX_EID_SIZE + DIX_LENGTH_SIZE);
#elif defined(BUILD_ETH_LLC)
                mem_hash(HASH_CRC8, &hcs,
                         (uint8_t *) &e_frame->dsap,
                         LLC_FIELDS_SIZE);
#endif
                if (hcs != e_frame->hcs)
                        goto fail_frame;

#if defined(BUILD_ETH_DIX)
                if (deid == MGMT_EID) {
#elif defined (BUILD_ETH_LLC)
                if (ssap == MGMT_SAP && dsap == MGMT_SAP) {
#endif
                        ipcp_spb_release(spb); /* No need for the N+1 buffer. */

                        if (length > MGMT_FRAME_SIZE) {
                                log_warn("Management frame size %u exceeds %u.",
                                         length, MGMT_FRAME_SIZE);
                                continue;
                        }

                        frame = malloc(sizeof(*frame));
                        if (frame == NULL) {
                                log_err("Failed to allocate frame.");
                                continue;
                        }

                        memcpy(frame->buf, &e_frame->payload, length);
                        memcpy(frame->r_addr, e_frame->src_hwaddr, MAC_SIZE);
                        frame->len = length;

                        pthread_mutex_lock(&eth_data.mgmt_lock);
                        list_add(&frame->next, &eth_data.mgmt_frames);
                        pthread_cond_signal(&eth_data.mgmt_cond);
                        pthread_mutex_unlock(&eth_data.mgmt_lock);
                        FETCH_ADD_RELAXED(&eth_data.stat.n_rcv, 1);
                        FETCH_ADD_RELAXED(&eth_data.stat.n_mgmt_rcv, 1);
                } else {
                        pthread_rwlock_rdlock(&eth_data.flows_lock);

#if defined(BUILD_ETH_DIX)
                        fd = deid;
#elif defined(BUILD_ETH_LLC)
                        fd = eth_data.ef_to_fd[dsap];
#endif
                        if (fd < 0) {
                                pthread_rwlock_unlock(&eth_data.flows_lock);
                                FETCH_ADD_RELAXED(&eth_data.stat.n_bad_id, 1);
                                goto fail_frame;
                        }

#ifdef BUILD_ETH_LLC
                        if (eth_data.fd_to_ef[fd].r_sap != ssap
                            || memcmp(eth_data.fd_to_ef[fd].r_addr,
                                      e_frame->src_hwaddr, MAC_SIZE)) {
                                pthread_rwlock_unlock(&eth_data.flows_lock);
                                FETCH_ADD_RELAXED(&eth_data.stat.n_bad_id, 1);
                                goto fail_frame;
                        }
#endif
                        FETCH_ADD_RELAXED(&eth_data.fd_to_ef[fd].stat.p_rcv, 1);
                        FETCH_ADD_RELAXED(&eth_data.fd_to_ef[fd].stat.b_rcv,
                                          length);
                        FETCH_ADD_RELAXED(&eth_data.stat.n_rcv, 1);
                        pthread_rwlock_unlock(&eth_data.flows_lock);

#ifndef HAVE_NETMAP
                        ssm_pk_buff_pop(spb, ETH_HEADER_TOT_SIZE);
                        ssm_pk_buff_truncate(spb, length);
#else
                        if (ipcp_spb_reserve(&spb, length))
                                continue;

                        buf = ssm_pk_buff_head(spb);
                        memcpy(buf, &e_frame->payload, length);
#endif
                        if (np1_flow_write(fd, spb, NP1_GET_POOL(fd)) < 0) {
                                ipcp_spb_release(spb);
                                FETCH_ADD_RELAXED(
                                        &eth_data.fd_to_ef[fd].stat.p_dlv_f,
                                        1);
                                FETCH_ADD_RELAXED(&eth_data.stat.n_dlv_f, 1);
                        }

                        continue;
 fail_frame:
#ifndef HAVE_NETMAP
                        ipcp_spb_release(spb);
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
        struct ssm_pk_buff * spb;
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

                        if (np1_flow_read(fd, &spb, NP1_GET_POOL(fd))) {
                                log_dbg("Bad read from fd %d.", fd);
                                continue;
                        }

                        len = ssm_pk_buff_len(spb);

                        if (ssm_pk_buff_push(spb, ETH_HEADER_TOT_SIZE)
                            == NULL) {
                                log_dbg("Failed to allocate header.");
                                ipcp_spb_release(spb);
                                FETCH_ADD_RELAXED(&eth_data.stat.n_buf_f, 1);
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
                                            ssm_pk_buff_head(spb),
                                            len)) {
                                log_dbg("Failed to send frame.");
                                FETCH_ADD_RELAXED(
                                        &eth_data.fd_to_ef[fd].stat.p_snd_f,
                                        1);
                                FETCH_ADD_RELAXED(&eth_data.stat.n_snd_f, 1);
                        } else {
                                FETCH_ADD_RELAXED(
                                        &eth_data.fd_to_ef[fd].stat.p_snd,
                                        1);
                                FETCH_ADD_RELAXED(
                                        &eth_data.fd_to_ef[fd].stat.b_snd,
                                        len);
                        }
                        ipcp_spb_release(spb);
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
#define SOCKOPT()
static int eth_init_raw_socket(struct ifreq * ifr)
{
        int idx;
        int sndbuf;
        int rcvbuf;
#if defined(IPCP_ETH_QDISC_BYPASS)
        int qdisc_bypass = 1;
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

#if defined(IPCP_ETH_QDISC_BYPASS)
        if (setsockopt(eth_data.s_fd, SOL_PACKET, PACKET_QDISC_BYPASS,
                       &qdisc_bypass, sizeof(qdisc_bypass))) {
                log_info("Qdisc bypass not supported.");
        }
#endif

        sndbuf = IPCP_ETH_SNDBUF;
        if (sndbuf > 0 && setsockopt(eth_data.s_fd, SOL_SOCKET, SO_SNDBUF,
                                     &sndbuf, sizeof(sndbuf))) {
                log_info("Failed to set SO_SNDBUF to %d.", sndbuf);
        }

        rcvbuf = IPCP_ETH_RCVBUF;
        if (rcvbuf > 0 && setsockopt(eth_data.s_fd, SOL_SOCKET, SO_RCVBUF,
                                     &rcvbuf, sizeof(rcvbuf))) {
                log_info("Failed to set SO_RCVBUF to %d.", rcvbuf);
        }

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
#ifdef IPCP_ETH_FLOW_STATS
        if (rib_reg(ETH_RIB_PATH, &eth_r_ops)) {
                log_err("Failed to register RIB.");
                goto fail_rib_reg;
        }
#endif
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
#ifdef IPCP_ETH_FLOW_STATS
        rib_unreg(ETH_RIB_PATH);
 fail_rib_reg:
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
        struct timespec    timeout;
        struct dir_query * query;
        int                ret;
        int                attempt;
        uint8_t *          buf;
        struct mgmt_msg *  msg;
        size_t             len;
        long               per_ms;

        if (shim_data_dir_has(eth_data.shim_data, hash))
                return 0;

        len = sizeof(*msg) + ipcp_dir_hash_len();

        buf = malloc(len + ETH_HEADER_TOT_SIZE);
        if (buf == NULL)
                return -1;

        memset(buf, 0, len + ETH_HEADER_TOT_SIZE);

        msg       = (struct mgmt_msg *) (buf + ETH_HEADER_TOT_SIZE);
        msg->code = NAME_QUERY_REQ;

        memcpy(msg + 1, hash, ipcp_dir_hash_len());

        memset(r_addr, 0xff, MAC_SIZE);

        per_ms = NAME_QUERY_TIMEO / (NAME_QUERY_RETRIES + 1);

        ret = -1;
        for (attempt = 0; attempt <= NAME_QUERY_RETRIES; ++attempt) {
                query = shim_data_dir_query_create(eth_data.shim_data, hash);
                if (query == NULL) {
                        ret = -1;
                        break;
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
                        shim_data_dir_query_destroy(eth_data.shim_data,
                                                    query);
                        ret = -1;
                        break;
                }

                FETCH_ADD_RELAXED(&eth_data.stat.n_mgmt_snd, 1);

                timeout.tv_sec  = per_ms / 1000;
                timeout.tv_nsec = (per_ms % 1000) * 1000000L;

                ret = shim_data_dir_query_wait(query, &timeout);

                shim_data_dir_query_destroy(eth_data.shim_data, query);

                if (ret != -ETIMEDOUT)
                        break;
        }

        free(buf);

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
#ifdef IPCP_ETH_FLOW_STATS
        pthread_rwlock_wrlock(&eth_data.flows_lock);
        memset(&eth_data.fd_to_ef[fd].stat, 0,
               sizeof(eth_data.fd_to_ef[fd].stat));
        eth_data.fd_to_ef[fd].stat.stamp = time(NULL);
        FETCH_ADD_RELAXED(&eth_data.stat.n_flows, 1);
        pthread_rwlock_unlock(&eth_data.flows_lock);
#endif
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
#ifdef IPCP_ETH_FLOW_STATS
        pthread_rwlock_wrlock(&eth_data.flows_lock);
        memset(&eth_data.fd_to_ef[fd].stat, 0,
               sizeof(eth_data.fd_to_ef[fd].stat));
        eth_data.fd_to_ef[fd].stat.stamp = time(NULL);
        FETCH_ADD_RELAXED(&eth_data.stat.n_flows, 1);
        pthread_rwlock_unlock(&eth_data.flows_lock);
#endif
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

#ifdef IPCP_ETH_FLOW_STATS
        memset(&eth_data.fd_to_ef[fd].stat, 0,
               sizeof(eth_data.fd_to_ef[fd].stat));
        FETCH_SUB_RELAXED(&eth_data.stat.n_flows, 1);
#endif

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
        .ipcp_flow_dealloc    = eth_ipcp_flow_dealloc,
        .ipcp_flow_update     = eth_ipcp_flow_update
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
#ifdef IPCP_ETH_FLOW_STATS
                rib_unreg(ETH_RIB_PATH);
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
