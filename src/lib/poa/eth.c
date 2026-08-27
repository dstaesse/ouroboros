/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Points of attachment (PoA) - Ethernet transport
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

#if defined(__APPLE__)
#define _BSD_SOURCE
#define _DARWIN_C_SOURCE
#elif defined(__FreeBSD__)
#define __BSD_VISIBLE 1
#elif defined(__linux__) || defined(__CYGWIN__)
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#else
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#endif

#include "config.h"

#define OUROBOROS_PREFIX "poa-eth"

#include <ouroboros/endian.h>
#include <ouroboros/errno.h>
#include <ouroboros/hash.h>
#include <ouroboros/logs.h>
#include <ouroboros/pthread.h>
#include <ouroboros/random.h>
#include <ouroboros/sockets.h>
#include <ouroboros/time.h>

#include "poa.h"

#ifdef HAVE_RAW_SOCKETS
#include <net/if.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/netlink.h>
#include <linux/gen_stats.h>
#include <linux/pkt_sched.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <ifaddrs.h>
#elif defined(HAVE_BPF)
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <ifaddrs.h>
#elif defined(HAVE_NETMAP)
#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <poll.h>
#ifndef __linux__
#include <net/if_dl.h>
#include <ifaddrs.h>
#endif
#endif

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ETH_TYPE_LEN_SIZE sizeof(uint16_t)
#define ETH_HDR_SIZE      (2 * POA_MAC_SIZE + ETH_TYPE_LEN_SIZE)
#define POA_HDR_SIZE      (sizeof(struct poa_hdr))
#define ETH_HDR_TOT_SIZE  (ETH_HDR_SIZE + POA_HDR_SIZE)

#define BPF_DEV_MAX       256  /* /dev/bpfN units to try */
/* Wait for the link to come back before reading it again. */
#define ETH_DOWN_TIMEO    100  /* ms */
/* Budget for a qdisc dump; the send path must not wait on netlink. */
#define POA_QDISC_TIMEO   5    /* ms */

#ifndef ETH_MAX_MTU        /* In if_ether.h as of Linux 4.10. */
#define ETH_MAX_MTU       0xFFFFU
#endif

struct poa_hdr {
        uint16_t eid;
        uint16_t len;
        uint8_t  hcs;
} __attribute__((packed));

struct eth_hdr {
        uint8_t        dst[POA_MAC_SIZE];
        uint8_t        src[POA_MAC_SIZE];
        uint16_t       ethertype;
        struct poa_hdr poa;
} __attribute__((packed));


struct eth_priv {
        struct poa *       poa;

        int                s_fd;      /* raw socket or bpf device */
        uint16_t           ethertype; /* network order            */
        uint8_t            hw_addr[POA_MAC_SIZE];
        uint32_t           mtu;       /* device payload capacity */
        int                ifindex;   /* link id; 0 where unknown */

        pthread_t          reader;
        bool               running;
#ifdef HAVE_RAW_SOCKETS
        struct sockaddr_ll device;
#elif defined(HAVE_BPF)
        size_t             blen;      /* bpf device buffer size */
#elif defined(HAVE_NETMAP)
        struct nm_desc *   nmd;
        struct pollfd      poll_in;
        struct pollfd      poll_out;
#endif
        /* The kernel zeroes its counters on read, so accumulate. */
        size_t             kern_rcv;
        size_t             kern_drp;
#ifdef HAVE_RAW_SOCKETS
        /* Qdisc depth: netlink descriptor, its try-lock and cache. */
        int                nl_fd;
        uint8_t            nl_busy;
        size_t             nl_pkt;
        size_t             nl_byt;
        uint64_t           nl_time;
#endif
};

struct eth_query {
        struct list_head next;
        uint8_t          hash[POA_QUERY_HLEN];
        /* The resolve's constraints; replies must satisfy them. */
        uint16_t         ethertype;
        char             c_dev[DEV_NAME_SIZE + 1];
        uint8_t          c_mac[POA_MAC_SIZE];
        bool             replied;
        char             dev[DEV_NAME_SIZE + 1];
        uint8_t          src_mac[POA_MAC_SIZE];
        uint8_t          mac[POA_MAC_SIZE];
        uint16_t         r_ethertype;
};

static struct {
        pthread_once_t  once;

        struct llist    pending;
        pthread_mutex_t mtx;
        pthread_cond_t  cond;
} queries = { .once = PTHREAD_ONCE_INIT };

static void eth_hdr_ser(const struct eth_priv * priv,
                        struct eth_hdr *        hdr,
                        const uint8_t *         dst,
                        uint32_t                eid,
                        size_t                  len)
{
        memcpy(hdr->dst, dst, POA_MAC_SIZE);
        memcpy(hdr->src, priv->hw_addr, POA_MAC_SIZE);

        hdr->ethertype = priv->ethertype;
        hdr->poa.eid   = htons((uint16_t) eid);
        hdr->poa.len   = htons((uint16_t) len);
        mem_hash(HASH_CRC8, &hdr->poa.hcs,
                 (uint8_t *) &hdr->poa.eid, 2 * sizeof(uint16_t));
}

/* Oriented from us to the sender: our PoA, then their MAC. */
static void frame_to_addr(const struct eth_priv * priv,
                          const struct eth_hdr *  hdr,
                          struct poa_addr *       addr)
{
        memset(addr, 0, sizeof(*addr));

        addr->type = priv->poa->type;

        addr->eth.src = priv->poa->local.eth.src;

        memcpy(addr->eth.dst.mac, hdr->src, POA_MAC_SIZE);

        addr->eth.dst.ethertype = ntohs(priv->ethertype);
}

static bool frame_is_for_us(const struct eth_priv * priv,
                            const uint8_t *         dst)
{
        static const uint8_t bc[POA_MAC_SIZE] =
                { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

        if (memcmp(dst, priv->hw_addr, POA_MAC_SIZE) == 0)
                return true;

        return memcmp(dst, bc, POA_MAC_SIZE) == 0;
}

/*
 * Parse and validate a frame; on success *eid and *plen locate the
 * payload. Errors are silent: anyone can spray an interface.
 */
static int frame_parse(const struct eth_priv * priv,
                       const uint8_t *         buf,
                       size_t                  len,
                       uint32_t *              eid,
                       size_t *                plen)
{
        const struct eth_hdr * hdr = (const struct eth_hdr *) buf;
        uint8_t                hcs;

        if (len < ETH_HDR_TOT_SIZE)
                return -1;

        if (!frame_is_for_us(priv, hdr->dst))
                return -1;

        if (hdr->ethertype != priv->ethertype)
                return -1;

        mem_hash(HASH_CRC8, &hcs,
                 (const uint8_t *) &hdr->poa.eid, 2 * sizeof(uint16_t));

        if (hcs != hdr->poa.hcs)
                return -1;

        *eid  = ntohs(hdr->poa.eid);

        *plen = ntohs(hdr->poa.len);
        if (*plen > len - ETH_HDR_TOT_SIZE)
                return -1;

        return 0;
}

#define ETH_QUERY_TIMEO   1900 /* ms total budget               */
#define ETH_QUERY_RETRIES 3    /* retransmits, 4 attempts total */

/* A resolve in progress; a reply fills every matching entry. */
static void queries_init(void)
{
        pthread_condattr_t cattr;

        llist_init(&queries.pending);

        pthread_mutex_init(&queries.mtx, NULL);

        pthread_condattr_init(&cattr);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        pthread_cond_init(&queries.cond, &cattr);
        pthread_condattr_destroy(&cattr);
}

static void eth_query_cleanup(void * o)
{
        struct eth_query * q = (struct eth_query *) o;

        pthread_mutex_lock(&queries.mtx);
        llist_del(&q->next, &queries.pending);
        pthread_mutex_unlock(&queries.mtx);
}

static void eth_query_arr(struct poa *            poa,
                          const struct poa_addr * src,
                          const uint8_t *         hash)
{
        uint8_t               buf[sizeof(struct poa_mgmt_msg)
                                   + POA_QUERY_HLEN];
        struct poa_mgmt_msg * msg = (struct poa_mgmt_msg *) buf;

        if (!poa_has_name(hash))
                return;

        poa_mgmt_msg_ser(msg, POA_NAME_REPLY, 0, 0, qos_raw, 0, POA_QUERY_HLEN);

        memcpy(buf + sizeof(*msg), hash, POA_QUERY_HLEN);

        if (poa->ops->poa_send_mgmt(poa, src, buf, sizeof(buf)) < 0)
                return; /* the requester retransmits */

        POA_STAT_BUMP(poa, rep_tx);
}

static bool mac_is_zero(const uint8_t * mac)
{
        static const uint8_t zero[POA_MAC_SIZE] = { 0 };

        return memcmp(mac, zero, POA_MAC_SIZE) == 0;
}

/* Assign a random MAC on loopback interfaces (zero MAC). */
static int eth_dev_mac(uint8_t * mac)
{
        if (!mac_is_zero(mac))
                return 0;

        if (random_buffer(mac, POA_MAC_SIZE) < 0)
                return -1;

        mac[0] = (mac[0] | 0x02) & 0xFE;

        return 0;
}

static bool eth_query_is_match(const struct eth_query * q,
                               const struct poa *       poa)
{
        if (q->ethertype != 0 &&
            q->ethertype != poa->local.eth.src.ethertype)
                return false;

        if (q->c_dev[0] != '\0' &&
            strcmp(q->c_dev, poa->local.eth.src.dev) != 0)
                return false;

        if (mac_is_zero(q->c_mac))
                return true;

        return memcmp(q->c_mac, poa->local.eth.src.mac, POA_MAC_SIZE) == 0;
}

static void eth_reply_arr(struct poa *            poa,
                          const struct poa_addr * src,
                          const uint8_t *         hash)
{
        struct list_head * p;

        pthread_once(&queries.once, queries_init);

        pthread_mutex_lock(&queries.mtx);

        list_for_each(p, &queries.pending.list) {
                struct eth_query * q;

                q = list_entry(p, struct eth_query, next);
                if (q->replied || memcmp(q->hash, hash, POA_QUERY_HLEN) != 0)
                        continue;

                if (!eth_query_is_match(q, poa))
                        continue;

                memcpy(q->mac, src->eth.dst.mac, POA_MAC_SIZE);
                memcpy(q->src_mac, src->eth.src.mac, POA_MAC_SIZE);
                strcpy(q->dev, src->eth.src.dev);

                q->r_ethertype = poa->local.eth.src.ethertype;

                q->replied = true;
        }

        pthread_cond_broadcast(&queries.cond);

        pthread_mutex_unlock(&queries.mtx);
}

/* Name query frames are handled in the transport. */
static void eth_rx_mgmt(struct poa *            poa,
                        const struct poa_addr * src,
                        const uint8_t *         buf,
                        size_t                  len)
{
        const struct poa_mgmt_msg * msg;
        const uint8_t *             hash;

        msg = (const struct poa_mgmt_msg *) buf;
        if (len < sizeof(*msg)) {
                poa_rx_mgmt(poa, src, buf, len);
                return;
        }

        if (msg->code != POA_NAME_QUERY && msg->code != POA_NAME_REPLY) {
                poa_rx_mgmt(poa, src, buf, len);
                return;
        }

        if (ntoh16(msg->data_len) != POA_QUERY_HLEN)
                return; /* malformed */

        if (len < sizeof(*msg) + POA_QUERY_HLEN)
                return; /* malformed */

        hash = buf + sizeof(*msg);

        if (msg->code == POA_NAME_QUERY) {
                POA_STAT_BUMP(poa, qry_rx);
                eth_query_arr(poa, src, hash);
        } else {
                POA_STAT_BUMP(poa, rep_rx);
                eth_reply_arr(poa, src, hash);
        }
}

static int eth_query_send(const uint8_t *         hash,
                          const struct poa_addr * addr)
{
        uint8_t               buf[sizeof(struct poa_mgmt_msg)
                                   + POA_QUERY_HLEN];
        struct poa_mgmt_msg * msg = (struct poa_mgmt_msg *) buf;
        struct poa_addr       bcast;

        bcast = *addr;

        memset(bcast.eth.dst.mac, 0xff, POA_MAC_SIZE);

        poa_mgmt_msg_ser(msg, POA_NAME_QUERY, 0, 0, qos_raw, 0, POA_QUERY_HLEN);

        memcpy(buf + sizeof(*msg), hash, POA_QUERY_HLEN);

        return poa_bcast_mgmt(&bcast, buf, sizeof(buf));
}

/* Complete addr for dst by broadcast query; the poa_query op. */
static int eth_query(const char *            dst,
                     const struct timespec * timeo,
                     struct poa_addr *       addr)
{
        struct timespec  dflt  = TIMESPEC_INIT_MS(ETH_QUERY_TIMEO);
        struct timespec  rintv = TIMESPEC_INIT_MS(ETH_QUERY_TIMEO
                                                  / (ETH_QUERY_RETRIES + 1));
        struct eth_query q;
        struct timespec  abstime;
        struct timespec  now;
        struct timespec  dl;
        time_t           rintv_ns = (time_t) TS_TO_UINT64(rintv);
        time_t           diff;
        uint8_t          hash[POA_QUERY_HLEN];
        int              n;
        int              err = -ETIMEDOUT;

        if (strlen(addr->eth.src.dev) > DEV_NAME_SIZE)
                return -EINVAL;

        addr->eth.src.ethertype = addr->eth.dst.ethertype;

        /* The destination is set; a zero ethertype cannot be sent. */
        if (!mac_is_zero(addr->eth.dst.mac))
                return addr->eth.dst.ethertype < 0x0600 ? -EINVAL : 0;

        str_hash(HASH_SHA3_256, hash, dst);

        pthread_once(&queries.once, queries_init);

        memset(&q, 0, sizeof(q));
        memcpy(q.hash, hash, POA_QUERY_HLEN);

        q.ethertype = addr->eth.dst.ethertype;

        memcpy(q.c_mac, addr->eth.src.mac, POA_MAC_SIZE);
        strcpy(q.c_dev, addr->eth.src.dev);

        pthread_mutex_lock(&queries.mtx);
        llist_add(&q.next, &queries.pending);
        pthread_mutex_unlock(&queries.mtx);

        pthread_cleanup_push(eth_query_cleanup, &q);

        clock_gettime(PTHREAD_COND_CLOCK, &now);
        ts_add(&now, timeo != NULL ? timeo : &dflt, &abstime);

        while (ts_diff_ns(&now, &abstime) < 0) {
                n = eth_query_send(hash, addr);
                if (n < 0) {
                        err = n;
                        break;
                }

                if (n == 0) {
                        err = -EPERM;
                        break;
                }

                ts_add(&now, &rintv, &dl);

                if (ts_diff_ns(&dl, &abstime) > 0)
                        dl = abstime;

                pthread_mutex_lock(&queries.mtx);

                pthread_cleanup_push(__cleanup_mutex_unlock, &queries.mtx);

                while (!q.replied) {
                        if (pthread_cond_timedwait(&queries.cond, &queries.mtx,
                                                   &dl) == ETIMEDOUT)
                                break;
                }

                if (q.replied) {
                        memcpy(addr->eth.dst.mac, q.mac, POA_MAC_SIZE);
                        memcpy(addr->eth.src.mac, q.src_mac, POA_MAC_SIZE);
                        strcpy(addr->eth.src.dev, q.dev);

                        addr->eth.dst.ethertype = q.r_ethertype;
                        addr->eth.src.ethertype = q.r_ethertype;

                        err = 0;
                }

                pthread_cleanup_pop(true);

                if (err == 0)
                        break;

                clock_gettime(PTHREAD_COND_CLOCK, &now);

                diff = ts_diff_ns(&now, &abstime);
                if (diff > -rintv_ns) /* skip the runt attempt */
                        break;
        }

        pthread_cleanup_pop(true);

        return err;
}

static void eth_spec(const struct poa * poa,
                     struct poa_spec *  spec)
{
        spec->type = poa->type;
        spec->eth  = poa->local.eth.src;
}

static bool eth_has_id(const struct poa *      poa,
                       const struct poa_spec * spec)
{
        if (strnlen(spec->eth.dev, sizeof(spec->eth.dev)) > DEV_NAME_SIZE)
                return false;

        if (strcmp(poa->local.eth.src.dev, spec->eth.dev) != 0)
                return false;

        return poa->local.eth.src.ethertype == spec->eth.ethertype;
}

/* Our end of the link; an unnamed one matches any. */
static bool eth_is_src(const struct poa *     poa,
                       const struct eth_poa * src)
{
        if (src->dev[0] != '\0' &&
            strcmp(poa->local.eth.src.dev, src->dev) != 0)
                return false;

        if (mac_is_zero(src->mac))
                return true;

        return memcmp(poa->local.eth.src.mac, src->mac,
                      POA_MAC_SIZE) == 0;
}

/* An ethertype of 0 in dst matches any, for broadcast queries. */
static bool eth_match(const struct poa *      poa,
                      const struct poa_addr * dst)
{
        uint16_t et = dst->eth.dst.ethertype;

        if (et != 0 && et != poa->local.eth.src.ethertype)
                return false;

        return eth_is_src(poa, &dst->eth.src);
}

static bool eth_link_match(const struct poa * poa,
                           int                id)
{
        struct eth_priv * priv = (struct eth_priv *) poa->priv;

        return priv->ifindex == id;
}

#ifdef HAVE_RAW_SOCKETS

/* MSG_DONTWAIT: the reader blocks on this socket. */
static int eth_sendv(struct eth_priv *       priv,
                     const uint8_t *         dst,
                     uint32_t                eid,
                     const uint8_t *         body,
                     size_t                  len,
                     bool                    block,
                     const struct timespec * abstime)
{
        struct eth_hdr hdr;
        struct msghdr  msg;
        struct iovec   iov[2];
        int            ret;

        if (len > priv->mtu - POA_HDR_SIZE)
                return -EMSGSIZE;

        eth_hdr_ser(priv, &hdr, dst, eid, len);

        iov[0].iov_base = &hdr;
        iov[0].iov_len  = ETH_HDR_TOT_SIZE;
        iov[1].iov_base = (void *) body;
        iov[1].iov_len  = len;

        memset(&msg, 0, sizeof(msg));

        msg.msg_name    = &priv->device;
        msg.msg_namelen = sizeof(priv->device);
        msg.msg_iov     = iov;
        msg.msg_iovlen  = len > 0 ? 2 : 1;
        while (sendmsg(priv->s_fd, &msg, MSG_DONTWAIT) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                        return -EIO;

                if (!block)
                        return -EAGAIN;

                ret = poa_wait_out(priv->s_fd, abstime);
                if (ret < 0)
                        return ret;
        }

        return 0;
}

static void * eth_reader(void * o)
{
        struct poa *      poa  = (struct poa *) o;
        struct eth_priv * priv = (struct eth_priv *) poa->priv;
        struct timespec   down = TIMESPEC_INIT_MS(ETH_DOWN_TIMEO);
        uint8_t *         buf;
        size_t            bufsz;

        bufsz = ETH_HDR_SIZE + priv->mtu;

        buf = malloc(bufsz);
        if (buf == NULL)
                return (void *) -1;

        pthread_cleanup_push(free, buf);

        while (true) {
                struct ssm_pk_buff * spb;
                struct sockaddr_ll   from;
                socklen_t            flen;
                struct poa_addr      src;
                ssize_t              n;
                uint32_t             eid;
                size_t               plen;
                const uint8_t *      body;

                flen = sizeof(from);

                n = recvfrom(priv->s_fd, buf, bufsz, 0,
                             (struct sockaddr *) &from, &flen);

                if (n < 0) {
                        if (errno == EINTR)
                                continue;

                        POA_STAT_BUMP(poa, rcv_fail);

                        if (errno == ENETDOWN) {
                                nanosleep(&down, NULL);
                                continue;
                        }

                        log_err("Reader on %s stopped: %s.",
                                poa->local.eth.src.dev,
                                strerror(errno));
                        break;
                }

                if (from.sll_pkttype == PACKET_OUTGOING)
                        continue;

                if (frame_parse(priv, buf, (size_t) n, &eid, &plen) < 0)
                        continue;

                body = buf + ETH_HDR_TOT_SIZE;

                if (eid == POA_MGMT_EID) {
                        frame_to_addr(priv, (struct eth_hdr *) buf, &src);
                        eth_rx_mgmt(poa, &src, body, plen);
                        continue;
                }

                if (poa_spb_reserve(&spb, plen) < 0) {
                        POA_STAT_BUMP(poa, buf_fail);
                        continue;
                }

                memcpy(ssm_pk_buff_head(spb), body, plen);

                poa_rx_pkt(poa, eid, spb);
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

/*
 * One netlink socket for the whole subsystem: RTMGRP_LINK delivers the
 * events of every interface anyway, so a socket per PoA only added
 * discards.
 */
int poa_monitor_open(void)
{
        struct sockaddr_nl sa;
        int                fd;

        memset(&sa, 0, sizeof(sa));

        sa.nl_family = AF_NETLINK;
        sa.nl_groups = RTMGRP_LINK;

        fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
        if (fd < 0)
                return -1;

        if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
                close(fd);
                return -1;
        }

        return fd;
}

void poa_monitor_read(int fd)
{
        uint8_t           buf[4096];
        struct nlmsghdr * h;
        ssize_t           n;

        n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0)
                return;

        for (h = (struct nlmsghdr *) buf;
             NLMSG_OK(h, (unsigned int) n);
             h = NLMSG_NEXT(h, n)) {
                struct ifinfomsg * ifi;
                unsigned int       usable;
                bool               up;
                size_t             cnt;

                if (h->nlmsg_type == NLMSG_DONE)
                        break;

                if (h->nlmsg_type != RTM_NEWLINK)
                        continue;

                ifi = NLMSG_DATA(h);

                usable = ifi->ifi_flags & (IFF_UP | IFF_RUNNING);
                up     = usable == (IFF_UP | IFF_RUNNING);

                cnt = poa_link_updown(ifi->ifi_index, up);
                if (cnt > 0)
                        log_info("Link %d %s, %zu flows.", ifi->ifi_index,
                                 up ? "up" : "down", cnt);
        }
}

static int eth_dev_info(const char * dev,
                        int *        idx,
                        uint8_t *    mac,
                        uint32_t *   mtu)
{
        struct ifreq ifr;
        int          fd;

        if (strlen(dev) >= IFNAMSIZ)
                return -EINVAL;

        *idx = if_nametoindex(dev);
        if (*idx == 0) {
                log_err("Failed to find device %s.", dev);
                return -ENODEV;
        }

        fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
                return -EIO;

        memset(&ifr, 0, sizeof(ifr));
        strcpy(ifr.ifr_name, dev);

        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
                log_err("Failed to get hardware address of %s.", dev);
                goto fail_ioctl;
        }

        memcpy(mac, ifr.ifr_hwaddr.sa_data, POA_MAC_SIZE);

        if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
                log_err("Failed to get MTU of %s.", dev);
                goto fail_ioctl;
        }

        close(fd);

        if (eth_dev_mac(mac) < 0)
                return -EIO;

        *mtu = MIN(MIN(ETH_MAX_MTU, POA_ETH_RD_BUF), (uint32_t) ifr.ifr_mtu);
        if (memcmp(dev, "lo", 2) == 0 && *mtu > POA_ETH_LO_MTU)
                *mtu = POA_ETH_LO_MTU;

        return 0;

 fail_ioctl:
        close(fd);
        return -EIO;
}

/* SO_RCVBUFFORCE bypasses rmem_max; SO_RCVBUF is the fallback. */
static void eth_set_rcvbuf(int fd,
                           int rcvbuf)
{
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUFFORCE,
                       &rcvbuf, sizeof(rcvbuf)) == 0)
                return;

        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0)
                log_info("Failed to set SO_RCVBUF to %d.", rcvbuf);
}

/* The send buffer holds at least one frame, or sendmsg cannot fit a PDU. */
static int eth_socket(struct eth_priv * priv,
                      int               idx,
                      const uint8_t *   mac)
{
        int sndbuf;
        int rcvbuf;
#ifdef POA_ETH_QDISC_BYPASS
        int bypass = 1;
#endif

        memset(&priv->device, 0, sizeof(priv->device));

        priv->device.sll_ifindex  = idx;
        priv->device.sll_family   = AF_PACKET;
        priv->device.sll_halen    = POA_MAC_SIZE;
        priv->device.sll_protocol = htons(ETH_P_ALL);

        memcpy(priv->device.sll_addr, mac, POA_MAC_SIZE);
        memcpy(priv->hw_addr, mac, POA_MAC_SIZE);

        priv->s_fd = socket(AF_PACKET, SOCK_RAW, priv->ethertype);
        if (priv->s_fd < 0) {
                log_err("Failed to create socket: %s.", strerror(errno));
                return -1;
        }

#ifdef POA_ETH_QDISC_BYPASS
        if (setsockopt(priv->s_fd, SOL_PACKET, PACKET_QDISC_BYPASS,
                       &bypass, sizeof(bypass)) < 0)
                log_info("Qdisc bypass not supported.");
#endif

        sndbuf = POA_ETH_SNDBUF;
        if (sndbuf > 0) {
                sndbuf = MAX(sndbuf, (int) (ETH_HDR_SIZE + priv->mtu));

                if (setsockopt(priv->s_fd, SOL_SOCKET, SO_SNDBUF,
                               &sndbuf, sizeof(sndbuf)) < 0)
                        log_info("Failed to set SO_SNDBUF to %d.", sndbuf);
        }

        rcvbuf = POA_ETH_RCVBUF;
        if (rcvbuf > 0)
                eth_set_rcvbuf(priv->s_fd, rcvbuf);

        if (bind(priv->s_fd, (struct sockaddr *) &priv->device,
                 sizeof(priv->device)) < 0) {
                log_err("Failed to bind socket to %d.", idx);
                close(priv->s_fd);
                return -1;
        }

        return 0;
}

/*
 * Pull qlen and backlog from the nested TCA_STATS2. The top-level
 * TCA_STATS shares TCA_STATS_QUEUE's id but carries a wholly
 * different struct, so descend first; never match on id alone.
 */
static void eth_qdisc_parse(struct rtattr * rta,
                            size_t          rlen,
                            size_t *        byt,
                            size_t *        pkt)
{
        struct gnet_stats_queue q;
        struct rtattr *         in;
        size_t                  ilen;

        for (; RTA_OK(rta, rlen); rta = RTA_NEXT(rta, rlen)) {
                if (rta->rta_type != TCA_STATS2)
                        continue;

                in   = (struct rtattr *) RTA_DATA(rta);
                ilen = RTA_PAYLOAD(rta);
                for (; RTA_OK(in, ilen); in = RTA_NEXT(in, ilen)) {
                        if (in->rta_type != TCA_STATS_QUEUE)
                                continue;

                        if (RTA_PAYLOAD(in) < sizeof(q))
                                continue;

                        memcpy(&q, RTA_DATA(in), sizeof(q));

                        *byt = q.backlog;
                        *pkt = q.qlen;
                }
        }
}

/*
 * Egress backlog of the device's root qdisc, in bytes and packets,
 * as the kernel queues them. The caller owns the netlink descriptor
 * and serialises the query. An early end of dump reports failure.
 */
static int eth_qdisc_backlog(int      fd,
                             int      ifindex,
                             size_t * byt,
                             size_t * pkt)
{
        struct {
                struct nlmsghdr nh;
                struct tcmsg    tc;
        }                  req;
        struct nlmsghdr *  nh;
        struct rtattr *    rta;
        struct tcmsg *     tc;
        char               buf[16384];
        ssize_t            len;
        int                ret = -1;

        if (fd < 0)
                goto fail;

        memset(&req, 0, sizeof(req));

        req.nh.nlmsg_len   = NLMSG_LENGTH(sizeof(req.tc));
        req.nh.nlmsg_type  = RTM_GETQDISC;
        req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        req.nh.nlmsg_seq   = 1;
        req.tc.tcm_family  = AF_UNSPEC;
        req.tc.tcm_ifindex = ifindex;
        if (send(fd, &req, req.nh.nlmsg_len, 0) < 0)
                goto fail;

        *byt = 0;
        *pkt = 0;

        while ((len = recv(fd, buf, sizeof(buf), 0)) > 0) {
                nh = (struct nlmsghdr *) buf;
                for (; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
                        if (nh->nlmsg_type == NLMSG_DONE)
                                goto done;

                        if (nh->nlmsg_type == NLMSG_ERROR)
                                goto fail;

                        if (nh->nlmsg_type != RTM_NEWQDISC)
                                continue;

                        tc = (struct tcmsg *) NLMSG_DATA(nh);
                        if (tc->tcm_ifindex != ifindex)
                                continue;

                        if (tc->tcm_parent != TC_H_ROOT)
                                continue;

                        rta = (struct rtattr *)
                                ((char *) tc + NLMSG_ALIGN(sizeof(*tc)));

                        eth_qdisc_parse(rta, nh->nlmsg_len
                                        - NLMSG_LENGTH(sizeof(*tc)),
                                        byt, pkt);
                }
        }

        goto fail; /* early end: a zero would read as empty */
 done:
        ret = 0;
 fail:
        return ret;
}

/*
 * A netlink descriptor for the qdisc query. SO_RCVTIMEO bounds the
 * dump: this is read from the send path, and a reply that never
 * arrives must not park a sender thread.
 */
static int eth_qdisc_open(void)
{
        struct sockaddr_nl sa;
        struct timeval     tv = TIMEVAL_INIT_MS(POA_QDISC_TIMEO);
        int                fd;

        fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
        if (fd < 0)
                return -1;

        memset(&sa, 0, sizeof(sa));

        sa.nl_family = AF_NETLINK;
        if (bind(fd, (struct sockaddr *) &sa, sizeof(sa)) < 0)
                goto fail;

        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
                goto fail;

        return fd;
 fail:
        close(fd);

        return -1;
}

/*
 * Queue depth in packets, straight from the qdisc. Gated like the
 * transport's own depth and skipped when another sender is already
 * asking, so the send path never waits on netlink.
 */
static int eth_qpkts(struct poa * poa,
                     size_t *     pkts,
                     size_t *     byts)
{
        struct eth_priv * priv = (struct eth_priv *) poa->priv;
        struct timespec   now;
        uint64_t          ns;
        size_t            byt;
        size_t            pkt;

        if (priv->nl_fd < 0)
                return -1;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        ns = TS_TO_UINT64(now);
        if (ns - LOAD_RELAXED(&priv->nl_time) < POA_QLEN_GATE)
                goto cached;

        if (__atomic_exchange_n(&priv->nl_busy, 1, __ATOMIC_ACQUIRE) != 0)
                goto cached;

        if (eth_qdisc_backlog(priv->nl_fd, priv->ifindex, &byt, &pkt) == 0) {
                STORE_RELAXED(&priv->nl_pkt, pkt);
                STORE_RELAXED(&priv->nl_byt, byt);
                STORE_RELAXED(&priv->nl_time, ns);
        }

        __atomic_store_n(&priv->nl_busy, 0, __ATOMIC_RELEASE);
 cached:
        if (LOAD_RELAXED(&priv->nl_time) == 0) /* nothing measured yet */
                return -1;

        *pkts = LOAD_RELAXED(&priv->nl_pkt);
        *byts = LOAD_RELAXED(&priv->nl_byt);

        return 0;
}

static int eth_attach(struct poa *            poa,
                      const struct poa_spec * spec)
{
        const struct eth_poa * c = &spec->eth;
        struct eth_priv *      priv;
        uint8_t                mac[POA_MAC_SIZE];
        uint32_t               mtu;
        int                    idx;
        int                    err;

        if (strnlen(c->dev, sizeof(c->dev)) > DEV_NAME_SIZE)
                return -EINVAL;

        if (c->ethertype < 0x0600 || c->ethertype == 0xFFFF) {
                log_err("Invalid Ethertype 0x%x.", c->ethertype);
                return -EINVAL;
        }

        priv = malloc(sizeof(*priv));
        if (priv == NULL)
                return -ENOMEM;

        memset(priv, 0, sizeof(*priv));

        priv->poa   = poa;
        priv->nl_fd = eth_qdisc_open(); /* optional; socket fallback */

        priv->ethertype = htons(c->ethertype);

        err = eth_dev_info(c->dev, &idx, mac, &mtu);
        if (err < 0)
                goto fail_conf;

        priv->mtu = mtu;
        if (eth_socket(priv, idx, mac) < 0)
                goto fail_conf;

        poa->priv                    = priv;
        poa->local.type              = poa->type;
        poa->local.eth.src.ethertype = c->ethertype;
        priv->ifindex                = idx;

        memcpy(poa->local.eth.src.mac, mac, POA_MAC_SIZE);
        strcpy(poa->local.eth.src.dev, c->dev);

        return 0;

 fail_conf:
        if (priv->nl_fd >= 0)
                close(priv->nl_fd);

        free(priv);

        return -EIO;
}

static void eth_detach(struct poa * poa)
{
        struct eth_priv * priv = (struct eth_priv *) poa->priv;

        if (priv == NULL)
                return;

        close(priv->s_fd);

        if (priv->nl_fd >= 0)
                close(priv->nl_fd);

        free(priv);

        poa->priv = NULL;
}

static uint32_t eth_mtu(struct poa *            poa,
                        const struct poa_addr * dst)
{
        struct eth_priv * priv = (struct eth_priv *) poa->priv;

        (void) dst;

        return priv->mtu - POA_HDR_SIZE;
}

/* All flows on the PoA share the socket, so this is aggregate. */
static size_t eth_qlen(struct poa * poa)
{
#ifdef SIOCOUTQ
        struct eth_priv * priv = (struct eth_priv *) poa->priv;
        int               qlen;

        qlen = 0;
        if (ioctl(priv->s_fd, SIOCOUTQ, &qlen) < 0)
                return 0;

        return (size_t) qlen;
#else
        (void) poa;

        return 0;
#endif
}

/*
 * PACKET_STATISTICS zeroes the kernel counters on read, so totals
 * accumulate here; relaxed atomics allow concurrent RIB reads.
 * The qdisc depth rides the sender's guarded path: one dump at a time.
 */
static int eth_rib(struct poa * poa,
                   char *       buf,
                   size_t       len)
{
        struct eth_priv *    priv = (struct eth_priv *) poa->priv;
        struct tpacket_stats ts;
        socklen_t            optlen;
        size_t               sndbuf = 0;
        size_t               rcvbuf = 0;
        size_t               qd_byt;
        size_t               qd_pkt;
        int                  val;
        int                  size;

        optlen = sizeof(val);
        if (getsockopt(priv->s_fd, SOL_SOCKET, SO_SNDBUF, &val, &optlen) == 0)
                sndbuf = (size_t) val;

        optlen = sizeof(val);
        if (getsockopt(priv->s_fd, SOL_SOCKET, SO_RCVBUF, &val, &optlen) == 0)
                rcvbuf = (size_t) val;

        optlen = sizeof(ts);

        if (getsockopt(priv->s_fd, SOL_PACKET, PACKET_STATISTICS,
                       &ts, &optlen) == 0) {
                FETCH_ADD_RELAXED(&priv->kern_rcv, ts.tp_packets);
                FETCH_ADD_RELAXED(&priv->kern_drp, ts.tp_drops);
        }

        if (eth_qpkts(poa, &qd_pkt, &qd_byt) < 0) {
                qd_byt = 0;
                qd_pkt = 0;
        }

        size = snprintf(buf, len,
                        "Socket sndbuf (bytes):     %zu\n"
                        "Socket rcvbuf (bytes):     %zu\n"
                        "Kernel packets received:   %zu\n"
                        "Kernel packets dropped:    %zu\n"
                        "Qdisc backlog (bytes):     %zu\n"
                        "Qdisc backlog (packets):   %zu\n",
                        sndbuf, rcvbuf,
                        LOAD_RELAXED(&priv->kern_rcv),
                        LOAD_RELAXED(&priv->kern_drp),
                        qd_byt, qd_pkt);
        if (size < 0 || (size_t) size >= len)
                return -1;

        return size;
}

#elif defined(HAVE_BPF)

/*
 * BSD and macOS reach the link layer through a cloned /dev/bpf
 * device, bound to an interface with BIOCSETIF. One device per PoA.
 */

static int eth_sendv(struct eth_priv *       priv,
                     const uint8_t *         dst,
                     uint32_t                eid,
                     const uint8_t *         body,
                     size_t                  len,
                     bool                    block,
                     const struct timespec * abstime)
{
        struct eth_hdr hdr;
        struct iovec   iov[2];
        int            n;
        int            ret;

        if (len > priv->mtu - POA_HDR_SIZE)
                return -EMSGSIZE;

        eth_hdr_ser(priv, &hdr, dst, eid, len);

        iov[0].iov_base = &hdr;
        iov[0].iov_len  = ETH_HDR_TOT_SIZE;
        iov[1].iov_base = (void *) body;
        iov[1].iov_len  = len;
        n               = len > 0 ? 2 : 1;
        while (writev(priv->s_fd, iov, n) < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                        return -EIO;

                if (!block)
                        return -EAGAIN;

                ret = poa_wait_out(priv->s_fd, abstime);
                if (ret < 0)
                        return ret;
        }

        return 0;
}

/* One read yields a batch of BPF_WORDALIGN'ed frames; walk all of them. */
static void * eth_reader(void * o)
{
        struct poa *      poa  = (struct poa *) o;
        struct eth_priv * priv = (struct eth_priv *) poa->priv;
        uint8_t *         buf;

        buf = malloc(priv->blen);
        if (buf == NULL)
                return (void *) -1;

        pthread_cleanup_push(free, buf);

        while (true) {
                uint8_t * p;
                uint8_t * end;
                ssize_t   n;

                n = read(priv->s_fd, buf, priv->blen);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;

                        POA_STAT_BUMP(poa, rcv_fail);
                        break;
                }

                p   = buf;
                end = buf + n;
                while (p + sizeof(struct bpf_hdr) <= end) {
                        struct bpf_hdr *     bh = (struct bpf_hdr *) p;
                        struct ssm_pk_buff * spb;
                        struct poa_addr      src;
                        const uint8_t *      frame;
                        const uint8_t *      body;
                        uint32_t             eid;
                        size_t               plen;

                        frame = p + bh->bh_hdrlen;
                        if (frame + bh->bh_caplen > end)
                                break;

                        if (frame_parse(priv, frame, bh->bh_caplen,
                                        &eid, &plen) < 0)
                                goto next;

                        body = frame + ETH_HDR_TOT_SIZE;

                        if (eid == POA_MGMT_EID) {
                                frame_to_addr(priv,
                                              (const struct eth_hdr *) frame,
                                              &src);
                                eth_rx_mgmt(poa, &src, body, plen);
                                goto next;
                        }

                        if (poa_spb_reserve(&spb, plen) < 0) {
                                POA_STAT_BUMP(poa, buf_fail);
                                goto next;
                        }

                        memcpy(ssm_pk_buff_head(spb), body, plen);

                        poa_rx_pkt(poa, eid, spb);
 next:
                        p += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
                }
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

static int eth_dev_info(const char * dev,
                        uint8_t *    mac,
                        uint32_t *   mtu)
{
        struct ifaddrs * ifas;
        struct ifaddrs * ifa;
        struct ifreq     ifr;
        int              fd;
        int              found = 0;

        if (getifaddrs(&ifas) < 0) {
                log_err("Failed to list interfaces.");
                return -1;
        }

        for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
                struct sockaddr_dl * dl;

                if (ifa->ifa_addr == NULL)
                        continue;

                if (ifa->ifa_addr->sa_family != AF_LINK)
                        continue;

                if (strcmp(ifa->ifa_name, dev) != 0)
                        continue;

                dl = (struct sockaddr_dl *) ifa->ifa_addr;
                if (dl->sdl_alen != POA_MAC_SIZE)
                        continue;

                memcpy(mac, LLADDR(dl), POA_MAC_SIZE);

                found = 1;
                break;
        }

        freeifaddrs(ifas);

        if (!found) {
                log_err("No such device: %s.", dev);
                return -1;
        }

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
                return -1;

        memset(&ifr, 0, sizeof(ifr));

        strcpy(ifr.ifr_name, dev);

        if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
                log_err("Failed to get MTU of %s.", dev);
                close(fd);
                return -1;
        }

        close(fd);

        if (eth_dev_mac(mac) < 0)
                return -1;

        *mtu = MIN(MIN(ETH_MAX_MTU, POA_ETH_RD_BUF), (uint32_t) ifr.ifr_mtu);
        if (memcmp(dev, "lo", 2) == 0 && *mtu > POA_ETH_LO_MTU)
                *mtu = POA_ETH_LO_MTU;

        return 0;
}

static int eth_bpf_open(void)
{
        char   dev[32];
        size_t i;

        for (i = 0; i < BPF_DEV_MAX; ++i) {
                int fd;

                sprintf(dev, "/dev/bpf%zu", i);

                fd = open(dev, O_RDWR);
                if (fd >= 0)
                        return fd;
        }

        return -1;
}

/*
 * BIOCSHDRCMPLT: we fill in the source address ourselves.
 * BIOCSSEESENT:  our own egress must not come back at us.
 * BIOCIMMEDIATE: deliver on arrival, do not wait for a full buffer.
 */
static int eth_bpf_setup(struct eth_priv * priv,
                         const char *      dev)
{
        struct ifreq ifr;
        int          enable  = 1;
        int          disable = 0;
        int          blen    = 0;

        memset(&ifr, 0, sizeof(ifr));

        strcpy(ifr.ifr_name, dev);

        if (ioctl(priv->s_fd, BIOCSETIF, &ifr) < 0) {
                log_err("Failed to bind bpf device to %s.", dev);
                return -1;
        }

        if (ioctl(priv->s_fd, BIOCGBLEN, &blen) < 0 || blen <= 0) {
                log_err("Failed to get the bpf buffer length.");
                return -1;
        }

        priv->blen = (size_t) blen;
        if (ioctl(priv->s_fd, BIOCSHDRCMPLT, &enable) < 0) {
                log_err("Failed to set BIOCSHDRCMPLT.");
                return -1;
        }

        if (ioctl(priv->s_fd, BIOCSSEESENT, &disable) < 0) {
                log_err("Failed to set BIOCSSEESENT.");
                return -1;
        }

        if (ioctl(priv->s_fd, BIOCIMMEDIATE, &enable) < 0) {
                log_err("Failed to set BIOCIMMEDIATE.");
                return -1;
        }

        return 0;
}

static int eth_attach(struct poa *            poa,
                      const struct poa_spec * spec)
{
        const struct eth_poa * c = &spec->eth;
        struct eth_priv *      priv;
        uint8_t                mac[POA_MAC_SIZE];
        uint32_t               mtu;

        if (strnlen(c->dev, sizeof(c->dev)) > DEV_NAME_SIZE)
                return -EINVAL;

        if (c->ethertype < 0x0600 || c->ethertype == 0xFFFF) {
                log_err("Invalid Ethertype 0x%x.", c->ethertype);
                return -EINVAL;
        }

        priv = malloc(sizeof(*priv));
        if (priv == NULL)
                return -ENOMEM;

        memset(priv, 0, sizeof(*priv));

        priv->poa  = poa;
        priv->s_fd = -1;

        priv->ethertype = htons(c->ethertype);

        if (eth_dev_info(c->dev, mac, &mtu) < 0)
                goto fail_conf;

        priv->mtu = mtu;

        memcpy(priv->hw_addr, mac, POA_MAC_SIZE);

        priv->s_fd = eth_bpf_open();
        if (priv->s_fd < 0) {
                log_err("Failed to open a bpf device.");
                goto fail_conf;
        }

        if (eth_bpf_setup(priv, c->dev) < 0)
                goto fail_device;

        poa->priv                    = priv;
        poa->local.type              = poa->type;
        poa->local.eth.src.ethertype = c->ethertype;

        memcpy(poa->local.eth.src.mac, mac, POA_MAC_SIZE);
        strcpy(poa->local.eth.src.dev, c->dev);

        log_info("Using Berkeley Packet Filter on %s.", c->dev);

        return 0;

 fail_device:
        close(priv->s_fd);
 fail_conf:
        free(priv);

        return -EIO;
}

static void eth_detach(struct poa * poa)
{
        struct eth_priv * priv = (struct eth_priv *) poa->priv;

        if (priv == NULL)
                return;

        close(priv->s_fd);

        free(priv);

        poa->priv = NULL;
}

static uint32_t eth_mtu(struct poa *            poa,
                        const struct poa_addr * dst)
{
        struct eth_priv * priv = (struct eth_priv *) poa->priv;

        (void) dst;

        return priv->mtu - POA_HDR_SIZE;
}

/* A bpf device has no send queue to report; mb-ECN cannot mark here. */
static size_t eth_qlen(struct poa * poa)
{
        (void) poa;

        return 0;
}

/* The bpf device buffer is all the receive queue there is. */
static int eth_rib(struct poa * poa,
                   char *       buf,
                   size_t       len)
{
        struct eth_priv * priv = (struct eth_priv *) poa->priv;
        struct bpf_stat   bs;
        int               size;

        if (ioctl(priv->s_fd, BIOCGSTATS, &bs) == 0) {
                FETCH_ADD_RELAXED(&priv->kern_rcv, bs.bs_recv);
                FETCH_ADD_RELAXED(&priv->kern_drp, bs.bs_drop);
        }

        size = snprintf(buf, len,
                        "Socket rcvbuf (bytes):     %zu\n"
                        "Kernel packets received:   %zu\n"
                        "Kernel packets dropped:    %zu\n",
                        priv->blen,
                        LOAD_RELAXED(&priv->kern_rcv),
                        LOAD_RELAXED(&priv->kern_drp));
        if (size < 0 || (size_t) size >= len)
                return -1;

        return size;
}

#elif defined(HAVE_NETMAP)

/*
 * netmap gives one PoA the whole port: reads copy out of the NIC
 * ring, writes inject into it.
 */

/* nm_inject takes one contiguous frame, so the header is copied in. */
static int eth_sendv(struct eth_priv *       priv,
                     const uint8_t *         dst,
                     uint32_t                eid,
                     const uint8_t *         body,
                     size_t                  len,
                     bool                    block,
                     const struct timespec * abstime)
{
        uint8_t * frame;
        size_t    flen;
        int       ret;

        if (len > priv->mtu - POA_HDR_SIZE)
                return -EMSGSIZE;

        flen  = ETH_HDR_TOT_SIZE + len;

        frame = malloc(flen);
        if (frame == NULL)
                return -ENOMEM;

        eth_hdr_ser(priv, (struct eth_hdr *) frame, dst, eid, len);

        if (len > 0)
                memcpy(frame + ETH_HDR_TOT_SIZE, body, len);

        if (block)
                ret = poa_wait_out(priv->poll_out.fd, abstime);
        else
                ret = poll(&priv->poll_out, 1, 0) > 0 ? 0 : -EAGAIN;

        if (ret < 0)
                goto fail;

        ret = nm_inject(priv->nmd, frame, flen) == (int) flen ? 0 : -EIO;
 fail:
        free(frame);

        return ret;
}

/* A slot stays owned by the ring, so each frame is copied out. */
static void * eth_reader(void * o)
{
        struct poa *      poa  = (struct poa *) o;
        struct eth_priv * priv = (struct eth_priv *) poa->priv;

        while (true) {
                struct ssm_pk_buff * spb;
                struct poa_addr      src;
                struct nm_pkthdr     hdr;
                const uint8_t *      frame;
                const uint8_t *      body;
                uint32_t             eid;
                size_t               plen;

                if (poll(&priv->poll_in, 1, -1) < 0) {
                        if (errno == EINTR)
                                continue;

                        POA_STAT_BUMP(poa, rcv_fail);
                        break;
                }

                if (priv->poll_in.revents == 0)
                        continue;

                frame = nm_nextpkt(priv->nmd, &hdr);
                if (frame == NULL)
                        continue;

                if (frame_parse(priv, frame, hdr.len, &eid, &plen) < 0)
                        continue;

                body = frame + ETH_HDR_TOT_SIZE;

                if (eid == POA_MGMT_EID) {
                        frame_to_addr(priv, (const struct eth_hdr *) frame,
                                      &src);
                        eth_rx_mgmt(poa, &src, body, plen);
                        continue;
                }

                if (poa_spb_reserve(&spb, plen) < 0) {
                        POA_STAT_BUMP(poa, buf_fail);
                        continue;
                }

                memcpy(ssm_pk_buff_head(spb), body, plen);

                poa_rx_pkt(poa, eid, spb);
        }

        return (void *) 0;
}

static int eth_dev_info(const char * dev,
                        uint8_t *    mac,
                        uint32_t *   mtu)
{
        struct ifreq     ifr;
#ifndef __linux__
        struct ifaddrs * ifas;
        struct ifaddrs * ifa;
        int              found = 0;
#endif
        int              fd;

        if (strlen(dev) >= IFNAMSIZ)
                return -EINVAL;

        fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0)
                return -EIO;

        memset(&ifr, 0, sizeof(ifr));

        strcpy(ifr.ifr_name, dev);

#ifdef __linux__
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
                log_err("Failed to get hardware address of %s.", dev);
                goto fail_ioctl;
        }

        memcpy(mac, ifr.ifr_hwaddr.sa_data, POA_MAC_SIZE);
#else
        if (getifaddrs(&ifas) < 0)
                goto fail_ioctl;

        for (ifa = ifas; ifa != NULL; ifa = ifa->ifa_next) {
                struct sockaddr_dl * dl;

                if (ifa->ifa_addr == NULL)
                        continue;

                if (ifa->ifa_addr->sa_family != AF_LINK)
                        continue;

                if (strcmp(ifa->ifa_name, dev) != 0)
                        continue;

                dl = (struct sockaddr_dl *) ifa->ifa_addr;
                if (dl->sdl_alen != POA_MAC_SIZE)
                        continue;

                memcpy(mac, LLADDR(dl), POA_MAC_SIZE);

                found = 1;
                break;
        }

        freeifaddrs(ifas);

        if (!found) {
                log_err("No hardware address for %s.", dev);
                goto fail_ioctl;
        }
#endif
        if (ioctl(fd, SIOCGIFMTU, &ifr) < 0) {
                log_err("Failed to get MTU of %s.", dev);
                goto fail_ioctl;
        }

        close(fd);

        if (eth_dev_mac(mac) < 0)
                return -1;

        *mtu = MIN(MIN(ETH_MAX_MTU, POA_ETH_RD_BUF), (uint32_t) ifr.ifr_mtu);
        if (memcmp(dev, "lo", 2) == 0 && *mtu > POA_ETH_LO_MTU)
                *mtu = POA_ETH_LO_MTU;

        return 0;

 fail_ioctl:
        close(fd);

        return -EIO;
}

static int eth_nm_open(struct eth_priv * priv,
                       const char *      dev)
{
        char ifn[IFNAMSIZ + sizeof("netmap:")];

        strcpy(ifn, "netmap:");
        strcat(ifn, dev);

        priv->nmd = nm_open(ifn, NULL, 0, NULL);
        if (priv->nmd == NULL) {
                log_err("Failed to open netmap device for %s.", dev);
                return -1;
        }

        memset(&priv->poll_in, 0, sizeof(priv->poll_in));
        memset(&priv->poll_out, 0, sizeof(priv->poll_out));

        priv->poll_in.fd      = NETMAP_FD(priv->nmd);
        priv->poll_in.events  = POLLIN;
        priv->poll_out.fd     = NETMAP_FD(priv->nmd);
        priv->poll_out.events = POLLOUT;

        return 0;
}

static int eth_attach(struct poa *            poa,
                      const struct poa_spec * spec)
{
        const struct eth_poa * c = &spec->eth;
        struct eth_priv *      priv;
        uint8_t                mac[POA_MAC_SIZE];
        uint32_t               mtu;

        if (strnlen(c->dev, sizeof(c->dev)) > DEV_NAME_SIZE)
                return -EINVAL;

        if (c->ethertype < 0x0600 || c->ethertype == 0xFFFF) {
                log_err("Invalid Ethertype 0x%x.", c->ethertype);
                return -EINVAL;
        }

        priv = malloc(sizeof(*priv));
        if (priv == NULL)
                return -ENOMEM;

        memset(priv, 0, sizeof(*priv));

        priv->poa = poa;

        priv->ethertype = htons(c->ethertype);

        if (eth_dev_info(c->dev, mac, &mtu) < 0)
                goto fail_conf;

        priv->mtu = mtu;

        memcpy(priv->hw_addr, mac, POA_MAC_SIZE);

        if (eth_nm_open(priv, c->dev) < 0)
                goto fail_conf;

        poa->priv                    = priv;
        poa->local.type              = poa->type;
        poa->local.eth.src.ethertype = c->ethertype;

        memcpy(poa->local.eth.src.mac, mac, POA_MAC_SIZE);
        strcpy(poa->local.eth.src.dev, c->dev);

        log_info("Using netmap on %s.", c->dev);

        return 0;

 fail_conf:
        free(priv);

        return -EIO;
}

static void eth_detach(struct poa * poa)
{
        struct eth_priv * priv = (struct eth_priv *) poa->priv;

        if (priv == NULL)
                return;

        nm_close(priv->nmd);

        free(priv);

        poa->priv = NULL;
}

static uint32_t eth_mtu(struct poa *            poa,
                        const struct poa_addr * dst)
{
        struct eth_priv * priv = (struct eth_priv *) poa->priv;

        (void) dst;

        return priv->mtu - POA_HDR_SIZE;
}

/* The ring is drained by the NIC; there is no queue to report. */
static size_t eth_qlen(struct poa * poa)
{
        (void) poa;

        return 0;
}

#endif /* HAVE_RAW_SOCKETS */

#ifndef HAVE_RAW_SOCKETS

/* Only netlink reports link events; no other backend has a monitor. */
int poa_monitor_open(void)
{
        return -1;
}

void poa_monitor_read(int fd)
{
        (void) fd;
}

#endif

/* One reader per socket, so a flow cannot be reordered on receive. */
static int eth_start(struct poa * poa)
{
        struct eth_priv * priv = (struct eth_priv *) poa->priv;

        if (pthread_create(&priv->reader, NULL, eth_reader, poa) != 0)
                return -1;

        priv->running = true;

        return 0;
}

static void eth_stop(struct poa * poa)
{
        struct eth_priv * priv = (struct eth_priv *) poa->priv;

        if (!priv->running)
                return;

        pthread_cancel(priv->reader);
        pthread_join(priv->reader, NULL);

        priv->running = false;
}

static int eth_send(struct poa *            poa,
                    const struct poa_addr * dst,
                    uint32_t                eid,
                    struct ssm_pk_buff *    spb,
                    bool                    block,
                    const struct timespec * abstime)
{
        return eth_sendv((struct eth_priv *) poa->priv, dst->eth.dst.mac, eid,
                         ssm_pk_buff_head(spb), ssm_pk_buff_len(spb),
                         block, abstime);
}

static int eth_send_mgmt(struct poa *            poa,
                         const struct poa_addr * dst,
                         const uint8_t *         buf,
                         size_t                  len)
{
        struct timespec timeo = TIMESPEC_INIT_MS(POA_MGMT_SND_TIMEO);
        struct timespec abstime;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        return eth_sendv((struct eth_priv *) poa->priv, dst->eth.dst.mac,
                         POA_MGMT_EID, buf, len, true, &abstime);
}

const struct poa_ops eth_poa_ops = {
        .poa_attach     = eth_attach,
        .poa_detach     = eth_detach,
        .poa_start      = eth_start,
        .poa_stop       = eth_stop,
        .poa_send       = eth_send,
        .poa_send_mgmt  = eth_send_mgmt,
        .poa_query      = eth_query,
        .poa_mtu        = eth_mtu,
        .poa_qlen       = eth_qlen,
#ifdef HAVE_RAW_SOCKETS
        .poa_qpkts      = eth_qpkts,
#endif
#ifndef HAVE_NETMAP
        .poa_rib        = eth_rib,
#endif
        .poa_spec       = eth_spec,
        .poa_has_id     = eth_has_id,
        .poa_match      = eth_match,
        .poa_link_match = eth_link_match,
        .mpl            = POA_ETH_MPL
};
