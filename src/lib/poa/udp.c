/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Points of attachment (PoA) - UDP transport
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

#define OUROBOROS_PREFIX "poa-udp"

#include <ouroboros/endian.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/time.h>
#include <ouroboros/utils.h>

#include "poa.h"

#ifdef __linux__
#include <linux/sockios.h>
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define UDP_HDR_LEN     sizeof(uint32_t) /* PoA id */
#define UDP_MAX_PAYLOAD (POA_UDP_RD_BUF - UDP_HDR_LEN)
/* The reader buffer must fit a full mgmt frame at any tuning. */
#define UDP_MAX_PACKET  MAX(POA_UDP_RD_BUF, POA_MGMT_FRAME_SIZE + UDP_HDR_LEN)
#define UDP_IP4_OVERH   28U              /* IPv4 + UDP */
#define UDP_IP6_OVERH   48U              /* IPv6 + UDP */
/* Wait for the link to come back before reading it again. */
#define UDP_DOWN_TIMEO  100              /* ms */

union udp_saddr {
        struct sockaddr     sa;
        struct sockaddr_in  in;
        struct sockaddr_in6 in6;
};

struct udp_priv {
        int             s_fd;
        int             af;
        union udp_saddr s_saddr;
        pthread_t       reader;
        bool            running;
};

static socklen_t saddr_len(int af)
{
        if (af == AF_INET)
                return sizeof(struct sockaddr_in);

        return sizeof(struct sockaddr_in6);
}

static void addr_to_saddr(const struct poa_addr * addr,
                          union udp_saddr *       saddr)
{
        memset(saddr, 0, sizeof(*saddr));

        if (addr->type == POA_UDP4) {
                saddr->in.sin_family = AF_INET;
                saddr->in.sin_addr   = addr->udp4.ip_addr;
                saddr->in.sin_port   = htons(addr->udp4.port);
        } else {
                saddr->in6.sin6_family = AF_INET6;
                saddr->in6.sin6_addr   = addr->udp6.ip_addr;
                saddr->in6.sin6_port   = htons(addr->udp6.port);
        }
}

static void saddr_to_addr(const union udp_saddr * saddr,
                          struct poa_addr *       addr)
{
        memset(addr, 0, sizeof(*addr));

        if (saddr->sa.sa_family == AF_INET) {
                addr->type         = POA_UDP4;
                addr->udp4.ip_addr = saddr->in.sin_addr;
                addr->udp4.port    = ntohs(saddr->in.sin_port);
        } else {
                addr->type         = POA_UDP6;
                addr->udp6.ip_addr = saddr->in6.sin6_addr;
                addr->udp6.port    = ntohs(saddr->in6.sin6_port);
        }
}

/* A datagram longer than the buffer arrives truncated: drop it. */
static void * udp_reader(void * o)
{
        struct poa *      poa  = (struct poa *) o;
        struct udp_priv * priv = (struct udp_priv *) poa->priv;
        struct timespec   down = TIMESPEC_INIT_MS(UDP_DOWN_TIMEO);
        uint8_t *         buf;

        buf = malloc(UDP_MAX_PACKET);
        if (buf == NULL)
                return (void *) -1;

        pthread_cleanup_push(free, buf);

        while (true) {
                struct ssm_pk_buff * spb;
                union udp_saddr      r_saddr;
                struct poa_addr      src;
                struct msghdr        mh;
                struct iovec         iov;
                ssize_t              n;
                uint32_t             eid;
                size_t               plen;

                iov.iov_base = buf;
                iov.iov_len  = UDP_MAX_PACKET;

                memset(&mh, 0, sizeof(mh));

                mh.msg_name    = &r_saddr;
                mh.msg_namelen = sizeof(r_saddr);
                mh.msg_iov     = &iov;
                mh.msg_iovlen  = 1;

                n = recvmsg(priv->s_fd, &mh, 0);
                if (n < 0) {
                        if (errno == EINTR)
                                continue;

                        POA_STAT_BUMP(poa, rcv_fail);

                        if (errno == ENETDOWN) {
                                nanosleep(&down, NULL);
                                continue;
                        }

                        log_err("Reader stopped: %s.", strerror(errno));
                        break;
                }

                if ((mh.msg_flags & MSG_TRUNC) != 0) {
                        POA_STAT_BUMP(poa, buf_fail);
                        continue;
                }

                if ((size_t) n < UDP_HDR_LEN)
                        continue;

                eid  = ntoh32(*(uint32_t *) buf);
                plen = (size_t) n - UDP_HDR_LEN;

                saddr_to_addr(&r_saddr, &src);

                if (eid == POA_MGMT_EID) {
                        poa_rx_mgmt(poa, &src, buf + UDP_HDR_LEN, plen);
                        continue;
                }

                if (poa_spb_reserve(&spb, plen) < 0) {
                        POA_STAT_BUMP(poa, buf_fail);
                        continue;
                }

                memcpy(ssm_pk_buff_head(spb), buf + UDP_HDR_LEN, plen);

                poa_rx_pkt(poa, eid, spb);
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

/* Reads the bound address back: an ephemeral port is only known after. */
static int udp_attach(struct poa *            poa,
                      const struct poa_spec * spec)
{
        struct udp_priv * priv;
        socklen_t         len;
        int               af;

        af = spec->type == POA_UDP4 ? AF_INET : AF_INET6;

        priv = malloc(sizeof(*priv));
        if (priv == NULL)
                return -ENOMEM;

        memset(priv, 0, sizeof(*priv));

        priv->af   = af;
        priv->s_fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
        if (priv->s_fd < 0) {
                log_err("Failed to create socket: %s.", strerror(errno));
                goto fail_socket;
        }

        if (af == AF_INET) {
                priv->s_saddr.in.sin_family = AF_INET;
                priv->s_saddr.in.sin_addr   = spec->udp4.ip_addr;
                priv->s_saddr.in.sin_port   = htons(spec->udp4.port);
        } else {
                int on = 1;

                if (setsockopt(priv->s_fd, IPPROTO_IPV6, IPV6_V6ONLY,
                               &on, sizeof(on)) < 0) {
                        log_err("Failed to set IPV6_V6ONLY: %s.",
                                strerror(errno));
                        goto fail_bind;
                }

                priv->s_saddr.in6.sin6_family = AF_INET6;
                priv->s_saddr.in6.sin6_addr   = spec->udp6.ip_addr;
                priv->s_saddr.in6.sin6_port   = htons(spec->udp6.port);
        }

        if (bind(priv->s_fd, &priv->s_saddr.sa, saddr_len(af)) < 0) {
                log_err("Failed to bind: %s.", strerror(errno));
                goto fail_bind;
        }

        poa->priv = priv;
        len       = saddr_len(af);
        if (getsockname(priv->s_fd, &priv->s_saddr.sa, &len) < 0)
                log_warn("Failed to read the bound address: %s.",
                         strerror(errno));

        saddr_to_addr(&priv->s_saddr, &poa->local);

        return 0;

 fail_bind:
        close(priv->s_fd);
 fail_socket:
        poa->priv = NULL;

        free(priv);

        return -EIO;
}

static void udp_detach(struct poa * poa)
{
        struct udp_priv * priv = (struct udp_priv *) poa->priv;

        if (priv == NULL)
                return;

        close(priv->s_fd);

        free(priv);

        poa->priv = NULL;
}

/* One reader per socket, so a flow cannot be reordered on receive. */
static int udp_start(struct poa * poa)
{
        struct udp_priv * priv = (struct udp_priv *) poa->priv;

        if (pthread_create(&priv->reader, NULL, udp_reader, poa) != 0)
                return -1;

        priv->running = true;

        return 0;
}

static void udp_stop(struct poa * poa)
{
        struct udp_priv * priv = (struct udp_priv *) poa->priv;

        if (!priv->running)
                return;

        pthread_cancel(priv->reader);
        pthread_join(priv->reader, NULL);

        priv->running = false;
}

/*
 * The PoA id is a separate iovec, so the buffer needs no headroom.
 * MSG_DONTWAIT: the reader blocks on this socket.
 */
static int udp_sendv(struct udp_priv *       priv,
                     const struct poa_addr * dst,
                     uint32_t                eid,
                     const uint8_t *         body,
                     size_t                  len,
                     bool                    block,
                     const struct timespec * abstime)
{
        union udp_saddr saddr;
        struct msghdr   msg;
        struct iovec    iov[2];
        uint32_t        hdr;
        int             ret;

        if (len > UDP_MAX_PAYLOAD)
                return -EMSGSIZE;

        addr_to_saddr(dst, &saddr);

        hdr = hton32(eid);

        iov[0].iov_base = &hdr;
        iov[0].iov_len  = sizeof(hdr);
        iov[1].iov_base = (void *) body;
        iov[1].iov_len  = len;

        memset(&msg, 0, sizeof(msg));

        msg.msg_name    = &saddr;
        msg.msg_namelen = saddr_len(priv->af);
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

static int udp_send(struct poa *            poa,
                    const struct poa_addr * dst,
                    uint32_t                eid,
                    struct ssm_pk_buff *    spb,
                    bool                    block,
                    const struct timespec * abstime)
{
        return udp_sendv((struct udp_priv *) poa->priv, dst, eid,
                         ssm_pk_buff_head(spb), ssm_pk_buff_len(spb),
                         block, abstime);
}

static int udp_send_mgmt(struct poa *            poa,
                         const struct poa_addr * dst,
                         const uint8_t *         buf,
                         size_t                  len)
{
        struct timespec timeo = TIMESPEC_INIT_MS(POA_MGMT_SND_TIMEO);
        struct timespec abstime;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        return udp_sendv((struct udp_priv *) poa->priv, dst, POA_MGMT_EID,
                         buf, len, true, &abstime);
}

/* The PoA id header eats into the usable MTU. */
static uint32_t udp_mtu(struct poa *            poa,
                        const struct poa_addr * dst)
{
        struct udp_priv * priv = (struct udp_priv *) poa->priv;
        uint32_t          fallback;
        uint32_t          overh;
#if defined(__linux__) && (defined(IP_MTU) || defined(IPV6_MTU))
        union udp_saddr   saddr;
        socklen_t         len;
        int               sock;
        int               mtu = 0;
#endif
        if (priv->af == AF_INET) {
                fallback = POA_UDP4_MTU;
                overh    = UDP_IP4_OVERH;
        } else {
                fallback = POA_UDP6_MTU;
                overh    = UDP_IP6_OVERH;
        }

        fallback -= UDP_HDR_LEN;
        if (fallback > UDP_MAX_PAYLOAD)
                fallback = UDP_MAX_PAYLOAD;

#if defined(__linux__) && (defined(IP_MTU) || defined(IPV6_MTU))

        addr_to_saddr(dst, &saddr);

        sock = socket(priv->af, SOCK_DGRAM, IPPROTO_UDP);
        if (sock < 0)
                return fallback;

        if (connect(sock, &saddr.sa, saddr_len(priv->af)) < 0)
                goto fallback;

        len = sizeof(mtu);

#if defined(IP_MTU)
        if (priv->af == AF_INET) {
                if (getsockopt(sock, IPPROTO_IP, IP_MTU, &mtu, &len) < 0)
                        goto fallback;
        }
#endif
#if defined(IPV6_MTU)
        if (priv->af == AF_INET6) {
                if (getsockopt(sock, IPPROTO_IPV6, IPV6_MTU, &mtu, &len) < 0)
                        goto fallback;
        }
#endif
        close(sock);

        if (mtu <= (int) (overh + UDP_HDR_LEN))
                return fallback;

        return MIN((uint32_t) mtu - overh - UDP_HDR_LEN, UDP_MAX_PAYLOAD);

 fallback:
        close(sock);
#else
        (void) dst;
        (void) overh;
#endif
        return fallback;
}

/* All flows on the PoA share the socket, so this is aggregate. */
static size_t udp_qlen(struct poa * poa)
{
#if defined(__linux__) && defined(SIOCOUTQ)
        struct udp_priv * priv = (struct udp_priv *) poa->priv;
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

/* The kernel keeps no per-socket drop count for UDP. */
static int udp_rib(struct poa * poa,
                   char *       buf,
                   size_t       len)
{
        struct udp_priv * priv = (struct udp_priv *) poa->priv;
        socklen_t         optlen;
        size_t            sndbuf = 0;
        size_t            rcvbuf = 0;
        int               val;
        int               size;

        optlen = sizeof(val);
        if (getsockopt(priv->s_fd, SOL_SOCKET, SO_SNDBUF, &val, &optlen) == 0)
                sndbuf = (size_t) val;

        optlen = sizeof(val);
        if (getsockopt(priv->s_fd, SOL_SOCKET, SO_RCVBUF, &val, &optlen) == 0)
                rcvbuf = (size_t) val;

        size = snprintf(buf, len,
                        "Socket sndbuf (bytes):     %zu\n"
                        "Socket rcvbuf (bytes):     %zu\n",
                        sndbuf, rcvbuf);
        if (size < 0 || (size_t) size >= len)
                return -1;

        return size;
}

/*
 * Asks the kernel which address it would send from: connect() does the
 * real route lookup and sends nothing, so this honours the default
 * route, metrics and policy rules alike.
 */
static int udp_src_addr(const struct poa_addr * dst,
                        struct poa_addr *       src)
{
        union udp_saddr saddr;
        socklen_t       len;
        int             af;
        int             fd;

        if (dst->type != POA_UDP4 && dst->type != POA_UDP6)
                return -EINVAL;

        af = dst->type == POA_UDP4 ? AF_INET : AF_INET6;

        addr_to_saddr(dst, &saddr);

        fd = socket(af, SOCK_DGRAM, IPPROTO_UDP);
        if (fd < 0)
                return -EIO;

        if (connect(fd, &saddr.sa, saddr_len(af)) < 0)
                goto fail;

        len = saddr_len(af);
        if (getsockname(fd, &saddr.sa, &len) < 0)
                goto fail;

        close(fd);

        saddr_to_addr(&saddr, src);

        return 0;

 fail:
        close(fd);

        return -EIO;
}

static void udp_spec(const struct poa * poa,
                     struct poa_spec *  spec)
{
        spec->type = poa->type;

        if (poa->type == POA_UDP4)
                spec->udp4 = poa->local.udp4;
        else
                spec->udp6 = poa->local.udp6;
}

static bool udp_has_id(const struct poa *      poa,
                       const struct poa_spec * spec)
{
        if (poa->type == POA_UDP4) {
                if (poa->local.udp4.port != spec->udp4.port)
                        return false;

                return memcmp(&poa->local.udp4.ip_addr,
                              &spec->udp4.ip_addr,
                              sizeof(spec->udp4.ip_addr)) == 0;
        }

        if (poa->local.udp6.port != spec->udp6.port)
                return false;

        return memcmp(&poa->local.udp6.ip_addr, &spec->udp6.ip_addr,
                      sizeof(spec->udp6.ip_addr)) == 0;
}

static bool udp_addr_is_any(const struct poa_addr * addr)
{
        static const struct in6_addr any6 = IN6ADDR_ANY_INIT;

        if (addr->type == POA_UDP4)
                return addr->udp4.ip_addr.s_addr == htonl(INADDR_ANY);

        return memcmp(&addr->udp6.ip_addr, &any6, sizeof(any6)) == 0;
}

/*
 * Our end of the flow: the IP the kernel would send to dst from. A
 * PoA bound to the wildcard is the catch-all and a failed probe
 * matches any. Ports are not compared: the probe's is ephemeral.
 */
static bool udp_match(const struct poa *      poa,
                      const struct poa_addr * dst)
{
        struct poa_addr src;

        if (udp_addr_is_any(&poa->local))
                return true;

        if (udp_src_addr(dst, &src) < 0)
                return true;

        if (poa->type == POA_UDP4)
                return memcmp(&poa->local.udp4.ip_addr,
                              &src.udp4.ip_addr,
                              sizeof(src.udp4.ip_addr)) == 0;

        return memcmp(&poa->local.udp6.ip_addr, &src.udp6.ip_addr,
                      sizeof(src.udp6.ip_addr)) == 0;
}

const struct poa_ops udp_poa_ops = {
        .poa_attach    = udp_attach,
        .poa_detach    = udp_detach,
        .poa_start     = udp_start,
        .poa_stop      = udp_stop,
        .poa_send      = udp_send,
        .poa_send_mgmt = udp_send_mgmt,
        .poa_mtu       = udp_mtu,
        .poa_qlen      = udp_qlen,
        .poa_rib       = udp_rib,
        .poa_spec      = udp_spec,
        .poa_has_id    = udp_has_id,
        .poa_match     = udp_match,
        .mpl           = POA_UDP_MPL
};
