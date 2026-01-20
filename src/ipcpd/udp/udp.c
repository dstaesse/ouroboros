/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * IPC process over UDP
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

#include "config.h"

#include <ouroboros/bitmap.h>
#include <ouroboros/endian.h>
#include <ouroboros/hash.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/pthread.h>

#include "ipcp.h"
#include "shim-data.h"

#include <string.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <fcntl.h>

#define FLOW_REQ                 1
#define FLOW_REPLY               2

#define OUR_HEADER_LEN           sizeof(uint32_t) /* adds eid */

#define IPCP_UDP_BUF_SIZE        IPCP_UDP_MAX_PACKET_SIZE
#define IPCP_UDP_MSG_SIZE        IPCP_UDP_MAX_PACKET_SIZE

#define DNS_TTL                  86400

#define SADDR                    ((struct sockaddr *) &udp_data.s_saddr)
#define SADDR_SIZE               (sizeof(udp_data.s_saddr))
#define LOCAL_IP                 (udp_data.s_saddr.sin_addr.s_addr)

#define MGMT_EID                 0
#define MGMT_FRAME_SIZE          (sizeof(struct mgmt_msg))
#define MGMT_FRAME_BUF_SIZE      2048

#ifdef __linux__
#define SENDTO_FLAGS MSG_CONFIRM
#else
#define SENDTO_FLAGS 0
#endif

/* Keep order for alignment. */
struct mgmt_msg {
        uint32_t eid;
        uint32_t s_eid;
        uint32_t d_eid;
        int32_t  response;
        uint64_t bandwidth;
        uint32_t delay;
        uint32_t loss;
        uint32_t ber;
        uint32_t max_gap;
        uint32_t timeout;
        uint8_t  code;
        /* QoS parameters from spec */
        uint8_t  availability;
        uint8_t  in_order;
} __attribute__((packed));

struct mgmt_frame {
        struct list_head  next;
        struct __SOCKADDR r_saddr;
        uint8_t           buf[MGMT_FRAME_BUF_SIZE];
        size_t            len;
};

/* UDP flow */
struct uf {
        int               d_eid;
        struct __SOCKADDR r_saddr;
};

struct {
        struct shim_data * shim_data;

        struct __ADDR      dns_addr;
        struct __SOCKADDR  s_saddr;
        int                s_fd;

        fset_t *           np1_flows;
        struct uf          fd_to_uf[SYS_MAX_FLOWS];
        pthread_rwlock_t   flows_lock;

        pthread_t          packet_writer[IPCP_UDP_WR_THR];
        pthread_t          packet_reader[IPCP_UDP_RD_THR];

        /* Handle mgmt frames in a different thread */
        pthread_t          mgmt_handler;
        pthread_mutex_t    mgmt_lock;
        pthread_cond_t     mgmt_cond;
        struct list_head   mgmt_frames;
} udp_data;

static const char * __inet_ntop(const struct __ADDR * addr,
                                char *                buf)
{
        return inet_ntop(__AF, addr, buf, __ADDRSTRLEN);
}

static int udp_data_init(void)
{
        int                i;
        pthread_condattr_t cattr;

        if (pthread_rwlock_init(&udp_data.flows_lock, NULL))
                goto fail_rwlock_init;

        if (pthread_condattr_init(&cattr))
                goto fail_condattr;
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&udp_data.mgmt_cond, &cattr))
                goto fail_mgmt_cond;

        if (pthread_mutex_init(&udp_data.mgmt_lock, NULL))
                goto fail_mgmt_lock;

        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                udp_data.fd_to_uf[i].d_eid = -1;

        udp_data.np1_flows = fset_create();
        if (udp_data.np1_flows == NULL)
                goto fail_fset;

        udp_data.shim_data = shim_data_create();
        if (udp_data.shim_data == NULL)
                goto fail_data;

        pthread_condattr_destroy(&cattr);

        list_head_init(&udp_data.mgmt_frames);

        return 0;

 fail_data:
        fset_destroy(udp_data.np1_flows);
 fail_fset:
        pthread_mutex_destroy(&udp_data.mgmt_lock);
 fail_mgmt_lock:
        pthread_cond_destroy(&udp_data.mgmt_cond);
 fail_mgmt_cond:
        pthread_condattr_destroy(&cattr);
 fail_condattr:
        pthread_rwlock_destroy(&udp_data.flows_lock);
 fail_rwlock_init:
        return -1;
}

static void udp_data_fini(void)
{
        shim_data_destroy(udp_data.shim_data);

        fset_destroy(udp_data.np1_flows);

        pthread_rwlock_destroy(&udp_data.flows_lock);
        pthread_cond_destroy(&udp_data.mgmt_cond);
        pthread_mutex_destroy(&udp_data.mgmt_lock);
}

static int udp_ipcp_port_alloc(const struct __SOCKADDR * r_saddr,
                               uint32_t                  s_eid,
                               const uint8_t *           dst,
                               qosspec_t                 qs,
                               const buffer_t *          data)
{
        uint8_t *         buf;
        struct mgmt_msg * msg;
        size_t            len;

        assert(data->len > 0 ? data->data != NULL : data->data == NULL);

        len = sizeof(*msg) + ipcp_dir_hash_len();

        buf = malloc(len + data->len);
        if (buf == NULL)
                return -1;

        memset(buf, 0, len + data->len);

        msg               = (struct mgmt_msg *) buf;
        msg->eid          = hton32(MGMT_EID);
        msg->code         = FLOW_REQ;
        msg->s_eid        = hton32(s_eid);
        msg->delay        = hton32(qs.delay);
        msg->bandwidth    = hton64(qs.bandwidth);
        msg->availability = qs.availability;
        msg->loss         = hton32(qs.loss);
        msg->ber          = hton32(qs.ber);
        msg->in_order     = qs.in_order;
        msg->max_gap      = hton32(qs.max_gap);
        msg->timeout      = hton32(qs.timeout);

        memcpy(msg + 1, dst, ipcp_dir_hash_len());
        if (data->len > 0)
                memcpy(buf + len, data->data, data->len);

        if (sendto(udp_data.s_fd, msg, len + data->len,
                   SENDTO_FLAGS,
                   (const struct sockaddr *) r_saddr, sizeof(*r_saddr)) < 0) {
                log_err("Failed to send flow allocation request: %s.",
                        strerror(errno));
                free(buf);
                return -1;
        }

        free(buf);

        return 0;
}

static int udp_ipcp_port_alloc_resp(const struct __SOCKADDR * r_saddr,
                                    uint32_t                  s_eid,
                                    uint32_t                  d_eid,
                                    int32_t                   response,
                                    const buffer_t *          data)
{
        struct mgmt_msg * msg;

        msg = malloc(sizeof(*msg) + data->len);
        if (msg == NULL)
                return -1;

        memset(msg, 0, sizeof(*msg) + data->len);

        msg->eid      = hton32(MGMT_EID);
        msg->code     = FLOW_REPLY;
        msg->s_eid    = hton32(s_eid);
        msg->d_eid    = hton32(d_eid);
        msg->response = hton32(response);

        if (data->len > 0)
                memcpy(msg + 1, data->data, data->len);

        if (sendto(udp_data.s_fd, msg, sizeof(*msg) + data->len,
                   SENDTO_FLAGS,
                   (const struct sockaddr *) r_saddr, sizeof(*r_saddr)) < 0 ) {
                free(msg);
                return -1;
        }

        free(msg);

        return 0;
}

static int udp_ipcp_port_req(struct __SOCKADDR * c_saddr,
                             int                 d_eid,
                             const uint8_t *     dst,
                             qosspec_t           qs,
                             const buffer_t *    data)
{
        int fd;

        fd = ipcp_wait_flow_req_arr(dst, qs, IPCP_UDP_MPL, data);
        if (fd < 0) {
                log_err("Could not get new flow from IRMd.");
                return -1;
        }

        pthread_rwlock_wrlock(&udp_data.flows_lock);

        udp_data.fd_to_uf[fd].r_saddr = *c_saddr;
        udp_data.fd_to_uf[fd].d_eid   = d_eid;

        pthread_rwlock_unlock(&udp_data.flows_lock);

        log_dbg("Pending allocation request, fd %d, remote eid %d.",
                fd, d_eid);

        return 0;
}

static int udp_ipcp_port_alloc_reply(const struct __SOCKADDR * saddr,
                                     uint32_t                  s_eid,
                                     uint32_t                  d_eid,
                                     int32_t                   response,
                                     const buffer_t *          data)
{
        time_t mpl = IPCP_UDP_MPL;

        pthread_rwlock_wrlock(&udp_data.flows_lock);

        if (memcmp(&udp_data.fd_to_uf[s_eid].r_saddr, saddr, sizeof(*saddr))) {
                char ipstr[__ADDRSTRLEN];
                pthread_rwlock_unlock(&udp_data.flows_lock);
                #ifdef BUILD_IPCP_UDP4
                __inet_ntop(&saddr->sin_addr, ipstr);
                #else
                __inet_ntop(&saddr->sin6_addr, ipstr);
                #endif
                log_err("Flow allocation reply for %u from wrong source %s.",
                        s_eid, ipstr);
                return -1;
        }

        if (response == 0)
                udp_data.fd_to_uf[s_eid].d_eid = d_eid;

        pthread_rwlock_unlock(&udp_data.flows_lock);

        if (ipcp_flow_alloc_reply(s_eid, response, mpl, data) < 0) {
                log_err("Failed to reply to flow allocation.");
                return -1;
        }

        log_dbg("Flow allocation completed on eids (%d, %d).",
                 s_eid, d_eid);

        return 0;
}

static int udp_ipcp_mgmt_frame(struct __SOCKADDR c_saddr,
                               const uint8_t *   buf,
                               size_t            len)
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

                data.len  = len - msg_len;
                data.data = (uint8_t *) buf + msg_len;


                qs.delay        = ntoh32(msg->delay);
                qs.bandwidth    = ntoh64(msg->bandwidth);
                qs.availability = msg->availability;
                qs.loss         = ntoh32(msg->loss);
                qs.ber          = ntoh32(msg->ber);
                qs.in_order     = msg->in_order;
                qs.max_gap      = ntoh32(msg->max_gap);
                qs.timeout      = ntoh32(msg->timeout);

                return udp_ipcp_port_req(&c_saddr, ntoh32(msg->s_eid),
                                         (uint8_t *) (msg + 1), qs,
                                          &data);
        case FLOW_REPLY:
                assert(len >= sizeof(*msg));

                data.len  = len - sizeof(*msg);
                data.data = (uint8_t *) buf + sizeof(*msg);

                return udp_ipcp_port_alloc_reply(&c_saddr,
                                                 ntoh32(msg->s_eid),
                                                 ntoh32(msg->d_eid),
                                                 ntoh32(msg->response),
                                                 &data);
        default:
                log_err("Unknown message received %d.", msg->code);
                return -1;
        }
}

static void * udp_ipcp_mgmt_handler(void * o)
{
        (void) o;

        pthread_cleanup_push(__cleanup_mutex_unlock, &udp_data.mgmt_lock);

        while (true) {
                struct mgmt_frame * frame;

                pthread_mutex_lock(&udp_data.mgmt_lock);

                while (list_is_empty(&udp_data.mgmt_frames))
                        pthread_cond_wait(&udp_data.mgmt_cond,
                                          &udp_data.mgmt_lock);

                frame = list_first_entry((&udp_data.mgmt_frames),
                                         struct mgmt_frame, next);
                assert(frame != NULL);
                list_del(&frame->next);

                pthread_mutex_unlock(&udp_data.mgmt_lock);

                udp_ipcp_mgmt_frame(frame->r_saddr, frame->buf, frame->len);

                free(frame);
        }

        pthread_cleanup_pop(false);

        return (void *) 0;
}

static void * udp_ipcp_packet_reader(void * o)
{
        uint8_t    buf[IPCP_UDP_MAX_PACKET_SIZE];
        uint8_t *  data;
        ssize_t    n;
        uint32_t   eid;
        uint32_t * eid_p;

        (void) o;

        ipcp_lock_to_core();

        data  = buf + sizeof(uint32_t);
        eid_p = (uint32_t *) buf;

        while (true) {
                struct mgmt_frame *  frame;
                struct __SOCKADDR    r_saddr;
                socklen_t            len;
                struct ssm_pk_buff * spb;
                uint8_t *            head;

                len = sizeof(r_saddr);

                n = recvfrom(udp_data.s_fd, buf, IPCP_UDP_MAX_PACKET_SIZE, 0,
                             (struct sockaddr *) &r_saddr, &len);
                if (n < 0)
                        continue;

                if (n == 0)
                        log_dbg("Got a 0 frame.");

                if ((size_t) n < sizeof(eid)) {
                        log_dbg("Dropped bad frame.");
                        continue;
                }

                eid = ntoh32(*eid_p);

                /* pass onto mgmt queue */
                if (eid == MGMT_EID) {
                        if ((size_t) n < MGMT_FRAME_SIZE) {
                                log_warn("Dropped runt mgmt frame.");
                                continue;
                        }

                        frame = malloc(sizeof(*frame));
                        if (frame == NULL)
                                continue;

                        memcpy(frame->buf, buf, n);
                        memcpy(&frame->r_saddr, &r_saddr, sizeof(r_saddr));
                        frame->len = n;

                        pthread_mutex_lock(&udp_data.mgmt_lock);
                        list_add(&frame->next, &udp_data.mgmt_frames);
                        pthread_cond_signal(&udp_data.mgmt_cond);
                        pthread_mutex_unlock(&udp_data.mgmt_lock);
                        continue;
                }

                n-= sizeof(eid);

                if (ipcp_spb_reserve(&spb, n))
                        continue;

                head = ssm_pk_buff_head(spb);
                memcpy(head, data, n);
                if (np1_flow_write(eid, spb) < 0)
                        ipcp_spb_release(spb);
        }

        return (void *) 0;
}

static void cleanup_fqueue(void * fq)
{
        fqueue_destroy((fqueue_t *) fq);
}

static void cleanup_spb(void * spb)
{
        ipcp_spb_release((struct ssm_pk_buff *) spb);
}

static void * udp_ipcp_packet_writer(void * o)
{
        fqueue_t * fq;

        fq = fqueue_create();
        if (fq == NULL)
                return (void *) -1;

        (void) o;

        ipcp_lock_to_core();

        pthread_cleanup_push(cleanup_fqueue, fq);

        while (true) {
                struct __SOCKADDR saddr;
                int               eid;
                int               fd;
                fevent(udp_data.np1_flows, fq, NULL);
                while ((fd = fqueue_next(fq)) >= 0) {
                        struct ssm_pk_buff * spb;
                        uint8_t *            buf;
                        uint16_t             len;

                        if (fqueue_type(fq) != FLOW_PKT)
                                continue;

                        if (np1_flow_read(fd, &spb)) {
                                log_dbg("Bad read from fd %d.", fd);
                                continue;
                        }

                        len = ssm_pk_buff_len(spb);
                        if (len > IPCP_UDP_MAX_PACKET_SIZE) {
                                log_dbg("Packet length exceeds MTU.");
                                ipcp_spb_release(spb);
                                continue;
                        }

                        buf = ssm_pk_buff_head_alloc(spb, OUR_HEADER_LEN);
                        if (buf == NULL) {
                                log_dbg("Failed to allocate header.");
                                ipcp_spb_release(spb);
                                continue;
                        }

                        pthread_rwlock_rdlock(&udp_data.flows_lock);

                        eid = hton32(udp_data.fd_to_uf[fd].d_eid);
                        saddr = udp_data.fd_to_uf[fd].r_saddr;

                        pthread_rwlock_unlock(&udp_data.flows_lock);

                        memcpy(buf, &eid, sizeof(eid));

                        pthread_cleanup_push(cleanup_spb, spb);

                        if (sendto(udp_data.s_fd, buf, len + OUR_HEADER_LEN,
                                   SENDTO_FLAGS,
                                   (const struct sockaddr *) &saddr,
                                   sizeof(saddr)) < 0)
                                log_err("Failed to send packet.");

                        pthread_cleanup_pop(true);
                }
        }

        pthread_cleanup_pop(true);

        return (void *) 1;
}

static bool is_addr_specified(const struct __ADDR * addr)
{
#ifdef BUILD_IPCP_UDP4
        return addr->s_addr != 0;
#else
        return !IN6_IS_ADDR_UNSPECIFIED(addr);
#endif
}

static int udp_ipcp_bootstrap(struct ipcp_config * conf)
{
        char ipstr[__ADDRSTRLEN];
        char dnsstr[__ADDRSTRLEN];
        int  i = 1;
#ifdef BUILD_IPCP_UDP4
        struct udp4_config * udp;
        udp = &conf->udp4;
#else
        struct udp6_config * udp;
        udp = &conf->udp6;
#endif

        assert(conf != NULL);
        assert(conf->type == THIS_TYPE);
        assert(conf->layer_info.dir_hash_algo == (enum pol_dir_hash) HASH_MD5);

        if (__inet_ntop(&udp->ip_addr, ipstr) == NULL) {
                log_err("Failed to convert IP address.");
                return -1;
        }

        if (is_addr_specified(&udp->dns_addr)) {
                if (__inet_ntop(&udp->dns_addr, dnsstr) == NULL) {
                        log_err("Failed to convert DNS address.");
                        return -1;
                }
#ifndef HAVE_DDNS
                log_warn("DNS disabled at compile time, address ignored.");
#endif
        } else {
                strcpy(dnsstr, "not set");
        }

        /* UDP listen server */
        udp_data.s_fd = socket(__AF, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_data.s_fd < 0) {
                log_err("Can't create socket: %s", strerror(errno));
                goto fail_socket;
        }

        memset((char *) &udp_data.s_saddr, 0, sizeof(udp_data.s_saddr));
#ifdef BUILD_IPCP_UDP4
        udp_data.s_saddr.sin_family  = AF_INET;
        udp_data.s_saddr.sin_addr   = udp->ip_addr;
        udp_data.s_saddr.sin_port   = htons(udp->port);
#else
        udp_data.s_saddr.sin6_family = AF_INET6;
        udp_data.s_saddr.sin6_addr   = udp->ip_addr;
        udp_data.s_saddr.sin6_port   = htons(udp->port);
#endif
        if (bind(udp_data.s_fd, SADDR, SADDR_SIZE) < 0) {
                log_err("Couldn't bind to %s:%d. %s.",
                        ipstr, udp->port, strerror(errno));
                goto fail_bind;
        }

        udp_data.dns_addr = udp->dns_addr;

        if (pthread_create(&udp_data.mgmt_handler, NULL,
                           udp_ipcp_mgmt_handler, NULL)) {
                log_err("Failed to create management thread.");
                goto fail_bind;
        }

        for (i = 0; i < IPCP_UDP_RD_THR; ++i) {
                if (pthread_create(&udp_data.packet_reader[i], NULL,
                                   udp_ipcp_packet_reader, NULL)) {
                        log_err("Failed to create reader thread.");
                        goto fail_packet_reader;
                }
        }

        for (i = 0; i < IPCP_UDP_WR_THR; ++i) {
                if (pthread_create(&udp_data.packet_writer[i], NULL,
                        udp_ipcp_packet_writer, NULL)) {
                        log_err("Failed to create writer thread.");
                        goto fail_packet_writer;
                }
        }

        log_dbg("Bootstrapped " TYPE_STR " with pid %d.", getpid());
        log_dbg("Bound to IP address %s.", ipstr);
        log_dbg("Using port %u.", udp->port);
        if (is_addr_specified(&udp_data.dns_addr))
                log_dbg("DNS server address is %s.", dnsstr);
        else
                log_dbg("DNS server not in use.");

        return 0;

 fail_packet_writer:
        while (i-- > 0) {
                pthread_cancel(udp_data.packet_writer[i]);
                pthread_join(udp_data.packet_writer[i], NULL);
        }
        i = IPCP_UDP_RD_THR;
 fail_packet_reader:
        while (i-- > 0) {
                pthread_cancel(udp_data.packet_reader[i]);
                pthread_join(udp_data.packet_reader[i], NULL);
        }
        pthread_cancel(udp_data.mgmt_handler);
        pthread_join(udp_data.mgmt_handler, NULL);
 fail_bind:
        close(udp_data.s_fd);
 fail_socket:
        return -1;
}

#ifdef HAVE_DDNS
/* FIXME: Dependency on nsupdate to be removed in the end */
/* NOTE: Disgusted with this crap */
static int ddns_send(char * cmd)
{
        pid_t pid;
        int   wstatus;
        int   pipe_fd[2];
        char * argv[] = {NSUPDATE_EXEC, 0};
        char * envp[] = {0};

        if (pipe(pipe_fd)) {
                log_err("Failed to create pipe: %s.", strerror(errno));
                return -1;
        }

        pid = fork();
        if (pid == -1) {
                log_err("Failed to fork: %s.", strerror(errno));
                close(pipe_fd[0]);
                close(pipe_fd[1]);
                return -1;
        }

        if (pid == 0) {
                close(pipe_fd[1]);
                dup2(pipe_fd[0], 0);
                execve(argv[0], &argv[0], envp);
                log_err("Failed to execute: %s", strerror(errno));
                exit(1);
        }

        close(pipe_fd[0]);

        if (write(pipe_fd[1], cmd, strlen(cmd)) == -1) {
                log_err("Failed to communicate with nsupdate: %s.",
                        strerror(errno));
                close(pipe_fd[1]);
                return -1;
        }

        waitpid(pid, &wstatus, 0);
        if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0)
                log_dbg("Succesfully communicated with DNS server.");
        else
                log_err("Failed to register with DNS server.");

        close(pipe_fd[1]);

        return 0;
}

static struct __ADDR ddns_resolve(char *        name,
                                  struct __ADDR dns_addr)
{
        pid_t          pid      = -1;
        int            wstatus;
        int            pipe_fd[2];
        char           dnsstr[__ADDRSTRLEN];
        char           buf[IPCP_UDP_BUF_SIZE];
        ssize_t        count    = 0;
        char *         substr   = NULL;
        char *         substr2  = NULL;
        char *         addr_str = "Address:";
        struct __ADDR  ip_addr  = __ADDR_ANY_INIT;

        if (__inet_ntop(&dns_addr, dnsstr) == NULL)
                return ip_addr;

        if (pipe(pipe_fd)) {
                log_err("Failed to create pipe: %s.", strerror(errno));
                return ip_addr;
        }

        pid = fork();
        if (pid == -1) {
                log_err("Failed to fork: %s.", strerror(errno));
                close(pipe_fd[0]);
                close(pipe_fd[1]);
                return ip_addr;
        }

        if (pid == 0) {
                char * argv[] = {NSLOOKUP_EXEC, name, dnsstr, 0};
                char * envp[] = {0};

                close(pipe_fd[0]);
                dup2(pipe_fd[1], 1);
                execve(argv[0], &argv[0], envp);
                log_err("Failed to execute: %s", strerror(errno));
                exit(1);
        }

        close(pipe_fd[1]);

        count = read(pipe_fd[0], buf, IPCP_UDP_BUF_SIZE - 1);
        if (count <= 0) {
                log_err("Failed to communicate with nslookup.");
                close(pipe_fd[0]);
                return ip_addr;
        }

        close(pipe_fd[0]);

        waitpid(pid, &wstatus, 0);
        if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0 &&
            count != IPCP_UDP_BUF_SIZE - 1)
                log_dbg("Succesfully communicated with nslookup.");
        else
                log_err("Failed to resolve DNS address.");

        buf[count] = '\0';
        substr = strtok(buf, "\n");
        while (substr != NULL) {
                substr2 = substr;
                substr = strtok(NULL, "\n");
        }

        if (substr2 == NULL || strstr(substr2, addr_str) == NULL) {
                log_err("Failed to resolve DNS address.");
                return ip_addr;
        }

        if (inet_pton(__AF, substr2 + strlen(addr_str) + 1, &ip_addr) != 1) {
                log_err("Failed to resolve DNS address.");
                assert(!is_addr_specified(&ip_addr));
                return ip_addr;
        }

        return ip_addr;
}
#endif

static int udp_ipcp_reg(const uint8_t * hash)
{
#ifdef HAVE_DDNS
        char          ipstr[__ADDRSTRLEN];
        char          dnsstr[__ADDRSTRLEN];
        char          cmd[1000];
        struct __ADDR dns_addr;
        struct __ADDR ip_addr;
#endif
        char *   hashstr;

        hashstr = malloc(ipcp_dir_hash_strlen() + 1);
        if (hashstr == NULL) {
                log_err("Failed to malloc hashstr.");
                return -1;
        }

        assert(hash);

        ipcp_hash_str(hashstr, hash);

        if (shim_data_reg_add_entry(udp_data.shim_data, hash)) {
                log_err("Failed to add " HASH_FMT32 " to local registry.",
                        HASH_VAL32(hash));
                free(hashstr);
                return -1;
        }

#ifdef HAVE_DDNS
        /* register application with DNS server */

        dns_addr = udp_data.dns_addr;

        if (is_addr_specified(&dns_addr)) {
#ifdef BUILD_IPCP_UDP4
                ip_addr = udp_data.s_saddr.sin_addr;
#else
                ip_addr = udp_data.s_saddr.sin6_addr;
#endif
                if (__inet_ntop(&ip_addr, ipstr) == NULL) {
                        log_err("Failed to convert IP address to string.");
                        free(hashstr);
                        return -1;
                }

                if (__inet_ntop(&dns_addr, dnsstr) == NULL) {
                        log_err("Failed to convert DNS address to string.");
                        free(hashstr);
                        return -1;
                }

                sprintf(cmd, "server %s\nupdate add %s %d A %s\nsend\nquit\n",
                        dnsstr, hashstr, DNS_TTL, ipstr);

                if (ddns_send(cmd)) {
                        log_err("Failed to send DDNS message.");
                        shim_data_reg_del_entry(udp_data.shim_data, hash);
                        free(hashstr);
                        return -1;
                }
        }
#endif
        free(hashstr);

        return 0;
}

static int udp_ipcp_unreg(const uint8_t * hash)
{
#ifdef HAVE_DDNS
        char          dnsstr[__ADDRSTRLEN];
        /* max DNS name length + max IP length + max command length */
        char          cmd[100];
        struct __ADDR dns_addr;
#endif
        char * hashstr;

        assert(hash);

        hashstr = malloc(ipcp_dir_hash_strlen() + 1);
        if (hashstr == NULL) {
                log_err("Failed to malloc hashstr.");
                return -1;
        }

        ipcp_hash_str(hashstr, hash);

#ifdef HAVE_DDNS
        /* unregister application with DNS server */

        dns_addr = udp_data.dns_addr;

        if (is_addr_specified(&dns_addr)) {
                if (__inet_ntop(&dns_addr, dnsstr) == NULL) {
                        log_err("Failed to convert DNS address to string.");
                        free(hashstr);
                        return -1;
                }
                sprintf(cmd, "server %s\nupdate delete %s A\nsend\nquit\n",
                        dnsstr, hashstr);

                ddns_send(cmd);
        }
#endif

        shim_data_reg_del_entry(udp_data.shim_data, hash);

        free(hashstr);

        return 0;
}

static int udp_ipcp_query(const uint8_t * hash)
{
        struct addr        addr = {};
        char *             hashstr;
        struct addrinfo    hints;
        struct addrinfo  * ai;
#ifdef HAVE_DDNS
        struct __ADDR      dns_addr = __ADDR_ANY_INIT;
        struct __ADDR      ip_addr = __ADDR_ANY_INIT;
#endif
        assert(hash);

        hashstr = malloc(ipcp_dir_hash_strlen() + 1);
        if (hashstr == NULL) {
                log_err("Failed to malloc hashstr.");
                return -ENOMEM;
        }

        ipcp_hash_str(hashstr, hash);

        if (shim_data_dir_has(udp_data.shim_data, hash)) {
                free(hashstr);
                return 0;
        }

#ifdef HAVE_DDNS
        dns_addr = udp_data.dns_addr;

        if (is_addr_specified(&dns_addr)) {
                ip_addr = ddns_resolve(hashstr, dns_addr);
                if (!is_addr_specified(&ip_addr)) {
                        log_err("Could not resolve %s.", hashstr);
                        free(hashstr);
                        return -1;
                }
        } else {
#endif
                memset(&hints, 0, sizeof(hints));

                hints.ai_family   = __AF;
                if (getaddrinfo(hashstr, NULL, &hints, &ai) != 0) {
                        log_err("Could not resolve %s: %s.", hashstr,
                                gai_strerror(errno));
                        free(hashstr);
                        return -1;
                }

                if (ai->ai_family != __AF) {
                        log_err("Wrong addres family for %s.", hashstr);
                        freeaddrinfo(ai);
                        free(hashstr);
                        return -1;
                }

        #ifdef BUILD_IPCP_UDP4
                addr.ip4 = ((struct sockaddr_in *) (ai->ai_addr))->sin_addr;
        #else
                addr.ip6 = ((struct sockaddr_in6 *) (ai->ai_addr))->sin6_addr;
        #endif
                freeaddrinfo(ai);
#ifdef HAVE_DDNS
        }
#endif
        if (shim_data_dir_add_entry(udp_data.shim_data, hash, addr)) {
                log_err("Failed to add directory entry.");
                free(hashstr);
                return -1;
        }

        free(hashstr);

        return 0;
}

static int udp_ipcp_flow_alloc(int              fd,
                               const uint8_t *  dst,
                               qosspec_t        qs,
                               const buffer_t * data)
{
        struct __SOCKADDR r_saddr; /* Server address */
        struct __ADDR     ip_addr;
        struct addr       addr;
        char              ipstr[__ADDRSTRLEN];

        (void) qs;

        assert(dst);

        if (!shim_data_dir_has(udp_data.shim_data, dst)) {
                log_err("Could not resolve destination.");
                return -1;
        }

        addr = shim_data_dir_get_addr(udp_data.shim_data, dst);
#ifdef BUILD_IPCP_UDP4
        ip_addr = addr.ip4;
#else
        ip_addr = addr.ip6;
#endif
        if (__inet_ntop(&ip_addr, ipstr) == NULL) {
                log_err("Could not convert IP address.");
                return -1;
        }

        log_dbg("Destination " HASH_FMT32 " resolved at IP %s.",
                HASH_VAL32(dst), ipstr);

        memset((char *) &r_saddr, 0, sizeof(r_saddr));
#ifdef BUILD_IPCP_UDP4
        r_saddr.sin_family = AF_INET;
        r_saddr.sin_addr   = addr.ip4;
        r_saddr.sin_port   = udp_data.s_saddr.sin_port;
#else
        r_saddr.sin6_family = AF_INET6;
        r_saddr.sin6_addr   = addr.ip6;
        r_saddr.sin6_port   = udp_data.s_saddr.sin6_port;
#endif

        if (udp_ipcp_port_alloc(&r_saddr, fd, dst, qs, data) < 0) {
                log_err("Could not allocate port.");
                return -1;
        }

        pthread_rwlock_wrlock(&udp_data.flows_lock);

        udp_data.fd_to_uf[fd].d_eid   = -1;
        udp_data.fd_to_uf[fd].r_saddr = r_saddr;

        pthread_rwlock_unlock(&udp_data.flows_lock);

        fset_add(udp_data.np1_flows, fd);

        return 0;
}

static int udp_ipcp_flow_alloc_resp(int              fd,
                                    int              resp,
                                    const buffer_t * data)
{
        struct __SOCKADDR saddr;
        int               d_eid;

        if (ipcp_wait_flow_resp(fd) < 0) {
                log_err("Failed to wait for flow response.");
                return -1;
        }

        pthread_rwlock_rdlock(&udp_data.flows_lock);

        saddr = udp_data.fd_to_uf[fd].r_saddr;
        d_eid = udp_data.fd_to_uf[fd].d_eid;

        pthread_rwlock_unlock(&udp_data.flows_lock);

        if (udp_ipcp_port_alloc_resp(&saddr, d_eid, fd, resp, data) < 0) {
                fset_del(udp_data.np1_flows, fd);
                log_err("Failed to respond to flow request.");
                return -1;
        }

        fset_add(udp_data.np1_flows, fd);

        return 0;
}

static int udp_ipcp_flow_dealloc(int fd)
{
        ipcp_flow_fini(fd);

        fset_del(udp_data.np1_flows, fd);

        pthread_rwlock_wrlock(&udp_data.flows_lock);

        udp_data.fd_to_uf[fd].d_eid = -1;
        memset(&udp_data.fd_to_uf[fd].r_saddr, 0, SADDR_SIZE);

        pthread_rwlock_unlock(&udp_data.flows_lock);

        ipcp_flow_dealloc(fd);

        return 0;
}

static struct ipcp_ops udp_ops = {
        .ipcp_bootstrap       = udp_ipcp_bootstrap,
        .ipcp_enroll          = NULL,
        .ipcp_connect         = NULL,
        .ipcp_disconnect      = NULL,
        .ipcp_reg             = udp_ipcp_reg,
        .ipcp_unreg           = udp_ipcp_unreg,
        .ipcp_query           = udp_ipcp_query,
        .ipcp_flow_alloc      = udp_ipcp_flow_alloc,
        .ipcp_flow_join       = NULL,
        .ipcp_flow_alloc_resp = udp_ipcp_flow_alloc_resp,
        .ipcp_flow_dealloc    = udp_ipcp_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        int i;


        if (udp_data_init() < 0) {
                log_err("Failed to init udp data.");
                goto fail_data_init;
        }

        if (ipcp_init(argc, argv, &udp_ops, THIS_TYPE) < 0) {
                log_err("Failed to initialize IPCP.");
                goto fail_init;
        }

        if (ipcp_start() < 0) {
                log_err("Failed to start IPCP.");
                goto fail_start;
        }

        ipcp_sigwait();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                for (i = 0; i < IPCP_UDP_WR_THR; ++i)
                        pthread_cancel(udp_data.packet_writer[i]);
                for (i = 0; i < IPCP_UDP_RD_THR; ++i)
                        pthread_cancel(udp_data.packet_reader[i]);
                pthread_cancel(udp_data.mgmt_handler);

                for (i = 0; i < IPCP_UDP_WR_THR; ++i)
                        pthread_join(udp_data.packet_writer[i], NULL);
                for (i = 0; i < IPCP_UDP_RD_THR; ++i)
                        pthread_join(udp_data.packet_reader[i], NULL);
                pthread_join(udp_data.mgmt_handler, NULL);
                close(udp_data.s_fd);
        }

        ipcp_stop();

        ipcp_fini();

        udp_data_fini();

        exit(EXIT_SUCCESS);

 fail_start:
        ipcp_fini();
 fail_init:
        udp_data_fini();
 fail_data_init:
        exit(EXIT_FAILURE);
}
