/*
 * Ouroboros - Copyright (C) 2016 - 2019
 *
 * IPC process over UDP
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200112L
#endif

#include "config.h"

#define OUROBOROS_PREFIX "ipcpd/udp"

#include <ouroboros/bitmap.h>
#include <ouroboros/hash.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>

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
#include <pthread.h>
#include <sys/wait.h>
#include <fcntl.h>

#define FLOW_REQ                 1
#define FLOW_REPLY               2

#define THIS_TYPE                IPCP_UDP
#define IPCP_UDP_MAX_PACKET_SIZE 8980
#define OUR_HEADER_LEN           sizeof(uint32_t) /* adds eid */

#define IPCP_UDP_BUF_SIZE        256
#define IPCP_UDP_MSG_SIZE        256
#define DNS_TTL                  86400
#define FD_UPDATE_TIMEOUT        100 /* microseconds */

#define SERV_PORT                udp_data.s_saddr.sin_port;
#define SERV_SADDR               ((struct sockaddr *) &udp_data.s_saddr)
#define CLNT_SADDR               ((struct sockaddr *) &udp_data.c_saddr)
#define SERV_SADDR_SIZE          (sizeof(udp_data.s_saddr))
#define LOCAL_IP                 (udp_data.s_saddr.sin_addr.s_addr)

#define MGMT_EID                 0
#define MGMT_FRAME_SIZE          512

/* Keep order for alignment. */
struct mgmt_msg {
        uint32_t eid;
        uint32_t s_eid;
        uint32_t d_eid;
        uint8_t  code;
        int8_t   response;
        /* QoS parameters from spec */
        uint8_t  availability;
        uint8_t  in_order;
        uint64_t bandwidth;
        uint32_t delay;
        uint32_t loss;
        uint32_t ber;
        uint32_t max_gap;
        uint16_t cypher_s;
} __attribute__((packed));

struct mgmt_frame {
        struct list_head   next;
        struct sockaddr_in r_saddr;
        uint8_t            buf[MGMT_FRAME_SIZE];
};

/* UDP flow */
struct uf {
        int d_eid;
        /* IP details are stored through connect(). */
        int skfd;
};

struct {
        struct shim_data * shim_data;

        uint32_t           ip_addr;
        uint32_t           dns_addr;
        /* server socket */
        struct sockaddr_in s_saddr;
        int                s_fd;
        /* client port */
        int                clt_port;

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

static int udp_data_init(void)
{
        int i;

        if (pthread_rwlock_init(&udp_data.flows_lock, NULL))
                goto fail_rwlock_init;

        if (pthread_cond_init(&udp_data.mgmt_cond, NULL))
                goto fail_mgmt_cond;

        if (pthread_mutex_init(&udp_data.mgmt_lock, NULL))
                goto fail_mgmt_lock;

        for (i = 0; i < SYS_MAX_FLOWS; ++i) {
                udp_data.fd_to_uf[i].skfd  = -1;
                udp_data.fd_to_uf[i].d_eid = -1;
        }

        udp_data.np1_flows = fset_create();
        if (udp_data.np1_flows == NULL)
                goto fail_fset;

        udp_data.shim_data = shim_data_create();
        if (udp_data.shim_data == NULL)
                goto fail_data;

        list_head_init(&udp_data.mgmt_frames);

        return 0;
 fail_data:
        fset_destroy(udp_data.np1_flows);
 fail_fset:
        pthread_mutex_destroy(&udp_data.mgmt_lock);
 fail_mgmt_lock:
        pthread_cond_destroy(&udp_data.mgmt_cond);
 fail_mgmt_cond:
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

static int ipcp_udp_port_alloc(int             skfd,
                               uint32_t        s_eid,
                               const uint8_t * dst,
                               qosspec_t       qs)
{
        uint8_t *         buf;
        struct mgmt_msg * msg;
        size_t            len;

        len = sizeof(*msg) + ipcp_dir_hash_len();

        buf = malloc(len);
        if (buf == NULL)
                return -1;

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
        msg->cypher_s     = hton16(qs.cypher_s);

        memcpy(msg + 1, dst, ipcp_dir_hash_len());

        if (write(skfd, msg, len) < 0) {
                free(buf);
                return -1;
        }

        free(buf);

        return 0;
}

static int ipcp_udp_port_alloc_resp(int      skfd,
                                    uint32_t s_eid,
                                    uint32_t d_eid,
                                    int8_t   response)
{
        struct mgmt_msg *  msg;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                return -1;

        msg->eid      = hton32(MGMT_EID);
        msg->code     = FLOW_REPLY;
        msg->s_eid    = hton32(s_eid);
        msg->d_eid    = hton32(d_eid);
        msg->response = response;

        if (write(skfd, msg, sizeof(*msg)) < 0) {
                free(msg);
                return -1;
        }

        free(msg);

        return 0;
}

static int ipcp_udp_port_req(struct sockaddr_in * c_saddr,
                             int                  d_eid,
                             const uint8_t *      dst,
                             qosspec_t            qs)
{
        struct timespec ts        = {0, FD_UPDATE_TIMEOUT * 1000};
        struct timespec abstime;
        int             skfd;
        int             fd;

        skfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (skfd < 0) {
                log_err("Could not create UDP socket.");
                return -1;
        }

        /* Remote listens on server port. Mod of c_saddr allowed. */
        c_saddr->sin_port = udp_data.s_saddr.sin_port;

        /* Connect stores the remote address in the file descriptor. */
        if (connect(skfd, (struct sockaddr *) c_saddr, sizeof(*c_saddr)) < 0) {
                log_err("Could not connect to remote UDP client.");
                close(skfd);
                return -1;
        }

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        pthread_mutex_lock(&ipcpi.alloc_lock);

        while (ipcpi.alloc_id != -1 && ipcp_get_state() == IPCP_OPERATIONAL) {
                ts_add(&abstime, &ts, &abstime);
                pthread_cond_timedwait(&ipcpi.alloc_cond, &ipcpi.alloc_lock,
                                       &abstime);
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_dbg("Won't allocate over non-operational IPCP.");
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                close(skfd);
                return -1;
        }

        /* reply to IRM */
        fd = ipcp_flow_req_arr(dst, ipcp_dir_hash_len(), qs);
        if (fd < 0) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                log_err("Could not get new flow from IRMd.");
                close(skfd);
                return -1;
        }

        pthread_rwlock_wrlock(&udp_data.flows_lock);

        udp_data.fd_to_uf[fd].skfd  = skfd;
        udp_data.fd_to_uf[fd].d_eid = d_eid;

        pthread_rwlock_unlock(&udp_data.flows_lock);

        ipcpi.alloc_id = fd;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

        log_dbg("Pending allocation request, fd %d, remote eid %d.",
                fd, d_eid);

        return 0;
}

static int ipcp_udp_port_alloc_reply(uint32_t s_eid,
                                     uint32_t d_eid,
                                     int8_t   response)
{
        struct sockaddr_in t_saddr;
        socklen_t          t_saddr_len;
        int                ret         = 0;
        int                skfd        = -1;

        t_saddr_len = sizeof(t_saddr);

        pthread_rwlock_wrlock(&udp_data.flows_lock);

        skfd = udp_data.fd_to_uf[s_eid].skfd;
        if (skfd < 0) {
                pthread_rwlock_unlock(&udp_data.flows_lock);
                log_err("Got reply for unknown UDP eid: %u.", s_eid);
                return -1;
        }

        udp_data.fd_to_uf[s_eid].d_eid = d_eid;

        pthread_rwlock_unlock(&udp_data.flows_lock);

        if (getpeername(skfd, (struct sockaddr *) &t_saddr, &t_saddr_len) < 0) {
                log_dbg("Flow with fd %d has no peer.", s_eid);
                close(skfd);
                return -1;
        }

        if (connect(skfd, (struct sockaddr *) &t_saddr, sizeof(t_saddr)) < 0) {
                log_dbg("Could not connect flow to remote.");
                close(skfd);
                return -1;
        }

        if (ipcp_flow_alloc_reply(s_eid, response) < 0) {
                log_dbg("Failed to reply to flow allocation.");
                return -1;
        }

        log_dbg("Flow allocation completed on eids (%d, %d).",
                 s_eid, d_eid);

        return ret;
}

static int ipcp_udp_mgmt_frame(const uint8_t *    buf,
                               struct sockaddr_in c_saddr)
{
        struct mgmt_msg * msg;
        qosspec_t         qs;

        msg = (struct mgmt_msg *) buf;

        switch (msg->code) {
        case FLOW_REQ:
                qs.delay        = ntoh32(msg->delay);
                qs.bandwidth    = ntoh64(msg->bandwidth);
                qs.availability = msg->availability;
                qs.loss         = ntoh32(msg->loss);
                qs.ber          = ntoh32(msg->ber);
                qs.in_order     = msg->in_order;
                qs.max_gap      = ntoh32(msg->max_gap);
                qs.cypher_s     = ntoh16(msg->cypher_s);

                return ipcp_udp_port_req(&c_saddr, ntoh32(msg->s_eid),
                                         (uint8_t *) (msg + 1), qs);
        case FLOW_REPLY:
                return ipcp_udp_port_alloc_reply(ntoh32(msg->s_eid),
                                                 ntoh32(msg->d_eid),
                                                 msg->response);
        default:
                log_err("Unknown message received %d.", msg->code);
                return -1;
        }
}

static void * ipcp_udp_mgmt_handler(void * o)
{
        (void) o;

        pthread_cleanup_push((void (*)(void *)) pthread_mutex_unlock,
                             (void *) &udp_data.mgmt_lock);

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

                ipcp_udp_mgmt_frame(frame->buf, frame->r_saddr);

                free(frame);
        }

        pthread_cleanup_pop(false);

        return (void *) 0;
}

static void * ipcp_udp_packet_reader(void * o)
{
        uint8_t    buf[IPCP_UDP_MAX_PACKET_SIZE];
        uint8_t *  data;
        ssize_t    n;
        uint32_t   eid;
        uint32_t * eid_p;

        (void) o;

        data  = buf + sizeof(uint32_t);
        eid_p = (uint32_t *) buf;

        while (true) {
                struct mgmt_frame * frame;
                struct sockaddr_in  r_saddr;
                socklen_t           len;

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
                        if (n > IPCP_UDP_MSG_SIZE) {
                                log_warn("Dropped oversize management frame.");
                                continue;
                        }

                        frame = malloc(sizeof(*frame));
                        if (frame == NULL)
                                continue;

                        memcpy(frame->buf, buf, n);
                        memcpy(&frame->r_saddr, &r_saddr, sizeof(r_saddr));

                        pthread_mutex_lock(&udp_data.mgmt_lock);
                        list_add(&frame->next, &udp_data.mgmt_frames);
                        pthread_cond_signal(&udp_data.mgmt_cond);
                        pthread_mutex_unlock(&udp_data.mgmt_lock);
                        continue;
                }

                flow_write(eid, data, n - sizeof(eid));
        }

        return 0;
}

static void cleanup_writer(void * o)
{
        fqueue_destroy((fqueue_t *) o);
}

static void * ipcp_udp_packet_writer(void * o)
{
        fqueue_t * fq;

        fq = fqueue_create();
        if (fq == NULL)
                return (void *) -1;

        (void) o;

        ipcp_lock_to_core();

        pthread_cleanup_push(cleanup_writer, fq);

        while (true) {
                int fd;
                int eid;
                fevent(udp_data.np1_flows, fq, NULL);
                while ((fd = fqueue_next(fq)) >= 0) {
                        struct shm_du_buff * sdb;
                        uint8_t *            buf;
                        uint16_t             len;
                        if (ipcp_flow_read(fd, &sdb)) {
                                log_dbg("Bad read from fd %d.", fd);
                                continue;
                        }

                        len = shm_du_buff_tail(sdb) - shm_du_buff_head(sdb);
                        if (len > IPCP_UDP_MAX_PACKET_SIZE) {
                                log_dbg("Packet length exceeds MTU.");
                                ipcp_sdb_release(sdb);
                                continue;
                        }

                        buf = shm_du_buff_head_alloc(sdb, OUR_HEADER_LEN);
                        if (buf == NULL) {
                                log_dbg("Failed to allocate header.");
                                ipcp_sdb_release(sdb);
                                continue;
                        }

                        pthread_rwlock_rdlock(&udp_data.flows_lock);

                        eid = hton32(udp_data.fd_to_uf[fd].d_eid);
                        fd = udp_data.fd_to_uf[fd].skfd;

                        pthread_rwlock_unlock(&udp_data.flows_lock);

                        memcpy(buf, &eid, sizeof(eid));

                        pthread_cleanup_push((void (*)(void *))
                                             ipcp_sdb_release, (void *) sdb);

                        if (write(fd, buf, len + OUR_HEADER_LEN) < 0)
                                log_err("Failed to send packet.");

                        pthread_cleanup_pop(true);
                }
        }

        pthread_cleanup_pop(true);

        return (void *) 1;
}

static int ipcp_udp_bootstrap(const struct ipcp_config * conf)
{
        char ipstr[INET_ADDRSTRLEN];
        char dnsstr[INET_ADDRSTRLEN];
        char portstr[128]; /* port is max 64535 = 5 chars */
        int  i = 1;

        assert(conf);
        assert(conf->type == THIS_TYPE);

        if (inet_ntop(AF_INET, &conf->ip_addr, ipstr, INET_ADDRSTRLEN)
            == NULL) {
                log_err("Failed to convert IP address");
                return -1;
        }

        if (conf->dns_addr != 0) {
                if (inet_ntop(AF_INET, &conf->dns_addr, dnsstr, INET_ADDRSTRLEN)
                    == NULL) {
                        log_err("Failed to convert DNS address");
                        return -1;
                }
#ifndef HAVE_DDNS
                log_warn("DNS disabled at compile time, address ignored");
#endif
        } else {
                strcpy(dnsstr, "not set");
        }

        /* UDP listen server */
        udp_data.s_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (udp_data.s_fd < 0) {
                log_err("Can't create socket: %s", strerror(errno));
                goto fail_socket;
        }

        if (setsockopt(udp_data.s_fd, SOL_SOCKET, SO_REUSEADDR,
                       &i, sizeof(i)) < 0)
                log_warn("Failed to set SO_REUSEADDR.");

        memset((char *) &udp_data.s_saddr, 0, sizeof(udp_data.s_saddr));
        udp_data.s_saddr.sin_family      = AF_INET;
        udp_data.s_saddr.sin_addr.s_addr = conf->ip_addr;
        udp_data.s_saddr.sin_port        = htons(conf->srv_port);

        if (bind(udp_data.s_fd, SERV_SADDR, SERV_SADDR_SIZE) < 0) {
                log_err("Couldn't bind to %s.", ipstr);
                goto fail_bind;
        }

        udp_data.ip_addr  = conf->ip_addr;
        udp_data.dns_addr = conf->dns_addr;
        udp_data.clt_port = htons(conf->clt_port);

        ipcp_set_state(IPCP_OPERATIONAL);

        if (pthread_create(&udp_data.mgmt_handler, NULL,
                           ipcp_udp_mgmt_handler, NULL)) {
                ipcp_set_state(IPCP_INIT);
                goto fail_bind;
        }

        for (i = 0; i < IPCP_UDP_RD_THR; ++i) {
                if (pthread_create(&udp_data.packet_reader[i], NULL,
                                   ipcp_udp_packet_reader, NULL)) {
                        ipcp_set_state(IPCP_INIT);
                        goto fail_packet_reader;
                }
        }

        for (i = 0; i < IPCP_UDP_WR_THR; ++i) {
                if (pthread_create(&udp_data.packet_writer[i], NULL,
                        ipcp_udp_packet_writer, NULL)) {
                        ipcp_set_state(IPCP_INIT);
                        goto fail_packet_writer;
                }
        }

        sprintf(portstr, "%d", conf->clt_port);

        log_dbg("Bootstrapped IPCP over UDP with pid %d.", getpid());
        log_dbg("Bound to IP address %s.", ipstr);
        log_dbg("Client port is %s.", conf->clt_port == 0 ? "random" : portstr);
        log_dbg("Server port is %u.", conf->srv_port);
        log_dbg("DNS server address is %s.", dnsstr);

        return 0;

 fail_packet_writer:
        while (i > 0) {
                pthread_cancel(udp_data.packet_writer[--i]);
                pthread_join(udp_data.packet_writer[i], NULL);
        }
        i = IPCP_UDP_RD_THR;
 fail_packet_reader:
        while (i > 0) {
                pthread_cancel(udp_data.packet_reader[--i]);
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
        pid_t pid     = -1;
        int   wstatus;
        int   pipe_fd[2];
        char * argv[] = {NSUPDATE_EXEC, 0};
        char * envp[] = {0};

        if (pipe(pipe_fd)) {
                log_err("Failed to create pipe.");
                return -1;
        }

        pid = fork();
        if (pid == -1) {
                log_err("Failed to fork.");
                return -1;
        }

        if (pid == 0) {
                close(pipe_fd[1]);
                dup2(pipe_fd[0], 0);
                execve(argv[0], &argv[0], envp);
        }

        close(pipe_fd[0]);

        if (write(pipe_fd[1], cmd, strlen(cmd)) == -1) {
                log_err("Failed to communicate with nsupdate.");
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

static uint32_t ddns_resolve(char *   name,
                             uint32_t dns_addr)
{
        pid_t    pid      = -1;
        int      wstatus;
        int      pipe_fd[2];
        char     dnsstr[INET_ADDRSTRLEN];
        char     buf[IPCP_UDP_BUF_SIZE];
        ssize_t  count    = 0;
        char *   substr   = NULL;
        char *   substr2  = NULL;
        char *   addr_str = "Address:";
        uint32_t ip_addr  = 0;

        if (inet_ntop(AF_INET, &dns_addr, dnsstr, INET_ADDRSTRLEN) == NULL)
                return 0;

        if (pipe(pipe_fd)) {
                log_err("Failed to create pipe.");
                return 0;
        }

        pid = fork();
        if (pid == -1) {
                log_err("Failed to fork.");
                return 0;
        }

        if (pid == 0) {
                char * argv[] = {NSLOOKUP_EXEC, name, dnsstr, 0};
                char * envp[] = {0};

                close(pipe_fd[0]);
                dup2(pipe_fd[1], 1);
                execve(argv[0], &argv[0], envp);
        }

        close(pipe_fd[1]);

        count = read(pipe_fd[0], buf, IPCP_UDP_BUF_SIZE);
        if (count <= 0) {
                log_err("Failed to communicate with nslookup.");
                close(pipe_fd[0]);
                return 0;
        }

        close(pipe_fd[0]);

        waitpid(pid, &wstatus, 0);
        if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0 &&
            count != IPCP_UDP_BUF_SIZE)
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
                return 0;
        }

        if (inet_pton(AF_INET, substr2 + strlen(addr_str) + 1, &ip_addr) != 1) {
                log_err("Failed to resolve DNS address.");
                return 0;
        }

        return ip_addr;
}
#endif

static int ipcp_udp_reg(const uint8_t * hash)
{
#ifdef HAVE_DDNS
        char     ipstr[INET_ADDRSTRLEN];
        char     dnsstr[INET_ADDRSTRLEN];
        char     cmd[1000];
        uint32_t dns_addr;
        uint32_t ip_addr;
#endif
        char *   hashstr;

        hashstr = malloc(ipcp_dir_hash_strlen() + 1);
        if (hashstr == NULL)
                return -1;

        assert(hash);

        ipcp_hash_str(hashstr, hash);

        if (shim_data_reg_add_entry(udp_data.shim_data, hash)) {
                log_err("Failed to add " HASH_FMT " to local registry.",
                        HASH_VAL(hash));
                free(hashstr);
                return -1;
        }

#ifdef HAVE_DDNS
        /* register application with DNS server */

        dns_addr = udp_data.dns_addr;

        if (dns_addr != 0) {
                ip_addr = udp_data.ip_addr;

                if (inet_ntop(AF_INET, &ip_addr,
                              ipstr, INET_ADDRSTRLEN) == NULL) {
                        free(hashstr);
                        return -1;
                }

                if (inet_ntop(AF_INET, &dns_addr,
                              dnsstr, INET_ADDRSTRLEN) == NULL) {
                        free(hashstr);
                        return -1;
                }

                sprintf(cmd, "server %s\nupdate add %s %d A %s\nsend\nquit\n",
                        dnsstr, hashstr, DNS_TTL, ipstr);

                if (ddns_send(cmd)) {
                        shim_data_reg_del_entry(udp_data.shim_data, hash);
                        free(hashstr);
                        return -1;
                }
        }
#endif
        log_dbg("Registered " HASH_FMT ".", HASH_VAL(hash));

        free(hashstr);

        return 0;
}

static int ipcp_udp_unreg(const uint8_t * hash)
{
#ifdef HAVE_DDNS
        char     dnsstr[INET_ADDRSTRLEN];
        /* max DNS name length + max IP length + max command length */
        char     cmd[100];
        uint32_t dns_addr;
#endif
        char *   hashstr;

        assert(hash);

        hashstr = malloc(ipcp_dir_hash_strlen() + 1);
        if (hashstr == NULL)
                return -1;

        ipcp_hash_str(hashstr, hash);

#ifdef HAVE_DDNS
        /* unregister application with DNS server */

        dns_addr = udp_data.dns_addr;

        if (dns_addr != 0) {
                if (inet_ntop(AF_INET, &dns_addr, dnsstr, INET_ADDRSTRLEN)
                    == NULL) {
                        free(hashstr);
                        return -1;
                }
                sprintf(cmd, "server %s\nupdate delete %s A\nsend\nquit\n",
                        dnsstr, hashstr);

                ddns_send(cmd);
        }
#endif

        shim_data_reg_del_entry(udp_data.shim_data, hash);

        log_dbg("Unregistered " HASH_FMT ".", HASH_VAL(hash));

        free(hashstr);

        return 0;
}

static int ipcp_udp_query(const uint8_t * hash)
{
        uint32_t         ip_addr  = 0;
        char *           hashstr;
        struct hostent * h;
#ifdef HAVE_DDNS
        uint32_t         dns_addr = 0;
#endif
        assert(hash);

        hashstr = malloc(ipcp_dir_hash_strlen() + 1);
        if (hashstr == NULL)
                return -ENOMEM;

        ipcp_hash_str(hashstr, hash);

        if (shim_data_dir_has(udp_data.shim_data, hash)) {
                free(hashstr);
                return 0;
        }

#ifdef HAVE_DDNS
        dns_addr = udp_data.dns_addr;

        if (dns_addr != 0) {
                ip_addr = ddns_resolve(hashstr, dns_addr);
                if (ip_addr == 0) {
                        log_dbg("Could not resolve %s.", hashstr);
                        free(hashstr);
                        return -1;
                }
        } else {
#endif
                h = gethostbyname(hashstr);
                if (h == NULL) {
                        log_dbg("Could not resolve %s.", hashstr);
                        free(hashstr);
                        return -1;
                }

                ip_addr = *((uint32_t *) (h->h_addr_list[0]));
#ifdef HAVE_DDNS
        }
#endif

        if (shim_data_dir_add_entry(udp_data.shim_data, hash, ip_addr)) {
                log_err("Failed to add directory entry.");
                free(hashstr);
                return -1;
        }

        free(hashstr);

        return 0;
}

static int ipcp_udp_flow_alloc(int             fd,
                               const uint8_t * dst,
                               qosspec_t       qs)
{
        struct sockaddr_in r_saddr; /* Server address */
        struct sockaddr_in c_saddr; /* Client address */
        socklen_t          c_saddr_len;
        int                skfd;
        uint32_t           ip_addr = 0;
        char               ip_str[INET_ADDRSTRLEN];

        c_saddr_len = sizeof(c_saddr);

        log_dbg("Allocating flow to " HASH_FMT ".", HASH_VAL(dst));

        (void) qs;

        assert(dst);

        skfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (skfd < 0) {
                log_err("Could not create socket.");
                return -1;
        }

        /* This socket is for the flow. */
        memset((char *) &c_saddr, 0, sizeof(c_saddr));
        c_saddr.sin_family      = AF_INET;
        c_saddr.sin_addr.s_addr = LOCAL_IP;
        c_saddr.sin_port        = udp_data.clt_port;

        if (bind(skfd, (struct sockaddr *) &c_saddr, sizeof(c_saddr)) < 0) {
                log_dbg("Could not bind socket to client address.");
                close(skfd);
                return -1;
        }

        if (getsockname(skfd, (struct sockaddr *) &c_saddr, &c_saddr_len) < 0) {
                log_err("Could not get address from fd.");
                close(skfd);
                return -1;
        }

        if (!shim_data_dir_has(udp_data.shim_data, dst)) {
                log_dbg("Could not resolve destination.");
                close(skfd);
                return -1;
        }

        ip_addr = (uint32_t) shim_data_dir_get_addr(udp_data.shim_data, dst);

        inet_ntop(AF_INET, &ip_addr, ip_str, INET_ADDRSTRLEN);
        log_dbg("Destination UDP ipcp resolved at %s.", ip_str);

        /* Connect to server and store the remote IP address in the skfd. */
        memset((char *) &r_saddr, 0, sizeof(r_saddr));
        r_saddr.sin_family      = AF_INET;
        r_saddr.sin_addr.s_addr = ip_addr;
        r_saddr.sin_port        = udp_data.s_saddr.sin_port;

        if (connect(skfd, (struct sockaddr *) &r_saddr, sizeof(r_saddr)) < 0) {
                log_dbg("Could not connect socket to remote.");
                close(skfd);
                return -1;
        }

        if (ipcp_udp_port_alloc(skfd, fd, dst, qs) < 0) {
                log_err("Could not allocate port.");
                close(skfd);
                return -1;
        }

        pthread_rwlock_wrlock(&udp_data.flows_lock);

        udp_data.fd_to_uf[fd].d_eid = -1;
        udp_data.fd_to_uf[fd].skfd  = skfd;

        fset_add(udp_data.np1_flows, fd);

        pthread_rwlock_unlock(&udp_data.flows_lock);

        log_dbg("Flow pending on fd %d, UDP src port %d, dst port %d.",
                fd, ntohs(c_saddr.sin_port), ntohs(r_saddr.sin_port));

        return 0;
}

static int ipcp_udp_flow_alloc_resp(int fd,
                                    int response)
{
        struct timespec ts  = {0, FD_UPDATE_TIMEOUT * 1000};
        struct timespec abstime;
        int             skfd;
        int             d_eid;

        if (response)
                return 0;

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

        pthread_rwlock_rdlock(&udp_data.flows_lock);

        skfd  = udp_data.fd_to_uf[fd].skfd;
        d_eid = udp_data.fd_to_uf[fd].d_eid;

        fset_add(udp_data.np1_flows, fd);

        pthread_rwlock_unlock(&udp_data.flows_lock);

        if (ipcp_udp_port_alloc_resp(skfd, d_eid, fd, response) < 0) {
                pthread_rwlock_rdlock(&udp_data.flows_lock);
                fset_del(udp_data.np1_flows, fd);
                pthread_rwlock_unlock(&udp_data.flows_lock);
                log_err("Failed to respond to flow request.");
                return -1;
        }

        log_dbg("Accepted flow, fd %d on eid %d.",
                fd, d_eid);

        return 0;
}

static int ipcp_udp_flow_dealloc(int fd)
{
        int skfd = -1;

        ipcp_flow_fini(fd);

        pthread_rwlock_wrlock(&udp_data.flows_lock);

        fset_del(udp_data.np1_flows, fd);

        skfd = udp_data.fd_to_uf[fd].skfd;

        udp_data.fd_to_uf[fd].d_eid = -1;
        udp_data.fd_to_uf[fd].skfd  = -1;

        close(skfd);

        pthread_rwlock_unlock(&udp_data.flows_lock);

        flow_dealloc(fd);

        log_dbg("Flow with fd %d deallocated.", fd);

        return 0;
}

static struct ipcp_ops udp_ops = {
        .ipcp_bootstrap       = ipcp_udp_bootstrap,
        .ipcp_enroll          = NULL,
        .ipcp_connect         = NULL,
        .ipcp_disconnect      = NULL,
        .ipcp_reg             = ipcp_udp_reg,
        .ipcp_unreg           = ipcp_udp_unreg,
        .ipcp_query           = ipcp_udp_query,
        .ipcp_flow_alloc      = ipcp_udp_flow_alloc,
        .ipcp_flow_join       = NULL,
        .ipcp_flow_alloc_resp = ipcp_udp_flow_alloc_resp,
        .ipcp_flow_dealloc    = ipcp_udp_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        int i;

        if (ipcp_init(argc, argv, &udp_ops) < 0)
                goto fail_init;

        if (udp_data_init() < 0) {
                log_err("Failed to init udp data.");
                goto fail_data_init;
        }

        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                goto fail_boot;
        }

        if (ipcp_create_r(0)) {
                log_err("Failed to notify IRMd we are initialized.");
                goto fail_create_r;
        }

        ipcp_shutdown();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                for (i = 0; i < IPCP_UDP_RD_THR; ++i)
                        pthread_cancel(udp_data.packet_reader[i]);
                for (i = 0; i < IPCP_UDP_WR_THR; ++i)
                        pthread_cancel(udp_data.packet_writer[i]);
                pthread_cancel(udp_data.mgmt_handler);

                for (i = 0; i < IPCP_UDP_RD_THR; ++i)
                        pthread_join(udp_data.packet_reader[i], NULL);
                for (i = 0; i < IPCP_UDP_WR_THR; ++i)
                        pthread_join(udp_data.packet_writer[i], NULL);
                pthread_join(udp_data.mgmt_handler, NULL);
        }

        udp_data_fini();

        ipcp_fini();

        exit(EXIT_SUCCESS);
 fail_create_r:
        ipcp_set_state(IPCP_NULL);
        ipcp_shutdown();
 fail_boot:
        udp_data_fini();
 fail_data_init:
        ipcp_fini();
 fail_init:
        ipcp_create_r(-1);
        exit(EXIT_FAILURE);
}
