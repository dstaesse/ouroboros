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
#define LISTEN_PORT              htons(0x0D1F)
#define SHIM_UDP_BUF_SIZE        256
#define SHIM_UDP_MSG_SIZE        256
#define SHIM_UDP_MAX_PACKET_SIZE 8980
#define DNS_TTL                  86400
#define FD_UPDATE_TIMEOUT        100 /* microseconds */

#define local_ip                 (udp_data.s_saddr.sin_addr.s_addr)

#define UDP_MAX_PORTS            0xFFFF

struct mgmt_msg {
        uint16_t src_udp_port;
        uint16_t dst_udp_port;
        uint8_t  code;
        uint8_t  response;
        /* QoS parameters from spec, aligned */
        uint8_t  availability;
        uint8_t  in_order;
        uint32_t delay;
        uint64_t bandwidth;
        uint32_t loss;
        uint32_t ber;
        uint32_t max_gap;
} __attribute__((packed));

struct uf {
        int udp;
        int skfd;
};

struct {
        struct shim_data * shim_data;

        uint32_t           ip_addr;
        uint32_t           dns_addr;
        /* listen server */
        struct sockaddr_in s_saddr;
        int                s_fd;

        fset_t *           np1_flows;
        fqueue_t *         fq;
        fd_set             flow_fd_s;
        /* bidir mappings of (n - 1) file descriptor to (n) flow descriptor */
        int                uf_to_fd[FD_SETSIZE];
        struct uf          fd_to_uf[SYS_MAX_FLOWS];
        pthread_rwlock_t   flows_lock;

        pthread_t          packet_loop;
        pthread_t          handler;
        pthread_t          packet_reader;

        bool               fd_set_mod;
        pthread_cond_t     fd_set_cond;
        pthread_mutex_t    fd_set_lock;
} udp_data;

static int udp_data_init(void)
{
        int i;

        if (pthread_rwlock_init(&udp_data.flows_lock, NULL))
                return -1;

        if (pthread_cond_init(&udp_data.fd_set_cond, NULL))
                goto fail_set_cond;

        if (pthread_mutex_init(&udp_data.fd_set_lock, NULL))
                goto fail_set_lock;

        for (i = 0; i < FD_SETSIZE; ++i)
                udp_data.uf_to_fd[i] = -1;

        for (i = 0; i < SYS_MAX_FLOWS; ++i) {
                udp_data.fd_to_uf[i].skfd = -1;
                udp_data.fd_to_uf[i].udp = -1;
        }

        FD_ZERO(&udp_data.flow_fd_s);

        udp_data.np1_flows = fset_create();
        if (udp_data.np1_flows == NULL)
                goto fail_fset;

        udp_data.fq = fqueue_create();
        if (udp_data.fq == NULL)
                goto fail_fqueue;

        udp_data.shim_data = shim_data_create();
        if (udp_data.shim_data == NULL)
                goto fail_data;

        return 0;
 fail_data:
        fqueue_destroy(udp_data.fq);
 fail_fqueue:
        fset_destroy(udp_data.np1_flows);
 fail_fset:
        pthread_mutex_destroy(&udp_data.fd_set_lock);
 fail_set_lock:
        pthread_cond_destroy(&udp_data.fd_set_cond);
 fail_set_cond:
        pthread_rwlock_destroy(&udp_data.flows_lock);
        return -1;
}

static void udp_data_fini(void)
{
        fset_destroy(udp_data.np1_flows);
        fqueue_destroy(udp_data.fq);

        shim_data_destroy(udp_data.shim_data);

        pthread_rwlock_destroy(&udp_data.flows_lock);
        pthread_mutex_destroy(&udp_data.fd_set_lock);
        pthread_cond_destroy(&udp_data.fd_set_cond);
}

static void set_fd(int fd)
{
        pthread_mutex_lock(&udp_data.fd_set_lock);

        udp_data.fd_set_mod = true;
        FD_SET(fd, &udp_data.flow_fd_s);

        while (udp_data.fd_set_mod)
                pthread_cond_wait(&udp_data.fd_set_cond, &udp_data.fd_set_lock);

        pthread_mutex_unlock(&udp_data.fd_set_lock);
}

static void clr_fd(int fd)
{
        pthread_mutex_lock(&udp_data.fd_set_lock);

        udp_data.fd_set_mod = true;
        FD_CLR(fd, &udp_data.flow_fd_s);

        while (udp_data.fd_set_mod)
                pthread_cond_wait(&udp_data.fd_set_cond, &udp_data.fd_set_lock);

        pthread_mutex_unlock(&udp_data.fd_set_lock);
}

static int send_shim_udp_msg(uint8_t * buf,
                             size_t    len,
                             uint32_t  dst_ip_addr)
{
       struct sockaddr_in r_saddr;

       memset((char *)&r_saddr, 0, sizeof(r_saddr));
       r_saddr.sin_family      = AF_INET;
       r_saddr.sin_addr.s_addr = dst_ip_addr;
       r_saddr.sin_port        = LISTEN_PORT;

       if (sendto(udp_data.s_fd, buf, len, 0,
                  (struct sockaddr *) &r_saddr,
                  sizeof(r_saddr)) == -1) {
               log_err("Failed to send message.");
               return -1;
       }

       return 0;
}

static int ipcp_udp_port_alloc(uint32_t        dst_ip_addr,
                               uint16_t        src_udp_port,
                               const uint8_t * dst,
                               qosspec_t       qs)
{
        uint8_t *         buf;
        struct mgmt_msg * msg;
        size_t            len;
        int               ret;

        len = sizeof(*msg) + ipcp_dir_hash_len();

        buf = malloc(len);
        if (buf == NULL)
                return -1;

        msg               = (struct mgmt_msg *) buf;
        msg->code         = FLOW_REQ;
        msg->src_udp_port = src_udp_port;
        msg->delay        = hton32(qs.delay);
        msg->bandwidth    = hton64(qs.bandwidth);
        msg->availability = qs.availability;
        msg->loss         = hton32(qs.loss);
        msg->ber          = hton32(qs.ber);
        msg->in_order     = qs.in_order;
        msg->max_gap      = hton32(qs.max_gap);

        memcpy(msg + 1, dst, ipcp_dir_hash_len());

        ret = send_shim_udp_msg(buf, len, dst_ip_addr);

        free(buf);

        return ret;
}

static int ipcp_udp_port_alloc_resp(uint32_t dst_ip_addr,
                                    uint16_t src_udp_port,
                                    uint16_t dst_udp_port,
                                    int      response)
{
        struct mgmt_msg * msg;
        int               ret;

        msg = malloc(sizeof(*msg));
        if (msg == NULL)
                return -1;

        msg->code         = FLOW_REPLY;
        msg->src_udp_port = src_udp_port;
        msg->dst_udp_port = dst_udp_port;
        msg->response     = response;

        ret = send_shim_udp_msg((uint8_t *) msg, sizeof(*msg), dst_ip_addr);

        free(msg);

        return ret;
}

static int ipcp_udp_port_req(struct sockaddr_in * c_saddr,
                             const uint8_t *      dst,
                             qosspec_t            qs)
{
        struct timespec    ts          = {0, FD_UPDATE_TIMEOUT * 1000};
        struct timespec    abstime;
        struct sockaddr_in f_saddr;
        socklen_t          f_saddr_len = sizeof(f_saddr);
        int                skfd;
        int                fd;

        log_dbg("Port request arrived from UDP port %d",
                 ntohs(c_saddr->sin_port));

        if ((skfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
                log_err("Could not create UDP socket.");
                return -1;
        }

        memset((char *) &f_saddr, 0, sizeof(f_saddr));
        f_saddr.sin_family      = AF_INET;
        f_saddr.sin_addr.s_addr = local_ip;
        f_saddr.sin_port        = 0;

        if (bind(skfd, (struct sockaddr *) &f_saddr, sizeof(f_saddr)) < 0) {
                log_err("Could not bind to socket.");
                close(skfd);
                return -1;
        }

        if (getsockname(skfd, (struct sockaddr *) &f_saddr, &f_saddr_len) < 0) {
                log_err("Could not get address from fd.");
                return -1;
        }

        /* connect stores the remote address in the file descriptor */
        if (connect(skfd, (struct sockaddr *) c_saddr, sizeof(*c_saddr)) < 0) {
                log_err("Could not connect to remote UDP client.");
                close(skfd);
                return -1;
        }

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

        udp_data.uf_to_fd[skfd]    = fd;
        udp_data.fd_to_uf[fd].skfd = skfd;
        udp_data.fd_to_uf[fd].udp  = f_saddr.sin_port;

        pthread_rwlock_unlock(&udp_data.flows_lock);

        ipcpi.alloc_id = fd;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

        log_dbg("Pending allocation request, fd %d, UDP port (%d, %d).",
                fd, ntohs(f_saddr.sin_port), ntohs(c_saddr->sin_port));

        return 0;
}

/* returns the n flow descriptor */
static int udp_port_to_fd(int udp_port)
{
        int i;

        for (i = 0; i < SYS_MAX_FLOWS; ++i)
                if (udp_data.fd_to_uf[i].udp == udp_port)
                        return i;

        return -1;
}

static int ipcp_udp_port_alloc_reply(uint16_t src_udp_port,
                                     uint16_t dst_udp_port,
                                     int      response)
{
        int fd   = -1;
        int ret  =  0;
        int skfd = -1;

        struct sockaddr_in t_saddr;
        socklen_t          t_saddr_len = sizeof(t_saddr);

        log_dbg("Received reply for flow on udp port %d.",
                ntohs(dst_udp_port));

        pthread_rwlock_rdlock(&udp_data.flows_lock);

        fd = udp_port_to_fd(dst_udp_port);
        if (fd < 0) {
                pthread_rwlock_unlock(&udp_data.flows_lock);
                return -1;
        }

        skfd = udp_data.fd_to_uf[fd].skfd;

        pthread_rwlock_unlock(&udp_data.flows_lock);

        /* get the original address with the LISTEN PORT */
        if (getpeername(skfd, (struct sockaddr *) &t_saddr, &t_saddr_len) < 0) {
                log_dbg("Flow with fd %d has no peer.", fd);
                return -1;
        }

        /* connect to the flow udp port */
        t_saddr.sin_port = src_udp_port;

        if (connect(skfd, (struct sockaddr *) &t_saddr, sizeof(t_saddr)) < 0) {
                close(skfd);
                return -1;
        }

        pthread_rwlock_rdlock(&udp_data.flows_lock);

        set_fd(skfd);

        pthread_rwlock_unlock(&udp_data.flows_lock);

        if (ipcp_flow_alloc_reply(fd, response) < 0)
                return -1;

        log_dbg("Flow allocation completed, UDP ports: (%d, %d).",
                 ntohs(dst_udp_port), ntohs(src_udp_port));

        return ret;
}

static void * ipcp_udp_listener(void * o)
{
        uint8_t            buf[SHIM_UDP_MSG_SIZE];
        ssize_t            n   = 0;
        struct sockaddr_in c_saddr;
        int                sfd = udp_data.s_fd;

        (void) o;

        while (true) {
                struct mgmt_msg * msg = NULL;
                qosspec_t         qs;
                memset(&buf, 0, SHIM_UDP_MSG_SIZE);
                n = recvfrom(sfd, buf, SHIM_UDP_MSG_SIZE, 0,
                             (struct sockaddr *) &c_saddr,
                             (socklen_t *) sizeof(c_saddr));
                if (n < 0)
                        continue;

                /* flow alloc request from other host */
                if (gethostbyaddr((const char *) &c_saddr.sin_addr.s_addr,
                                  sizeof(c_saddr.sin_addr.s_addr), AF_INET)
                    == NULL)
                        continue;

                msg = (struct mgmt_msg *) buf;

                switch (msg->code) {
                case FLOW_REQ:
                        c_saddr.sin_port = msg->src_udp_port;
                        qs.delay = ntoh32(msg->delay);
                        qs.bandwidth = ntoh64(msg->bandwidth);
                        qs.availability = msg->availability;
                        qs.loss = ntoh32(msg->loss);
                        qs.ber = ntoh32(msg->ber);
                        qs.in_order = msg->in_order;
                        qs.max_gap = ntoh32(msg->max_gap);
                        ipcp_udp_port_req(&c_saddr,
                                          (uint8_t *) (msg + 1),
                                          qs);
                        break;
                case FLOW_REPLY:
                        ipcp_udp_port_alloc_reply(msg->src_udp_port,
                                                  msg->dst_udp_port,
                                                  msg->response);
                        break;
                default:
                        log_err("Unknown message received %d.", msg->code);
                        continue;
                }

                c_saddr.sin_port = LISTEN_PORT;
        }

        return 0;
}

static void * ipcp_udp_packet_reader(void * o)
{
        ssize_t            n;
        int                skfd;
        int                fd;
        /* FIXME: avoid this copy */
        char               buf[SHIM_UDP_MAX_PACKET_SIZE];
        struct sockaddr_in r_saddr;
        struct timeval     tv = {0, FD_UPDATE_TIMEOUT};
        fd_set             read_fds;
        int                flags;

        (void) o;

        ipcp_lock_to_core();

        while (true) {
                pthread_rwlock_rdlock(&udp_data.flows_lock);
                pthread_mutex_lock(&udp_data.fd_set_lock);

                read_fds = udp_data.flow_fd_s;
                udp_data.fd_set_mod = false;
                pthread_cond_broadcast(&udp_data.fd_set_cond);

                pthread_mutex_unlock(&udp_data.fd_set_lock);
                pthread_rwlock_unlock(&udp_data.flows_lock);

                if (select(FD_SETSIZE, &read_fds, NULL, NULL, &tv) <= 0)
                        continue;

                for (skfd = 0; skfd < FD_SETSIZE; ++skfd) {
                        if (!FD_ISSET(skfd, &read_fds))
                                continue;
                        flags = fcntl(skfd, F_GETFL, 0);
                        fcntl(skfd, F_SETFL, flags | O_NONBLOCK);
                        n = sizeof(r_saddr);
                        if ((n = recvfrom(skfd,
                                          &buf,
                                          SHIM_UDP_MAX_PACKET_SIZE,
                                          0,
                                          (struct sockaddr *) &r_saddr,
                                          (unsigned *) &n)) <= 0)
                                continue;

                        pthread_rwlock_rdlock(&udp_data.flows_lock);

                        fd = udp_data.uf_to_fd[skfd];

                        pthread_rwlock_unlock(&udp_data.flows_lock);

                        flow_write(fd, buf, n);
                }
        }

        return (void *) 0;
}

static void * ipcp_udp_packet_loop(void * o)
{
        int fd;
        struct shm_du_buff * sdb;

        (void) o;

        ipcp_lock_to_core();

        while (true) {
                fevent(udp_data.np1_flows, udp_data.fq, NULL);
                while ((fd = fqueue_next(udp_data.fq)) >= 0) {
                        if (ipcp_flow_read(fd, &sdb)) {
                                log_err("Bad read from fd %d.", fd);
                                continue;
                        }

                        pthread_rwlock_rdlock(&udp_data.flows_lock);

                        fd = udp_data.fd_to_uf[fd].skfd;

                        pthread_rwlock_unlock(&udp_data.flows_lock);

                        pthread_cleanup_push((void (*)(void *))
                                             ipcp_sdb_release,
                                             (void *) sdb);

                        if (send(fd, shm_du_buff_head(sdb),
                                 shm_du_buff_tail(sdb) - shm_du_buff_head(sdb),
                                 0) < 0)
                                log_err("Failed to send PACKET.");

                        pthread_cleanup_pop(true);
                }
        }

        return (void *) 1;
}

static int ipcp_udp_bootstrap(const struct ipcp_config * conf)
{
        struct sockaddr_in s_saddr;
        char ipstr[INET_ADDRSTRLEN];
        char dnsstr[INET_ADDRSTRLEN];
        int  enable = 1;
        int  fd = -1;

        assert(conf);
        assert(conf->type == THIS_TYPE);

        if (inet_ntop(AF_INET,
                      &conf->ip_addr,
                      ipstr,
                      INET_ADDRSTRLEN) == NULL) {
                log_err("Failed to convert IP address");
                return -1;
        }

        if (conf->dns_addr != 0) {
                if (inet_ntop(AF_INET,
                              &conf->dns_addr,
                              dnsstr,
                              INET_ADDRSTRLEN) == NULL) {
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
        if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
                log_err("Can't create socket.");
                goto fail_socket;
        }

        if (setsockopt(fd,
                       SOL_SOCKET,
                       SO_REUSEADDR,
                       &enable,
                       sizeof(int)) < 0)
                log_warn("Failed to set SO_REUSEADDR.");

        memset((char *) &s_saddr, 0, sizeof(s_saddr));
        udp_data.s_saddr.sin_family      = AF_INET;
        udp_data.s_saddr.sin_addr.s_addr = conf->ip_addr;
        udp_data.s_saddr.sin_port        = LISTEN_PORT;

        if (bind(fd,
                 (struct sockaddr *) &udp_data.s_saddr,
                 sizeof(udp_data.s_saddr)) < 0) {
                log_err("Couldn't bind to %s.", ipstr);
                goto fail_bind;
        }

        udp_data.s_fd     = fd;
        udp_data.ip_addr  = conf->ip_addr;
        udp_data.dns_addr = conf->dns_addr;

        FD_CLR(udp_data.s_fd, &udp_data.flow_fd_s);

        ipcp_set_state(IPCP_OPERATIONAL);

        if (pthread_create(&udp_data.handler,
                           NULL,
                           ipcp_udp_listener,
                           NULL)) {
                ipcp_set_state(IPCP_INIT);
                goto fail_bind;
        }

        if (pthread_create(&udp_data.packet_reader,
                           NULL,
                           ipcp_udp_packet_reader,
                           NULL)) {
                ipcp_set_state(IPCP_INIT);
                goto fail_packet_reader;
        }

        if (pthread_create(&udp_data.packet_loop,
                           NULL,
                           ipcp_udp_packet_loop,
                           NULL)) {
                ipcp_set_state(IPCP_INIT);
                goto fail_packet_loop;
        }

        log_dbg("Bootstrapped IPCP over UDP with pid %d.", getpid());
        log_dbg("Bound to IP address %s.", ipstr);
        log_dbg("DNS server address is %s.", dnsstr);

        return 0;

 fail_packet_loop:
        pthread_cancel(udp_data.packet_reader);
        pthread_join(udp_data.packet_reader, NULL);
 fail_packet_reader:
        pthread_cancel(udp_data.handler);
        pthread_join(udp_data.handler, NULL);
 fail_bind:
        close(fd);
 fail_socket:
        return -1;
}

#ifdef HAVE_DDNS
/* FIXME: Dependency on nsupdate to be removed in the end */
/* NOTE: Disgusted with this crap */
static int ddns_send(char * cmd)
{
        pid_t pid = -1;
        int wstatus;
        int pipe_fd[2];
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
        pid_t pid = -1;
        int wstatus;
        int pipe_fd[2];
        char dnsstr[INET_ADDRSTRLEN];
        char buf[SHIM_UDP_BUF_SIZE];
        ssize_t count = 0;
        char * substr = NULL;
        char * substr2 = NULL;
        char * addr_str = "Address:";
        uint32_t ip_addr = 0;

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

        count = read(pipe_fd[0], buf, SHIM_UDP_BUF_SIZE);
        if (count <= 0) {
                log_err("Failed to communicate with nslookup.");
                close(pipe_fd[0]);
                return 0;
        }

        close(pipe_fd[0]);

        waitpid(pid, &wstatus, 0);
        if (WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0 &&
            count != SHIM_UDP_BUF_SIZE)
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
        char ipstr[INET_ADDRSTRLEN];
        char dnsstr[INET_ADDRSTRLEN];
        char cmd[1000];
        uint32_t dns_addr;
        uint32_t ip_addr;
#endif
        char * hashstr;

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
        char dnsstr[INET_ADDRSTRLEN];
        /* max DNS name length + max IP length + max command length */
        char cmd[100];
        uint32_t dns_addr;
#endif
        char * hashstr;

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
        uint32_t           ip_addr = 0;
        char *             hashstr;
        struct hostent *   h;
#ifdef HAVE_DDNS
        uint32_t           dns_addr = 0;
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
        struct sockaddr_in r_saddr; /* server address */
        struct sockaddr_in f_saddr; /* flow */
        socklen_t          f_saddr_len = sizeof(f_saddr);
        int                skfd;
        uint32_t           ip_addr = 0;

        log_dbg("Allocating flow to " HASH_FMT ".", HASH_VAL(dst));

        (void) qs;

        assert(dst);

        skfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (skfd < 0)
                return -1;

        /* this socket is for the flow */
        memset((char *) &f_saddr, 0, sizeof(f_saddr));
        f_saddr.sin_family      = AF_INET;
        f_saddr.sin_addr.s_addr = local_ip;
        f_saddr.sin_port        = 0;

        if (bind(skfd, (struct sockaddr *) &f_saddr, sizeof(f_saddr)) < 0) {
                close(skfd);
                return -1;
        }

        if (getsockname(skfd, (struct sockaddr *) &f_saddr, &f_saddr_len) < 0) {
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

        /* connect to server (store the remote IP address in the fd) */
        memset((char *) &r_saddr, 0, sizeof(r_saddr));
        r_saddr.sin_family      = AF_INET;
        r_saddr.sin_addr.s_addr = ip_addr;
        r_saddr.sin_port        = LISTEN_PORT;

        if (connect(skfd, (struct sockaddr *) &r_saddr, sizeof(r_saddr)) < 0) {
                close(skfd);
                return -1;
        }

        pthread_rwlock_wrlock(&udp_data.flows_lock);

        udp_data.fd_to_uf[fd].udp  = f_saddr.sin_port;
        udp_data.fd_to_uf[fd].skfd = skfd;
        udp_data.uf_to_fd[skfd]    = fd;

        fset_add(udp_data.np1_flows, fd);

        pthread_rwlock_unlock(&udp_data.flows_lock);

        if (ipcp_udp_port_alloc(ip_addr, f_saddr.sin_port, dst, qs) < 0) {
                pthread_rwlock_wrlock(&udp_data.flows_lock);

                udp_data.fd_to_uf[fd].udp  = -1;
                udp_data.fd_to_uf[fd].skfd = -1;
                udp_data.uf_to_fd[skfd]    = -1;

                pthread_rwlock_unlock(&udp_data.flows_lock);
                close(skfd);
                return -1;
        }

        log_dbg("Flow pending on fd %d, UDP port %d.",
                fd, ntohs(f_saddr.sin_port));

        return 0;
}

static int ipcp_udp_flow_alloc_resp(int fd,
                                    int response)
{
        struct timespec    ts   = {0, FD_UPDATE_TIMEOUT * 1000};
        struct timespec    abstime;
        int                skfd = -1;
        struct sockaddr_in f_saddr;
        struct sockaddr_in r_saddr;
        socklen_t          len  = sizeof(r_saddr);

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

        skfd = udp_data.fd_to_uf[fd].skfd;

        pthread_rwlock_unlock(&udp_data.flows_lock);

        if (getsockname(skfd, (struct sockaddr *) &f_saddr, &len) < 0) {
                log_dbg("Socket with fd %d has no address.", skfd);
                return -1;
        }

        if (getpeername(skfd, (struct sockaddr *) &r_saddr, &len) < 0) {
                log_dbg("Socket with fd %d has no peer.", skfd);
                return -1;
        }

        pthread_rwlock_rdlock(&udp_data.flows_lock);

        set_fd(skfd);

        fset_add(udp_data.np1_flows, fd);

        pthread_rwlock_unlock(&udp_data.flows_lock);

        if (ipcp_udp_port_alloc_resp(r_saddr.sin_addr.s_addr, f_saddr.sin_port,
                                     r_saddr.sin_port, response) < 0) {
                pthread_rwlock_rdlock(&udp_data.flows_lock);
                clr_fd(skfd);
                pthread_rwlock_unlock(&udp_data.flows_lock);
                return -1;
        }

        log_dbg("Accepted flow, fd %d on UDP port %d.",
                fd, ntohs(f_saddr.sin_port));

        return 0;
}

static int ipcp_udp_flow_dealloc(int fd)
{
        int skfd = -1;

        ipcp_flow_fini(fd);

        pthread_rwlock_wrlock(&udp_data.flows_lock);

        fset_del(udp_data.np1_flows, fd);

        skfd = udp_data.fd_to_uf[fd].skfd;

        udp_data.uf_to_fd[skfd]    = -1;
        udp_data.fd_to_uf[fd].udp  = -1;
        udp_data.fd_to_uf[fd].skfd = -1;

        close(skfd);

        pthread_rwlock_unlock(&udp_data.flows_lock);
        pthread_rwlock_rdlock(&udp_data.flows_lock);

        clr_fd(skfd);

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
                pthread_cancel(udp_data.packet_loop);
                pthread_cancel(udp_data.handler);
                pthread_cancel(udp_data.packet_reader);

                pthread_join(udp_data.packet_loop, NULL);
                pthread_join(udp_data.handler, NULL);
                pthread_join(udp_data.packet_reader, NULL);
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
