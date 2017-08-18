/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Shim IPC process over UDP
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

#define _POSIX_C_SOURCE 200112L

#include "config.h"

#define OUROBOROS_PREFIX "ipcpd/shim-udp"

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
#include "shim_udp_messages.pb-c.h"

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

typedef ShimUdpMsg shim_udp_msg_t;

#define THIS_TYPE IPCP_SHIM_UDP
#define LISTEN_PORT htons(0x0D1F)
#define SHIM_UDP_BUF_SIZE 256
#define SHIM_UDP_MSG_SIZE 256
#define SHIM_UDP_MAX_SDU_SIZE 8980
#define DNS_TTL 86400
#define FD_UPDATE_TIMEOUT 100 /* microseconds */

#define local_ip (udp_data.s_saddr.sin_addr.s_addr)

#define UDP_MAX_PORTS 0xFFFF

struct uf {
        int                udp;
        int                skfd;
};

struct {
        struct shim_data * shim_data;

        uint32_t           ip_addr;
        uint32_t           dns_addr;
        /* listen server */
        struct sockaddr_in s_saddr;
        int                s_fd;

        flow_set_t *       np1_flows;
        fqueue_t *         fq;
        fd_set             flow_fd_s;
        /* bidir mappings of (n - 1) file descriptor to (n) flow descriptor */
        int                uf_to_fd[FD_SETSIZE];
        struct uf          fd_to_uf[SYS_MAX_FLOWS];
        pthread_rwlock_t   flows_lock;

        pthread_t          sduloop;
        pthread_t          handler;
        pthread_t          sdu_reader;

        bool               fd_set_mod;
        pthread_cond_t     fd_set_cond;
        pthread_mutex_t    fd_set_lock;
} udp_data;

static int udp_data_init(void)
{
        int i;

        for (i = 0; i < FD_SETSIZE; ++i)
                udp_data.uf_to_fd[i] = -1;

        for (i = 0; i < SYS_MAX_FLOWS; ++i) {
                udp_data.fd_to_uf[i].skfd = -1;
                udp_data.fd_to_uf[i].udp = -1;
        }

        FD_ZERO(&udp_data.flow_fd_s);

        udp_data.np1_flows = flow_set_create();
        if (udp_data.np1_flows == NULL)
                return -ENOMEM;

        udp_data.fq = fqueue_create();
        if (udp_data.fq == NULL) {
                flow_set_destroy(udp_data.np1_flows);
                return -ENOMEM;
        }

        udp_data.shim_data = shim_data_create();
        if (udp_data.shim_data == NULL) {
                fqueue_destroy(udp_data.fq);
                flow_set_destroy(udp_data.np1_flows);
                return -ENOMEM;
        }

        pthread_rwlock_init(&udp_data.flows_lock, NULL);
        pthread_cond_init(&udp_data.fd_set_cond, NULL);
        pthread_mutex_init(&udp_data.fd_set_lock, NULL);

        return 0;
}

static void udp_data_fini(void)
{
        flow_set_destroy(udp_data.np1_flows);
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

static int send_shim_udp_msg(shim_udp_msg_t * msg,
                             uint32_t         dst_ip_addr)
{
       buffer_t           buf;
       struct sockaddr_in r_saddr;

       memset((char *)&r_saddr, 0, sizeof(r_saddr));
       r_saddr.sin_family      = AF_INET;
       r_saddr.sin_addr.s_addr = dst_ip_addr;
       r_saddr.sin_port        = LISTEN_PORT;

       buf.len = shim_udp_msg__get_packed_size(msg);
       if (buf.len == 0) {
               return -1;
       }

       buf.data = malloc(SHIM_UDP_MSG_SIZE);
       if (buf.data == NULL)
               return -1;

       shim_udp_msg__pack(msg, buf.data);

       if (sendto(udp_data.s_fd,
                  buf.data,
                  buf.len,
                  0,
                  (struct sockaddr *) &r_saddr,
                  sizeof(r_saddr)) == -1) {
               log_err("Failed to send message.");
               free(buf.data);
               return -1;
       }

       free(buf.data);

       return 0;
}

static int ipcp_udp_port_alloc(uint32_t        dst_ip_addr,
                               uint16_t        src_udp_port,
                               const uint8_t * dst,
                               qoscube_t       cube)
{
        shim_udp_msg_t msg = SHIM_UDP_MSG__INIT;

        msg.code         = SHIM_UDP_MSG_CODE__FLOW_REQ;
        msg.src_udp_port = src_udp_port;
        msg.has_hash     = true;
        msg.hash.len     = ipcp_dir_hash_len();
        msg.hash.data    = (uint8_t *) dst;
        msg.has_qoscube  = true;
        msg.qoscube      = cube;

        return send_shim_udp_msg(&msg, dst_ip_addr);
}

static int ipcp_udp_port_alloc_resp(uint32_t dst_ip_addr,
                                    uint16_t src_udp_port,
                                    uint16_t dst_udp_port,
                                    int      response)
{
        shim_udp_msg_t msg = SHIM_UDP_MSG__INIT;

        msg.code             = SHIM_UDP_MSG_CODE__FLOW_REPLY;
        msg.src_udp_port     = src_udp_port;
        msg.has_dst_udp_port = true;
        msg.dst_udp_port     = dst_udp_port;
        msg.has_response     = true;
        msg.response         = response;

        return send_shim_udp_msg(&msg, dst_ip_addr);
}

static int ipcp_udp_port_req(struct sockaddr_in * c_saddr,
                             const uint8_t *      dst,
                             qoscube_t            cube)
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
                return -1;
        }

        /* reply to IRM */
        fd = ipcp_flow_req_arr(getpid(), dst, ipcp_dir_hash_len(), cube);
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
        pthread_mutex_unlock(&ipcpi.alloc_lock);

        ipcpi.alloc_id = fd;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

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
                                     int response)
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
        struct timeval     ltv = {(SOCKET_TIMEOUT / 1000),
                                  (SOCKET_TIMEOUT % 1000) * 1000};

        (void) o;

        if (setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO,
                       (void *) &ltv, sizeof(ltv)))
                log_warn("Failed to set timeout on socket.");

        while (ipcp_get_state() == IPCP_OPERATIONAL) {
                shim_udp_msg_t * msg = NULL;

                memset(&buf, 0, SHIM_UDP_MSG_SIZE);
                n = sizeof(c_saddr);
                n = recvfrom(sfd, buf, SHIM_UDP_MSG_SIZE, 0,
                             (struct sockaddr *) &c_saddr, (unsigned *) &n);
                if (n < 0)
                        continue;

                /* flow alloc request from other host */
                if (gethostbyaddr((const char *) &c_saddr.sin_addr.s_addr,
                                  sizeof(c_saddr.sin_addr.s_addr), AF_INET)
                    == NULL)
                        continue;

                msg = shim_udp_msg__unpack(NULL, n, buf);
                if (msg == NULL)
                        continue;

                switch (msg->code) {
                case SHIM_UDP_MSG_CODE__FLOW_REQ:
                        c_saddr.sin_port = msg->src_udp_port;
                        ipcp_udp_port_req(&c_saddr,
                                          msg->hash.data,
                                          msg->qoscube);
                        break;
                case SHIM_UDP_MSG_CODE__FLOW_REPLY:
                        ipcp_udp_port_alloc_reply(msg->src_udp_port,
                                                  msg->dst_udp_port,
                                                  msg->response);
                        break;
                default:
                        log_err("Unknown message received %d.", msg->code);
                        shim_udp_msg__free_unpacked(msg, NULL);
                        continue;
                }

                c_saddr.sin_port = LISTEN_PORT;

                shim_udp_msg__free_unpacked(msg, NULL);
        }

        return 0;
}

static void * ipcp_udp_sdu_reader(void * o)
{
        ssize_t n;
        int skfd;
        int fd;
        /* FIXME: avoid this copy */
        char buf[SHIM_UDP_MAX_SDU_SIZE];
        struct sockaddr_in r_saddr;
        fd_set read_fds;
        int flags;
        struct timeval tv = {0, FD_UPDATE_TIMEOUT};

        (void) o;

        while (ipcp_get_state() == IPCP_OPERATIONAL) {
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
                                          SHIM_UDP_MAX_SDU_SIZE,
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

static void * ipcp_udp_sdu_loop(void * o)
{
        int fd;
        struct timespec timeout = {0, FD_UPDATE_TIMEOUT * 1000};
        struct shm_du_buff * sdb;

        (void) o;

        while (ipcp_get_state() == IPCP_OPERATIONAL) {
                flow_event_wait(udp_data.np1_flows, udp_data.fq, &timeout);
                while ((fd = fqueue_next(udp_data.fq)) >= 0) {
                        if (ipcp_flow_read(fd, &sdb)) {
                                log_err("Bad read from fd %d.", fd);
                                continue;
                        }

                        pthread_rwlock_rdlock(&udp_data.flows_lock);

                        fd = udp_data.fd_to_uf[fd].skfd;

                        pthread_rwlock_unlock(&udp_data.flows_lock);

                        if (send(fd, shm_du_buff_head(sdb),
                                 shm_du_buff_tail(sdb) - shm_du_buff_head(sdb),
                                 0) < 0)
                                log_err("Failed to send SDU.");

                        ipcp_sdb_release(sdb);
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
#ifndef CONFIG_OUROBOROS_ENABLE_DNS
                log_warn("DNS disabled at compile time, address ignored");
#endif
        } else {
                strcpy(dnsstr, "not set");
        }

        /* UDP listen server */
        if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
                log_err("Can't create socket.");
                return -1;
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
                close(fd);
                return -1;
        }

        udp_data.s_fd     = fd;
        udp_data.ip_addr  = conf->ip_addr;
        udp_data.dns_addr = conf->dns_addr;

        FD_CLR(udp_data.s_fd, &udp_data.flow_fd_s);

        ipcp_set_state(IPCP_OPERATIONAL);

        pthread_create(&udp_data.handler,
                       NULL,
                       ipcp_udp_listener,
                       NULL);
        pthread_create(&udp_data.sdu_reader,
                       NULL,
                       ipcp_udp_sdu_reader,
                       NULL);

        pthread_create(&udp_data.sduloop,
                       NULL,
                       ipcp_udp_sdu_loop,
                       NULL);

        log_dbg("Bootstrapped shim IPCP over UDP with api %d.", getpid());
        log_dbg("Bound to IP address %s.", ipstr);
        log_dbg("DNS server address is %s.", dnsstr);

        return 0;
}

#ifdef CONFIG_OUROBOROS_ENABLE_DNS
/* FIXME: Dependency on nsupdate to be removed in the end */
/* NOTE: Disgusted with this crap */
static int ddns_send(char * cmd)
{
        pid_t api = -1;
        int wstatus;
        int pipe_fd[2];
        char * argv[] = {NSUPDATE_EXEC, 0};
        char * envp[] = {0};

        if (pipe(pipe_fd)) {
                log_err("Failed to create pipe.");
                return -1;
        }

        api = fork();
        if (api == -1) {
                log_err("Failed to fork.");
                return -1;
        }

        if (api == 0) {
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

        waitpid(api, &wstatus, 0);
        if (WIFEXITED(wstatus) == true &&
            WEXITSTATUS(wstatus) == 0)
                log_dbg("Succesfully communicated with DNS server.");
        else
                log_err("Failed to register with DNS server.");

        close(pipe_fd[1]);
        return 0;
}

static uint32_t ddns_resolve(char *   name,
                             uint32_t dns_addr)
{
        pid_t api = -1;
        int wstatus;
        int pipe_fd[2];
        char dnsstr[INET_ADDRSTRLEN];
        char buf[SHIM_UDP_BUF_SIZE];
        ssize_t count = 0;
        char * substr = NULL;
        char * substr2 = NULL;
        char * addr_str = "Address:";
        uint32_t ip_addr = 0;

        if (inet_ntop(AF_INET, &dns_addr, dnsstr, INET_ADDRSTRLEN) == NULL) {
                return 0;
        }


        if (pipe(pipe_fd)) {
                log_err("Failed to create pipe.");
                return 0;
        }

        api = fork();
        if (api == -1) {
                log_err("Failed to fork.");
                return 0;
        }

        if (api == 0) {
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

        waitpid(api, &wstatus, 0);
        if (WIFEXITED(wstatus) == true &&
            WEXITSTATUS(wstatus) == 0)
                log_dbg("Succesfully communicated with nslookup.");
        else
                log_err("Failed to resolve DNS address.");

        buf[count] = '\0';
        substr = strtok(buf, "\n");
        while (substr != NULL) {
                substr2 = substr;
                substr = strtok(NULL, "\n");
        }

        if (strstr(substr2, addr_str) == NULL) {
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
#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        char ipstr[INET_ADDRSTRLEN];
        char dnsstr[INET_ADDRSTRLEN];
        char cmd[1000];
        uint32_t dns_addr;
        uint32_t ip_addr;
#endif
        char hashstr[ipcp_dir_hash_strlen() + 1];
        uint8_t * hash_dup;

        assert(hash);

        ipcp_hash_str(hashstr, hash);

        hash_dup = ipcp_hash_dup(hash);
        if (hash_dup == NULL) {
                log_err("Failed to duplicate hash.");
                return -ENOMEM;
        }

        if (shim_data_reg_add_entry(udp_data.shim_data, hash_dup)) {
                log_err("Failed to add " HASH_FMT " to local registry.",
                        HASH_VAL(hash));
                free(hash_dup);
                return -1;
        }

#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        /* register application with DNS server */

        dns_addr = udp_data.dns_addr;

        if (dns_addr != 0) {
                ip_addr = udp_data.ip_addr;

                if (inet_ntop(AF_INET, &ip_addr,
                              ipstr, INET_ADDRSTRLEN) == NULL) {
                        return -1;
                }

                if (inet_ntop(AF_INET, &dns_addr,
                              dnsstr, INET_ADDRSTRLEN) == NULL) {
                        return -1;
                }

                sprintf(cmd, "server %s\nupdate add %s %d A %s\nsend\nquit\n",
                        dnsstr, hashstr, DNS_TTL, ipstr);

                if (ddns_send(cmd)) {
                        shim_data_reg_del_entry(udp_data.shim_data, hash_dup);
                        return -1;
                }
        }
#endif
        log_dbg("Registered " HASH_FMT ".", HASH_VAL(hash));

        return 0;
}

static int ipcp_udp_unreg(const uint8_t * hash)
{
#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        char dnsstr[INET_ADDRSTRLEN];
        /* max DNS name length + max IP length + max command length */
        char cmd[100];
        uint32_t dns_addr;
#endif
        char hashstr[ipcp_dir_hash_strlen() + 1];

        assert(hash);

        ipcp_hash_str(hashstr, hash);

#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        /* unregister application with DNS server */

        dns_addr = udp_data.dns_addr;

        if (dns_addr != 0) {
                if (inet_ntop(AF_INET, &dns_addr, dnsstr, INET_ADDRSTRLEN)
                    == NULL) {
                        return -1;
                }
                sprintf(cmd, "server %s\nupdate delete %s A\nsend\nquit\n",
                        dnsstr, hashstr);

                ddns_send(cmd);
        }
#endif

        shim_data_reg_del_entry(udp_data.shim_data, hash);

        log_dbg("Unregistered " HASH_FMT ".", HASH_VAL(hash));

        return 0;
}

static int ipcp_udp_query(const uint8_t * hash)
{
        uint32_t           ip_addr = 0;
        struct hostent *   h;
#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        uint32_t           dns_addr = 0;
#endif
        char hashstr[ipcp_dir_hash_strlen() + 1];

        assert(hash);

        ipcp_hash_str(hashstr, hash);

        if (shim_data_dir_has(udp_data.shim_data, hash))
                return 0;

#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        dns_addr = udp_data.dns_addr;

        if (dns_addr != 0) {
                ip_addr = ddns_resolve(hashstr, dns_addr);
                if (ip_addr == 0) {
                        log_dbg("Could not resolve %s.", hashstr);
                        return -1;
                }
        } else {
#endif
                h = gethostbyname(hashstr);
                if (h == NULL) {
                        log_dbg("Could not resolve %s.", hashstr);
                        return -1;
                }

                ip_addr = *((uint32_t *) (h->h_addr_list[0]));
#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        }
#endif

        if (shim_data_dir_add_entry(udp_data.shim_data, hash, ip_addr)) {
                log_err("Failed to add directory entry.");
                return -1;
        }

        return 0;
}

static int ipcp_udp_flow_alloc(int             fd,
                               const uint8_t * dst,
                               qoscube_t       cube)
{
        struct sockaddr_in r_saddr; /* server address */
        struct sockaddr_in f_saddr; /* flow */
        socklen_t          f_saddr_len = sizeof(f_saddr);
        int                skfd;
        uint32_t           ip_addr = 0;

        log_dbg("Allocating flow to " HASH_FMT ".", HASH_VAL(dst));

        assert(dst);

        if (cube != QOS_CUBE_BE) {
                log_dbg("Unsupported QoS requested.");
                return -1;
        }

        skfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

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

        flow_set_add(udp_data.np1_flows, fd);

        pthread_rwlock_unlock(&udp_data.flows_lock);

        if (ipcp_udp_port_alloc(ip_addr, f_saddr.sin_port, dst, cube) < 0) {
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

        flow_set_add(udp_data.np1_flows, fd);

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

        flow_set_del(udp_data.np1_flows, fd);

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
        .ipcp_enroll          = NULL,                       /* shim */
        .ipcp_reg             = ipcp_udp_reg,
        .ipcp_unreg           = ipcp_udp_unreg,
        .ipcp_query           = ipcp_udp_query,
        .ipcp_flow_alloc      = ipcp_udp_flow_alloc,
        .ipcp_flow_alloc_resp = ipcp_udp_flow_alloc_resp,
        .ipcp_flow_dealloc    = ipcp_udp_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        if (ipcp_init(argc, argv, THIS_TYPE, &udp_ops) < 0) {
                ipcp_create_r(getpid(), -1);
                exit(EXIT_FAILURE);
        }

        if (udp_data_init() < 0) {
                log_err("Failed to init shim-udp data.");
                ipcp_create_r(getpid(), -1);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                ipcp_create_r(getpid(), -1);
                udp_data_fini();
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        if (ipcp_create_r(getpid(), 0)) {
                log_err("Failed to notify IRMd we are initialized.");
                ipcp_set_state(IPCP_NULL);
                ipcp_shutdown();
                udp_data_fini();
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        ipcp_shutdown();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                pthread_join(udp_data.sduloop, NULL);
                pthread_join(udp_data.handler, NULL);
                pthread_join(udp_data.sdu_reader, NULL);
        }

        udp_data_fini();

        ipcp_fini();

        exit(EXIT_SUCCESS);
}
