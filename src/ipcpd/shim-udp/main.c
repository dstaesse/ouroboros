/*
 * Ouroboros - Copyright (C) 2016
 *
 * Shim IPC process over UDP
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <ouroboros/config.h>
#include "ipcp.h"
#include "shim_udp_config.h"
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/dev.h>
#include <ouroboros/ipcp-dev.h>

#define OUROBOROS_PREFIX "ipcpd/shim-udp"

#include <ouroboros/logs.h>

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

#include "shim_udp_messages.pb-c.h"

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

/* global for trapping signal */
int irmd_api;

struct uf {
        int                udp;
        int                skfd;
};

struct {
        uint32_t           ip_addr;
        uint32_t           dns_addr;
        /* listen server */
        struct sockaddr_in s_saddr;
        int                s_fd;

        fd_set             flow_fd_s;
        /* bidir mappings of (n - 1) file descriptor to (n) flow descriptor */
        int                uf_to_fd[FD_SETSIZE];
        struct uf          fd_to_uf[IRMD_MAX_FLOWS];
        pthread_rwlock_t   flows_lock;

        pthread_t          sduloop;
        pthread_t          handler;
        pthread_t          sdu_reader;

        bool               fd_set_mod;
        pthread_cond_t     fd_set_cond;
        pthread_mutex_t    fd_set_lock;
} udp_data;

static void udp_data_init()
{
        int i;

        for (i = 0; i < FD_SETSIZE; ++i)
                udp_data.uf_to_fd[i] = -1;

        for (i = 0; i < IRMD_MAX_FLOWS; ++i) {
                udp_data.fd_to_uf[i].skfd = -1;
                udp_data.fd_to_uf[i].udp = -1;
        }

        FD_ZERO(&udp_data.flow_fd_s);

        pthread_rwlock_init(&udp_data.flows_lock, NULL);
        pthread_cond_init(&udp_data.fd_set_cond, NULL);
        pthread_mutex_init(&udp_data.fd_set_lock, NULL);
}

static void udp_data_fini()
{
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

static int send_shim_udp_msg(shim_udp_msg_t * msg, uint32_t dst_ip_addr)
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
               LOG_ERR("Failed to send message.");
               free(buf.data);
               return -1;
       }

       free(buf.data);

       return 0;
}

static int ipcp_udp_port_alloc(uint32_t dst_ip_addr,
                               uint32_t src_udp_port,
                               char *   dst_name,
                               char *   src_ae_name)
{
        shim_udp_msg_t msg = SHIM_UDP_MSG__INIT;

        msg.code         = SHIM_UDP_MSG_CODE__FLOW_REQ;
        msg.src_udp_port = src_udp_port;
        msg.dst_name     = dst_name;
        msg.src_ae_name  = src_ae_name;

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

static int ipcp_udp_port_dealloc(uint32_t dst_ip_addr,
                                 uint16_t src_udp_port)
{
        shim_udp_msg_t msg = SHIM_UDP_MSG__INIT;

        msg.code             = SHIM_UDP_MSG_CODE__FLOW_DEALLOC;
        msg.src_udp_port     = src_udp_port;

        return send_shim_udp_msg(&msg, dst_ip_addr);
}

static int ipcp_udp_port_req(struct sockaddr_in * c_saddr,
                             char * dst_name,
                             char * src_ae_name)
{
        int skfd;
        int fd;

        struct sockaddr_in f_saddr;
        socklen_t          f_saddr_len = sizeof(f_saddr);

        LOG_DBG("Port request arrived from UDP port %d",
                 ntohs(c_saddr->sin_port));

        if ((skfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
                LOG_ERR("Could not create UDP socket.");
                return -1;
        }

        memset((char *) &f_saddr, 0, sizeof(f_saddr));
        f_saddr.sin_family      = AF_INET;
        f_saddr.sin_addr.s_addr = local_ip;
        f_saddr.sin_port        = 0;

        if (bind(skfd, (struct sockaddr *) &f_saddr, sizeof(f_saddr)) < 0) {
                LOG_ERR("Could not bind to socket.");
                close(skfd);
                return -1;
        }

        if (getsockname(skfd, (struct sockaddr *) &f_saddr, &f_saddr_len) < 0) {
                LOG_ERR("Could not get address from fd.");
                return -1;
        }

        /* connect stores the remote address in the file descriptor */
        if (connect(skfd, (struct sockaddr *) c_saddr, sizeof(*c_saddr)) < 0) {
                LOG_ERR("Could not connect to remote UDP client.");
                close(skfd);
                return -1;
        }

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        /* reply to IRM */
        fd = ipcp_flow_req_arr(getpid(), dst_name, src_ae_name);
        if (fd < 0) {
                pthread_rwlock_unlock(&udp_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Could not get new flow from IRMd.");
                close(skfd);
                return -1;
        }

        pthread_rwlock_wrlock(&udp_data.flows_lock);

        udp_data.uf_to_fd[skfd]    = fd;
        udp_data.fd_to_uf[fd].skfd = skfd;
        udp_data.fd_to_uf[fd].udp  = f_saddr.sin_port;

        pthread_rwlock_unlock(&udp_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_DBG("Pending allocation request, fd %d, UDP port (%d, %d).",
                fd, ntohs(f_saddr.sin_port), ntohs(c_saddr->sin_port));

        return 0;
}

/* returns the n flow descriptor */
static int udp_port_to_fd(int udp_port)
{
        int i;

        for (i = 0; i < IRMD_MAX_FLOWS; ++i)
                if (udp_data.fd_to_uf[i].udp == udp_port)
                        return i;

        return -1;
}

static int ipcp_udp_port_alloc_reply(int src_udp_port,
                                     int dst_udp_port,
                                     int response)
{
        int fd   = -1;
        int ret  =  0;
        int skfd = -1;

        struct sockaddr_in t_saddr;
        socklen_t          t_saddr_len = sizeof(t_saddr);

        LOG_DBG("Received reply for flow on udp port %d.",
                ntohs(dst_udp_port));

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_rdlock(&udp_data.flows_lock);

        fd = udp_port_to_fd(dst_udp_port);
        skfd = udp_data.fd_to_uf[fd].skfd;

        pthread_rwlock_unlock(&udp_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        /* get the original address with the LISTEN PORT */
        if (getpeername(skfd, (struct sockaddr *) &t_saddr, &t_saddr_len) < 0) {
                LOG_DBG("Flow with fd %d has no peer.", fd);
                return -1;
        }

        /* connect to the flow udp port */
        t_saddr.sin_port = src_udp_port;

        if (connect(skfd, (struct sockaddr *) &t_saddr, sizeof(t_saddr)) < 0) {
                close(skfd);
                return -1;
        }

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_rdlock(&udp_data.flows_lock);

        set_fd(skfd);

        pthread_rwlock_unlock(&udp_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        if (ipcp_flow_alloc_reply(fd, response) < 0)
                return -1;

        LOG_DBG("Flow allocation completed, UDP ports: (%d, %d).",
                 ntohs(dst_udp_port), ntohs(src_udp_port));

        return ret;
}

static int ipcp_udp_flow_dealloc_req(int udp_port)
{
        int skfd = -1;
        int fd   = -1;

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&udp_data.flows_lock);

        fd = udp_port_to_fd(udp_port);
        if (fd < 0) {
                pthread_rwlock_unlock(&udp_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_DBG("Could not find flow on UDP port %d.",
                         ntohs(udp_port));
                return 0;
        }

        skfd = udp_data.fd_to_uf[fd].skfd;

        udp_data.uf_to_fd[skfd]    = -1;
        udp_data.fd_to_uf[fd].udp  = -1;
        udp_data.fd_to_uf[fd].skfd = -1;

        pthread_rwlock_unlock(&udp_data.flows_lock);
        pthread_rwlock_rdlock(&udp_data.flows_lock);

        clr_fd(skfd);

        pthread_rwlock_unlock(&udp_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        flow_dealloc(fd);

        close(skfd);

        LOG_DBG("Flow with fd %d deallocated.", fd);

        return 0;
}

static void * ipcp_udp_listener()
{
        uint8_t buf[SHIM_UDP_MSG_SIZE];
        int  n = 0;
        struct sockaddr_in c_saddr;
        int sfd = udp_data.s_fd;

        while (true) {
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
                                          msg->dst_name,
                                          msg->src_ae_name);
                        break;
                case SHIM_UDP_MSG_CODE__FLOW_REPLY:
                        ipcp_udp_port_alloc_reply(msg->src_udp_port,
                                                  msg->dst_udp_port,
                                                  msg->response);
                        break;
                case SHIM_UDP_MSG_CODE__FLOW_DEALLOC:
                        ipcp_udp_flow_dealloc_req(msg->src_udp_port);
                        break;
                default:
                        LOG_ERR("Unknown message received %d.", msg->code);
                        shim_udp_msg__free_unpacked(msg, NULL);
                        continue;
                }

                c_saddr.sin_port = LISTEN_PORT;

                shim_udp_msg__free_unpacked(msg, NULL);
        }

        return 0;
}

static void * ipcp_udp_sdu_reader()
{
        int n;
        int skfd;
        int fd;
        /* FIXME: avoid this copy */
        char buf[SHIM_UDP_MAX_SDU_SIZE];
        struct sockaddr_in r_saddr;
        fd_set read_fds;
        int flags;
        struct timeval tv = {0, FD_UPDATE_TIMEOUT};

        while (true) {
                pthread_rwlock_rdlock(&ipcpi.state_lock);
                pthread_rwlock_rdlock(&udp_data.flows_lock);
                pthread_mutex_lock(&udp_data.fd_set_lock);

                read_fds = udp_data.flow_fd_s;
                udp_data.fd_set_mod = false;
                pthread_cond_broadcast(&udp_data.fd_set_cond);

                pthread_mutex_unlock(&udp_data.fd_set_lock);
                pthread_rwlock_unlock(&udp_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);

                if (select(FD_SETSIZE, &read_fds, NULL, NULL, &tv) <= 0)
                        continue;

                for (skfd = 0; skfd < FD_SETSIZE; ++skfd) {
                        if (!FD_ISSET(skfd, &read_fds))
                                continue;
                        flags = fcntl(skfd, F_GETFL, 0);
                        fcntl(skfd, F_SETFL, flags | O_NONBLOCK);
                        fd = udp_data.uf_to_fd[skfd];
                        n = sizeof(r_saddr);
                        if ((n = recvfrom(skfd,
                                          &buf,
                                          SHIM_UDP_MAX_SDU_SIZE,
                                          0,
                                          (struct sockaddr *) &r_saddr,
                                          (unsigned *) &n)) <= 0)
                                continue;

                        /* send the sdu to the correct fd */
                        flow_write(fd, buf, n);
                }
        }

        return (void *) 0;
}

static void * ipcp_udp_sdu_loop(void * o)
{

        while (true) {
                int fd;
                struct shm_du_buff * sdb;

                fd = ipcp_read_shim(&sdb);
                if (fd < 0)
                        continue;

                pthread_rwlock_rdlock(&ipcpi.state_lock);
                pthread_rwlock_rdlock(&udp_data.flows_lock);

                fd = udp_data.fd_to_uf[fd].skfd;

                pthread_rwlock_unlock(&udp_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);

                if (send(fd,
                         shm_du_buff_head(sdb),
                         shm_du_buff_tail(sdb) - shm_du_buff_head(sdb),
                         0) < 0)
                        LOG_ERR("Failed to send SDU.");

                ipcp_flow_del(sdb);
        }

        return (void *) 1;
}

void ipcp_sig_handler(int sig, siginfo_t * info, void * c)
{
        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                if (info->si_pid == irmd_api) {
                        pthread_rwlock_wrlock(&ipcpi.state_lock);

                        ipcp_set_state(IPCP_SHUTDOWN);

                        pthread_rwlock_unlock(&ipcpi.state_lock);
                }
        default:
                return;
        }
}

static int ipcp_udp_bootstrap(struct dif_config * conf)
{
        struct sockaddr_in s_saddr;
        char ipstr[INET_ADDRSTRLEN];
        char dnsstr[INET_ADDRSTRLEN];
        int  enable = 1;
        int  fd = -1;

        if (conf == NULL)
                return -1; /* -EINVAL */

        if (conf->type != THIS_TYPE) {
                LOG_ERR("Config doesn't match IPCP type.");
                return -1;
        }

        if (inet_ntop(AF_INET,
                      &conf->ip_addr,
                      ipstr,
                      INET_ADDRSTRLEN) == NULL) {
                LOG_ERR("Failed to convert IP address");
                return -1;
        }

        if (conf->dns_addr != 0) {
                if (inet_ntop(AF_INET,
                              &conf->dns_addr,
                              dnsstr,
                              INET_ADDRSTRLEN) == NULL) {
                        LOG_ERR("Failed to convert DNS address");
                        return -1;
                }
#ifndef CONFIG_OUROBOROS_ENABLE_DNS
                LOG_WARN("DNS disabled at compile time, address ignored");
#endif
        } else {
                strcpy(dnsstr, "not set");
        }

        /* UDP listen server */
        if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
                LOG_ERR("Can't create socket.");
                return -1;
        }

        if (setsockopt(fd,
                       SOL_SOCKET,
                       SO_REUSEADDR,
                       &enable,
                       sizeof(int)) < 0)
                LOG_WARN("Failed to set SO_REUSEADDR.");

        memset((char *) &s_saddr, 0, sizeof(s_saddr));
        udp_data.s_saddr.sin_family      = AF_INET;
        udp_data.s_saddr.sin_addr.s_addr = conf->ip_addr;
        udp_data.s_saddr.sin_port        = LISTEN_PORT;

        if (bind(fd,
                 (struct sockaddr *) &udp_data.s_saddr,
                 sizeof(udp_data.s_saddr)) < 0) {
                LOG_ERR("Couldn't bind to %s.", ipstr);
                close(fd);
                return -1;
        }

        pthread_rwlock_wrlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_INIT) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("IPCP in wrong state.");
                close(fd);
                return -1;
        }

        udp_data.s_fd     = fd;
        udp_data.ip_addr  = conf->ip_addr;
        udp_data.dns_addr = conf->dns_addr;

        FD_CLR(udp_data.s_fd, &udp_data.flow_fd_s);

        ipcp_set_state(IPCP_ENROLLED);

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

        pthread_rwlock_unlock(&ipcpi.state_lock);

        LOG_DBG("Bootstrapped shim IPCP over UDP with api %d.", getpid());
        LOG_DBG("Bound to IP address %s.", ipstr);
        LOG_DBG("DNS server address is %s.", dnsstr);

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
                LOG_ERR("Failed to create pipe.");
                return -1;
        }

        api = fork();
        if (api == -1) {
                LOG_ERR("Failed to fork.");
                return -1;
        }

        if (api == 0) {
                close(pipe_fd[1]);
                dup2(pipe_fd[0], 0);
                execve(argv[0], &argv[0], envp);
        }

        close(pipe_fd[0]);

        if (write(pipe_fd[1], cmd, strlen(cmd)) == -1) {
                LOG_ERR("Failed to communicate with nsupdate.");
                close(pipe_fd[1]);
                return -1;
        }

        waitpid(api, &wstatus, 0);
        if (WIFEXITED(wstatus) == true &&
            WEXITSTATUS(wstatus) == 0)
                LOG_DBG("Succesfully communicated with DNS server.");
        else
                LOG_ERR("Failed to register with DNS server.");

        close(pipe_fd[1]);
        return 0;
}

static uint32_t ddns_resolve(char * name, uint32_t dns_addr)
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
                LOG_ERR("Failed to create pipe.");
                return 0;
        }

        api = fork();
        if (api == -1) {
                LOG_ERR("Failed to fork.");
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
                LOG_ERR("Failed to communicate with nslookup.");
                close(pipe_fd[0]);
                return 0;
        }

        close(pipe_fd[0]);

        waitpid(api, &wstatus, 0);
        if (WIFEXITED(wstatus) == true &&
            WEXITSTATUS(wstatus) == 0)
                LOG_DBG("Succesfully communicated with nslookup.");
        else
                LOG_ERR("Failed to resolve DNS address.");

        buf[count] = '\0';
        substr = strtok(buf, "\n");
        while (substr != NULL) {
                substr2 = substr;
                substr = strtok(NULL, "\n");
        }

        if (strstr(substr2, addr_str) == NULL) {
                LOG_ERR("Failed to resolve DNS address.");
                return 0;
        }

        if (inet_pton(AF_INET, substr2 + strlen(addr_str) + 1, &ip_addr) != 1) {
                LOG_ERR("Failed to resolve DNS address.");
                return 0;
        }

        return ip_addr;
}
#endif

static int ipcp_udp_name_reg(char * name)
{
#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        char ipstr[INET_ADDRSTRLEN];
        char dnsstr[INET_ADDRSTRLEN];
        /* max DNS name length + max IP length + command length */
        char cmd[100];
        uint32_t dns_addr;
        uint32_t ip_addr;
#endif

        if (strlen(name) > 24) {
                LOG_ERR("DNS names cannot be longer than 24 chars.");
                return -1;
        }

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (ipcp_data_add_reg_entry(ipcpi.data, name)) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_ERR("Failed to add %s to local registry.", name);
                return -1;
        }

#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        /* register application with DNS server */

        dns_addr = udp_data.dns_addr;

        pthread_rwlock_unlock(&ipcpi.state_lock);

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
                        dnsstr, name, DNS_TTL, ipstr);

                if (ddns_send(cmd)) {
                        pthread_rwlock_rdlock(&ipcpi.state_lock);
                        ipcp_data_del_reg_entry(ipcpi.data, name);
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        return -1;
                }
        }
#else
        pthread_rwlock_unlock(&ipcpi.state_lock);
#endif
        LOG_DBG("Registered %s.", name);

        return 0;
}

static int ipcp_udp_name_unreg(char * name)
{
#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        char dnsstr[INET_ADDRSTRLEN];
        /* max DNS name length + max IP length + max command length */
        char cmd[100];
        uint32_t dns_addr;
#endif

        if (strlen(name) > 24) {
                LOG_ERR("DNS names cannot be longer than 24 chars.");
                return -1;
        }

#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        /* unregister application with DNS server */

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        dns_addr = udp_data.dns_addr;

        pthread_rwlock_unlock(&ipcpi.state_lock);

        if (dns_addr != 0) {
                if (inet_ntop(AF_INET, &dns_addr, dnsstr, INET_ADDRSTRLEN)
                    == NULL) {
                        return -1;
                }
                sprintf(cmd, "server %s\nupdate delete %s A\nsend\nquit\n",
                        dnsstr, name);

                ddns_send(cmd);
        }
#endif

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        ipcp_data_del_reg_entry(ipcpi.data, name);

        pthread_rwlock_unlock(&ipcpi.state_lock);

        return 0;
}

static int ipcp_udp_flow_alloc(int           fd,
                               char *        dst_name,
                               char *        src_ae_name,
                               enum qos_cube qos)
{
        struct sockaddr_in r_saddr; /* server address */
        struct sockaddr_in f_saddr; /* flow */
        socklen_t          f_saddr_len = sizeof(f_saddr);
        int                skfd;
        struct hostent *   h;
        uint32_t           ip_addr = 0;
#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        uint32_t           dns_addr = 0;
#endif
        LOG_DBG("Allocating flow to %s.", dst_name);

        if (dst_name == NULL || src_ae_name == NULL)
                return -1;
        if (strlen(dst_name) > 255
            || strlen(src_ae_name) > 255) {
                LOG_ERR("Name too long for this shim.");
                return -1;
        }

        if (qos != QOS_CUBE_BE)
                LOG_DBG("QoS requested. UDP/IP can't do that.");

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
                LOG_ERR("Could not get address from fd.");
                close(skfd);
                return -1;
        }

        pthread_rwlock_rdlock(&ipcpi.state_lock);

        if (ipcp_get_state() != IPCP_ENROLLED) {
                pthread_rwlock_unlock(&ipcpi.state_lock);
                LOG_DBG("Won't allocate flow with non-enrolled IPCP.");
                close(skfd);
                return -1; /* -ENOTENROLLED */
        }

#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        dns_addr = udp_data.dns_addr;

        if (dns_addr != 0) {
                pthread_rwlock_unlock(&ipcpi.state_lock);

                ip_addr = ddns_resolve(dst_name, dns_addr);
                if (ip_addr == 0) {
                        LOG_DBG("Could not resolve %s.", dst_name);
                        close(fd);
                        return -1;
                }

                pthread_rwlock_rdlock(&ipcpi.state_lock);
                if (ipcp_get_state() != IPCP_ENROLLED) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        LOG_DBG("Won't allocate flow with non-enrolled IPCP.");
                        close(skfd);
                        return -1; /* -ENOTENROLLED */
                }
        } else {
#endif
                h = gethostbyname(dst_name);
                if (h == NULL) {
                        LOG_DBG("Could not resolve %s.", dst_name);
                        close(skfd);
                        return -1;
                }

                ip_addr = *((uint32_t *) (h->h_addr_list[0]));
#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        }
#endif

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

        pthread_rwlock_unlock(&udp_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        if (ipcp_udp_port_alloc(ip_addr,
                                f_saddr.sin_port,
                                dst_name,
                                src_ae_name) < 0) {
                pthread_rwlock_rdlock(&ipcpi.state_lock);
                pthread_rwlock_wrlock(&udp_data.flows_lock);

                udp_data.fd_to_uf[fd].udp  = -1;
                udp_data.fd_to_uf[fd].skfd = -1;
                udp_data.uf_to_fd[skfd]    = -1;

                pthread_rwlock_unlock(&udp_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);
                close(skfd);
                return -1;
        }

        LOG_DBG("Flow pending on fd %d, UDP port %d.",
                fd, ntohs(f_saddr.sin_port));

        return fd;
}

static int ipcp_udp_flow_alloc_resp(int fd, int response)
{
        int skfd = -1;
        struct sockaddr_in f_saddr;
        struct sockaddr_in r_saddr;
        socklen_t len = sizeof(r_saddr);

        if (response)
                return 0;

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&udp_data.flows_lock);

        skfd = udp_data.fd_to_uf[fd].skfd;

        if (getsockname(skfd, (struct sockaddr *) &f_saddr, &len) < 0) {
                LOG_DBG("Socket with fd %d has no address.", skfd);
                return -1;
        }

        if (getpeername(skfd, (struct sockaddr *) &r_saddr, &len) < 0) {
                LOG_DBG("Socket with fd %d has no peer.", skfd);
                return -1;
        }

        pthread_rwlock_unlock(&udp_data.flows_lock);
        pthread_rwlock_rdlock(&udp_data.flows_lock);

        set_fd(skfd);

        pthread_rwlock_unlock(&udp_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        if (ipcp_udp_port_alloc_resp(r_saddr.sin_addr.s_addr,
                                     f_saddr.sin_port,
                                     r_saddr.sin_port,
                                     response) < 0) {
                pthread_rwlock_rdlock(&ipcpi.state_lock);
                pthread_rwlock_rdlock(&udp_data.flows_lock);
                clr_fd(skfd);
                pthread_rwlock_unlock(&udp_data.flows_lock);
                pthread_rwlock_unlock(&ipcpi.state_lock);

                return -1;
        }

        LOG_DBG("Accepted flow, fd %d on UDP port %d.",
                fd, ntohs(f_saddr.sin_port));

        return 0;
}

static int ipcp_udp_flow_dealloc(int fd)
{
        int skfd = -1;
        int remote_udp = -1;
        struct sockaddr_in    r_saddr;
        socklen_t             r_saddr_len = sizeof(r_saddr);

        pthread_rwlock_rdlock(&ipcpi.state_lock);
        pthread_rwlock_wrlock(&udp_data.flows_lock);

        skfd = udp_data.fd_to_uf[fd].skfd;

        udp_data.uf_to_fd[skfd]    = -1;
        udp_data.fd_to_uf[fd].udp  = -1;
        udp_data.fd_to_uf[fd].skfd = -1;

        pthread_rwlock_unlock(&udp_data.flows_lock);
        pthread_rwlock_rdlock(&udp_data.flows_lock);

        clr_fd(skfd);

        pthread_rwlock_unlock(&udp_data.flows_lock);
        pthread_rwlock_unlock(&ipcpi.state_lock);

        if (getpeername(skfd, (struct sockaddr *) &r_saddr, &r_saddr_len) < 0) {
                LOG_DBG("Socket with fd %d has no peer.", skfd);
                close(skfd);
                return 0;
        }

        remote_udp       = r_saddr.sin_port;
        r_saddr.sin_port = LISTEN_PORT;

        if (connect(skfd, (struct sockaddr *) &r_saddr, sizeof(r_saddr)) < 0) {
                close(skfd);
                return 0 ;
        }

        if (ipcp_udp_port_dealloc(r_saddr.sin_addr.s_addr, remote_udp) < 0) {
                LOG_DBG("Could not notify remote.");
                close(skfd);
                return 0;
        }

        close(skfd);

        LOG_DBG("Flow with fd %d deallocated.", fd);

        return 0;
}

static struct ipcp_ops udp_ops = {
        .ipcp_bootstrap       = ipcp_udp_bootstrap,
        .ipcp_enroll          = NULL,                       /* shim */
        .ipcp_name_reg        = ipcp_udp_name_reg,
        .ipcp_name_unreg      = ipcp_udp_name_unreg,
        .ipcp_flow_alloc      = ipcp_udp_flow_alloc,
        .ipcp_flow_alloc_resp = ipcp_udp_flow_alloc_resp,
        .ipcp_flow_dealloc    = ipcp_udp_flow_dealloc
};

int main(int argc, char * argv[])
{
        struct sigaction sig_act;
        sigset_t  sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        if (ipcp_parse_arg(argc, argv)) {
                LOG_ERR("Failed to parse arguments.");
                exit(EXIT_FAILURE);
        }

        udp_data_init();

        if (ap_init(NULL) < 0) {
                close_logfile();
                exit(EXIT_FAILURE);
        }

        /* store the process id of the irmd */
        irmd_api = atoi(argv[1]);

        /* init sig_act */
        memset(&sig_act, 0, sizeof(sig_act));

        /* install signal traps */
        sig_act.sa_sigaction = &ipcp_sig_handler;
        sig_act.sa_flags     = SA_SIGINFO;

        sigaction(SIGINT,  &sig_act, NULL);
        sigaction(SIGTERM, &sig_act, NULL);
        sigaction(SIGHUP,  &sig_act, NULL);
        sigaction(SIGPIPE, &sig_act, NULL);

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (ipcp_init(THIS_TYPE, &udp_ops) < 0) {
                close_logfile();
                exit(EXIT_FAILURE);
        }

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        if (ipcp_create_r(getpid())) {
                LOG_ERR("Failed to notify IRMd we are initialized.");
                close_logfile();
                exit(EXIT_FAILURE);
        }

        ipcp_fini();

        pthread_cancel(udp_data.handler);
        pthread_cancel(udp_data.sdu_reader);
        pthread_cancel(udp_data.sduloop);

        pthread_join(udp_data.sduloop, NULL);
        pthread_join(udp_data.handler, NULL);
        pthread_join(udp_data.sdu_reader, NULL);

        ap_fini();

        udp_data_fini();

        close_logfile();

        exit(EXIT_SUCCESS);
}
