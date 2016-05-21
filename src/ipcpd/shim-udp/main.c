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
#include "flow.h"
#include "shim_udp_config.h"
#include <ouroboros/shm_du_map.h>
#include <ouroboros/shm_ap_rbuff.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/dif_config.h>
#include <ouroboros/sockets.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/flow.h>
#include <ouroboros/dev.h>
#include <ouroboros/rw_lock.h>

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

#define shim_data(type) ((struct ipcp_udp_data *) type->data)

#define local_ip (((struct ipcp_udp_data *)                     \
                   _ipcp->data)->s_saddr.sin_addr.s_addr)

/* global for trapping signal */
int irmd_pid;

/* this IPCP's data */
#ifdef MAKE_CHECK
extern struct ipcp * _ipcp; /* defined in test */
#else
struct ipcp * _ipcp;
#endif

/*
 * copied from ouroboros/dev. The shim needs access to the internals
 * because it doesn't follow all steps necessary steps to get
 * the info
 */

/* the shim needs access to these internals */
struct shim_ap_data {
        instance_name_t *     api;
        struct shm_du_map *   dum;
        struct bmp *          fds;
        struct shm_ap_rbuff * rb;

        struct flow           flows[AP_MAX_FLOWS];
        rw_lock_t             flows_lock;

        pthread_t             mainloop;
        pthread_t             sduloop;
        pthread_t             handler;
        pthread_t             sdu_reader;

        bool                  fd_set_sync;
        pthread_mutex_t       fd_set_lock;
} * _ap_instance;

static int shim_ap_init(char * ap_name)
{
        int i;

        _ap_instance = malloc(sizeof(struct shim_ap_data));
        if (_ap_instance == NULL) {
                return -1;
        }

        _ap_instance->api = instance_name_create();
        if (_ap_instance->api == NULL) {
                free(_ap_instance);
                return -1;
        }

        if (instance_name_init_from(_ap_instance->api,
                                    ap_name,
                                    getpid()) == NULL) {
                instance_name_destroy(_ap_instance->api);
                free(_ap_instance);
                return -1;
        }

        _ap_instance->fds = bmp_create(AP_MAX_FLOWS, 0);
        if (_ap_instance->fds == NULL) {
                instance_name_destroy(_ap_instance->api);
                free(_ap_instance);
                return -1;
        }

        _ap_instance->dum = shm_du_map_open();
        if (_ap_instance->dum == NULL) {
                instance_name_destroy(_ap_instance->api);
                bmp_destroy(_ap_instance->fds);
                free(_ap_instance);
                return -1;
        }

        _ap_instance->rb = shm_ap_rbuff_create();
        if (_ap_instance->rb == NULL) {
                instance_name_destroy(_ap_instance->api);
                shm_du_map_close(_ap_instance->dum);
                bmp_destroy(_ap_instance->fds);
                free(_ap_instance);
                return -1;
        }

        for (i = 0; i < AP_MAX_FLOWS; i ++) {
                _ap_instance->flows[i].rb = NULL;
                _ap_instance->flows[i].port_id = -1;
                _ap_instance->flows[i].state = FLOW_NULL;
        }

        rw_lock_init(&_ap_instance->flows_lock);
        pthread_mutex_init(&_ap_instance->fd_set_lock, NULL);

        return 0;
}

void shim_ap_fini()
{
        int i = 0;

        if (_ap_instance == NULL)
                return;

        rw_lock_wrlock(&_ipcp->state_lock);

        if (_ipcp->state != IPCP_SHUTDOWN)
                LOG_WARN("Cleaning up AP while not in shutdown.");

        if (_ap_instance->api != NULL)
                instance_name_destroy(_ap_instance->api);
        if (_ap_instance->fds != NULL)
                bmp_destroy(_ap_instance->fds);
        if (_ap_instance->dum != NULL)
                shm_du_map_close(_ap_instance->dum);
        if (_ap_instance->rb != NULL)
                shm_ap_rbuff_destroy(_ap_instance->rb);

        rw_lock_wrlock(&_ap_instance->flows_lock);

        for (i = 0; i < AP_MAX_FLOWS; i ++)
                if (_ap_instance->flows[i].rb != NULL)
                        shm_ap_rbuff_close(_ap_instance->flows[i].rb);

        rw_lock_unlock(&_ap_instance->flows_lock);
        rw_lock_unlock(&_ipcp->state_lock);

        free(_ap_instance);
}

/* only call this under flows_lock */
static int port_id_to_fd(int port_id)
{
        int i;

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                if (_ap_instance->flows[i].port_id == port_id
                    && _ap_instance->flows[i].state != FLOW_NULL)
                        return i;
        }

        return -1;
}

static ssize_t ipcp_udp_flow_write(int fd, void * buf, size_t count)
{
        ssize_t index;
        struct rb_entry e;

        rw_lock_rdlock(&_ipcp->state_lock);

        if (_ipcp->state != IPCP_ENROLLED) {
                rw_lock_unlock(&_ipcp->state_lock);
                return -1; /* -ENOTENROLLED */
        }

        index = shm_create_du_buff(_ap_instance->dum, count, 0, buf, count);

        if (index == -1) {
                return -1;
        }

        e.index = index;

        rw_lock_rdlock(&_ap_instance->flows_lock);

        e.port_id = _ap_instance->flows[fd].port_id;

        if (shm_ap_rbuff_write(_ap_instance->flows[fd].rb, &e) < 0) {
                rw_lock_unlock(&_ap_instance->flows_lock);
                shm_release_du_buff(_ap_instance->dum, index);
                return -EPIPE;
        }

        rw_lock_unlock(&_ap_instance->flows_lock);

        rw_lock_unlock(&_ipcp->state_lock);

        return 0;
}

/*
 * end copy from dev.c
 */

/* only call this under flows_lock */
static int udp_port_to_fd(int udp_port)
{
        int i;
        struct sockaddr_in f_saddr;
        socklen_t len = sizeof(f_saddr);

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                if (getsockname(i, (struct sockaddr *) &f_saddr, &len) < 0)
                        continue;
                if (f_saddr.sin_port == udp_port)
                        return i;
        }

        return -1;
}

struct ipcp_udp_data {
        /* keep ipcp_data first for polymorphism */
        struct ipcp_data ipcp_data;

        uint32_t ip_addr;
        uint32_t dns_addr;
        /* listen server */
        struct sockaddr_in s_saddr;
        int                s_fd;

        /* only modify under _ap_instance->flows_lock */
        fd_set flow_fd_s;
};

struct ipcp_udp_data * ipcp_udp_data_create()
{
        struct ipcp_udp_data * udp_data;
        struct ipcp_data *     data;
        enum ipcp_type         ipcp_type;

        udp_data = malloc(sizeof(*udp_data));
        if (udp_data == NULL) {
                LOG_ERR("Failed to allocate.");
                return NULL;
        }

        ipcp_type = THIS_TYPE;
        data = (struct ipcp_data *) udp_data;
        if (ipcp_data_init(data, ipcp_type) == NULL) {
                free(udp_data);
                return NULL;
        }

        FD_ZERO(&udp_data->flow_fd_s);

        return udp_data;
}

static void set_fd(int fd)
{
        bool fd_wait = true;

        pthread_mutex_lock(&_ap_instance->fd_set_lock);

        _ap_instance->fd_set_sync =  true;
        FD_SET(fd, &shim_data(_ipcp)->flow_fd_s);

        pthread_mutex_unlock(&_ap_instance->fd_set_lock);

        while (fd_wait) {
                sched_yield();
                pthread_mutex_lock(&_ap_instance->fd_set_lock);
                fd_wait = _ap_instance->fd_set_sync;
                pthread_mutex_unlock(&_ap_instance->fd_set_lock);
        }
}

static void clr_fd(int fd)
{
        bool fd_wait = true;

        pthread_mutex_lock(&_ap_instance->fd_set_lock);

        _ap_instance->fd_set_sync =  true;
        FD_CLR(fd, &shim_data(_ipcp)->flow_fd_s);

        pthread_mutex_unlock(&_ap_instance->fd_set_lock);

        while (fd_wait) {
                sched_yield();
                pthread_mutex_lock(&_ap_instance->fd_set_lock);
                fd_wait = _ap_instance->fd_set_sync;
                pthread_mutex_unlock(&_ap_instance->fd_set_lock);
        }
}


static int send_shim_udp_msg(shim_udp_msg_t * msg,
                             uint32_t dst_ip_addr)
{
       buffer_t           buf;
       struct sockaddr_in r_saddr;

       memset((char *)&r_saddr, 0, sizeof(r_saddr));
       r_saddr.sin_family      = AF_INET;
       r_saddr.sin_addr.s_addr = dst_ip_addr;
       r_saddr.sin_port        = LISTEN_PORT;

       buf.size = shim_udp_msg__get_packed_size(msg);
       if (buf.size == 0) {
               return -1;
       }

       buf.data = malloc(SHIM_UDP_MSG_SIZE);
       if (buf.data == NULL) {
               return -1;
       }

       shim_udp_msg__pack(msg, buf.data);

       if (sendto(shim_data(_ipcp)->s_fd,
                  buf.data,
                  buf.size,
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
                               char *   src_ap_name,
                               char *   src_ae_name)
{
        shim_udp_msg_t msg = SHIM_UDP_MSG__INIT;

        msg.code         = SHIM_UDP_MSG_CODE__FLOW_REQ;
        msg.src_udp_port = src_udp_port;
        msg.dst_name     = dst_name;
        msg.src_ap_name  = src_ap_name;
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
                             char * src_ap_name,
                             char * src_ae_name)
{
        int  fd;
        int  port_id;

        struct sockaddr_in f_saddr;
        socklen_t          f_saddr_len = sizeof(f_saddr);

        LOG_DBGF("Port request arrived from UDP port %d",
                 ntohs(c_saddr->sin_port));

        if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
                LOG_ERR("Could not create UDP socket.");
                return -1;
        }

        memset((char *) &f_saddr, 0, sizeof(f_saddr));
        f_saddr.sin_family      = AF_INET;
        f_saddr.sin_addr.s_addr = local_ip;

        /*
         * FIXME: we could have a port dedicated per registered AP
         * Not that critical for UDP, but will be for LLC
         */

        f_saddr.sin_port        = 0;

        if (bind(fd, (struct sockaddr *) &f_saddr, sizeof(f_saddr)) < 0) {
                LOG_ERR("Could not bind to socket.");
                close(fd);
                return -1;
        }

        if (getsockname(fd, (struct sockaddr *) &f_saddr, &f_saddr_len) < 0) {
                LOG_ERR("Could not get address from fd.");
                return -1;
        }

        /*
         * store the remote address in the file descriptor
         * this avoids having to store the sockaddr_in in
         * the flow structure
         */

        if (connect(fd, (struct sockaddr *) c_saddr, sizeof(*c_saddr)) < 0) {
                LOG_ERR("Could not connect to remote UDP client.");
                close(fd);
                return -1;
        }


        rw_lock_rdlock(&_ipcp->state_lock);
        rw_lock_wrlock(&_ap_instance->flows_lock);

        /* reply to IRM */
        port_id = ipcp_flow_req_arr(getpid(),
                                    dst_name,
                                    src_ap_name,
                                    src_ae_name);

        if (port_id < 0) {
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_ERR("Could not get port id from IRMd");
                close(fd);
                return -1;
        }

        _ap_instance->flows[fd].port_id = port_id;
        _ap_instance->flows[fd].rb      = NULL;
        _ap_instance->flows[fd].state   = FLOW_PENDING;

        rw_lock_unlock(&_ap_instance->flows_lock);
        rw_lock_unlock(&_ipcp->state_lock);

        LOG_DBGF("Pending allocation request, port_id %d, UDP port (%d, %d).",
                 port_id, ntohs(f_saddr.sin_port), ntohs(c_saddr->sin_port));

        return 0;
}

static int ipcp_udp_port_alloc_reply(int src_udp_port,
                                     int dst_udp_port,
                                     int response)
{
        int  fd        = -1;
        int  ret       =  0;
        int  port_id   = -1;

        struct sockaddr_in t_saddr;
        socklen_t          t_saddr_len = sizeof(t_saddr);

        LOG_DBGF("Received reply for flow on udp port %d.",
                 ntohs(dst_udp_port));

        rw_lock_rdlock(&_ipcp->state_lock);
        rw_lock_rdlock(&_ap_instance->flows_lock);

        fd = udp_port_to_fd(dst_udp_port);
        if (fd == -1) {
                rw_lock_unlock(&_ap_instance->flows_lock);
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Unknown flow on UDP port %d.", dst_udp_port);
                return -1; /* -EUNKNOWNFLOW */
        }

        if (_ap_instance->flows[fd].state != FLOW_PENDING) {
                rw_lock_unlock(&_ap_instance->flows_lock);
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Flow on UDP port %d not pending.", dst_udp_port);
                return -1; /* -EFLOWNOTPENDING */
        }

        port_id = _ap_instance->flows[fd].port_id;

        if (response) {
                _ap_instance->flows[fd].port_id = -1;
                _ap_instance->flows[fd].rb      = NULL;
                shm_ap_rbuff_close(_ap_instance->flows[fd].rb);
                _ap_instance->flows[fd].state   = FLOW_NULL;
        } else {
                /* get the original address with the LISTEN PORT */
                if (getpeername(fd,
                                (struct sockaddr *) &t_saddr,
                                &t_saddr_len) < 0) {
                        rw_lock_unlock(&_ap_instance->flows_lock);
                        rw_lock_unlock(&_ipcp->state_lock);
                        LOG_DBGF("Flow with port_id %d has no peer.", port_id);
                        return -1;
                }

                /* connect to the flow udp port */
                t_saddr.sin_port = src_udp_port;

                if (connect(fd,
                            (struct sockaddr *) &t_saddr,
                            sizeof(t_saddr)) < 0) {
                        rw_lock_unlock(&_ap_instance->flows_lock);
                        rw_lock_unlock(&_ipcp->state_lock);
                        close(fd);
                        return -1;
                }

                _ap_instance->flows[fd].state   = FLOW_ALLOCATED;
        }

        rw_lock_unlock(&_ap_instance->flows_lock);
        rw_lock_unlock(&_ipcp->state_lock);


        if ((ret = ipcp_flow_alloc_reply(getpid(),
                                         port_id,
                                         response)) < 0) {
                return -1; /* -EPIPE */
        }

        LOG_INFO("Flow allocation completed, UDP ports: (%d, %d).",
                 ntohs(dst_udp_port), ntohs(src_udp_port));

        return ret;

}

static int ipcp_udp_flow_dealloc_req(int udp_port)
{
        int fd          = -1;
        struct shm_ap_rbuff * rb;
        int port_id     = -1;

        rw_lock_rdlock(&_ipcp->state_lock);
        rw_lock_wrlock(&_ap_instance->flows_lock);

        fd = udp_port_to_fd(udp_port);
        if (fd < 0) {
                rw_lock_unlock(&_ap_instance->flows_lock);
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Could not find flow on UDP port %d.",
                         ntohs(udp_port));
                return 0;
        }

        clr_fd(fd);

        _ap_instance->flows[fd].state   = FLOW_NULL;
        port_id = _ap_instance->flows[fd].port_id;
        _ap_instance->flows[fd].port_id = -1;
        rb = _ap_instance->flows[fd].rb;
        _ap_instance->flows[fd].rb      = NULL;

        rw_lock_unlock(&_ap_instance->flows_lock);

        if (rb != NULL)
                shm_ap_rbuff_close(rb);

        rw_lock_unlock(&_ipcp->state_lock);

        ipcp_flow_dealloc(0, port_id);

        close(fd);

        LOG_DBGF("Flow with port_id %d deallocated.", port_id);

        return 0;
}

static void * ipcp_udp_listener()
{
        uint8_t buf[SHIM_UDP_MSG_SIZE];
        int  n = 0;

        struct sockaddr_in c_saddr;

        while (true) {
                int sfd = 0;
                shim_udp_msg_t * msg = NULL;

                rw_lock_rdlock(&_ipcp->state_lock);

                if (_ipcp->state != IPCP_ENROLLED) {
                        rw_lock_unlock(&_ipcp->state_lock);
                        return (void *) 1; /* -ENOTENROLLED */
                }

                sfd = shim_data(_ipcp)->s_fd;

                rw_lock_unlock(&_ipcp->state_lock);

                memset(&buf, 0, SHIM_UDP_MSG_SIZE);
                n = sizeof(c_saddr);
                n = recvfrom(sfd, buf, SHIM_UDP_MSG_SIZE, 0,
                             (struct sockaddr *) &c_saddr, (unsigned *) &n);

                if (n < 0) {
                        continue;
                }

                /* flow alloc request from other host */
                if (gethostbyaddr((const char *) &c_saddr.sin_addr.s_addr,
                                  sizeof(c_saddr.sin_addr.s_addr), AF_INET)
                    == NULL) {
                        continue;
                }

                msg = shim_udp_msg__unpack(NULL, n, buf);
                if (msg == NULL) {
                        continue;
                }

                switch (msg->code) {
                case SHIM_UDP_MSG_CODE__FLOW_REQ:
                        c_saddr.sin_port = msg->src_udp_port;
                        ipcp_udp_port_req(&c_saddr,
                                          msg->dst_name,
                                          msg->src_ap_name,
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
        int fd;
        char buf[SHIM_UDP_MAX_SDU_SIZE];
        struct timeval tv = {0, 100};
        struct sockaddr_in r_saddr;
        fd_set read_fds;
        int flags;

        while (true) {
                rw_lock_rdlock(&_ipcp->state_lock);

                if (_ipcp->state != IPCP_ENROLLED) {
                        rw_lock_unlock(&_ipcp->state_lock);
                        return (void *) 1; /* -ENOTENROLLED */
                }

                rw_lock_rdlock(&_ap_instance->flows_lock);

                pthread_mutex_lock(&_ap_instance->fd_set_lock);

                read_fds = shim_data(_ipcp)->flow_fd_s;
                _ap_instance->fd_set_sync = false;

                pthread_mutex_unlock(&_ap_instance->fd_set_lock);

                rw_lock_unlock(&_ap_instance->flows_lock);
                rw_lock_unlock(&_ipcp->state_lock);

                if (select(FD_SETSIZE, &read_fds, NULL, NULL, &tv) <= 0) {
                        continue;
                }

                for (fd = 0; fd < FD_SETSIZE; ++fd) {
                        if (!FD_ISSET(fd, &read_fds))
                                continue;
                        flags = fcntl(fd, F_GETFL, 0);
                        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

                        n = sizeof(r_saddr);
                        if ((n = recvfrom(fd,
                                          buf,
                                          SHIM_UDP_MAX_SDU_SIZE,
                                          0,
                                          (struct sockaddr *) &r_saddr,
                                          (unsigned *) &n)) <= 0)
                                continue;

                        /* send the sdu to the correct port_id */
                        if (ipcp_udp_flow_write(fd, buf, n) < 0)
                                LOG_ERR("Failed to write SDU.");
                }
        }

        return (void *) 0;
}

/* FIXME: if we move _ap_instance to dev.h, we can reuse it everywhere */
static void * ipcp_udp_sdu_loop(void * o)
{

        while (true) {
                struct rb_entry * e;
                int fd;
                int len = 0;
                char * buf;

                rw_lock_rdlock(&_ipcp->state_lock);

                if (_ipcp->state != IPCP_ENROLLED) {
                        rw_lock_unlock(&_ipcp->state_lock);
                        return (void *) 1; /* -ENOTENROLLED */
                }

                e = shm_ap_rbuff_read(_ap_instance->rb);

                if (e == NULL) {
                        rw_lock_unlock(&_ipcp->state_lock);
                        continue;
                }

                len = shm_du_map_read_sdu((uint8_t **) &buf,
                                          _ap_instance->dum,
                                          e->index);
                if (len <= 0) {
                        rw_lock_unlock(&_ipcp->state_lock);
                        free(e);
                        continue;
                }

                rw_lock_rdlock(&_ap_instance->flows_lock);

                fd = port_id_to_fd(e->port_id);

                rw_lock_unlock(&_ap_instance->flows_lock);
                rw_lock_unlock(&_ipcp->state_lock);

                if (fd == -1) {
                        free(e);
                        continue;
                }

                if (send(fd, buf, len, 0) < 0)
                        LOG_ERR("Failed to send SDU.");

                rw_lock_rdlock(&_ipcp->state_lock);

                if (_ap_instance->dum != NULL)
                        shm_release_du_buff(_ap_instance->dum, e->index);

                rw_lock_unlock(&_ipcp->state_lock);
        }

        return (void *) 1;
}

void ipcp_sig_handler(int sig, siginfo_t * info, void * c)
{
        sigset_t  sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);

        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                if (info->si_pid == irmd_pid || info->si_pid == 0) {
                        LOG_DBG("Terminating by order of %d. Bye.",
                                info->si_pid);

                        rw_lock_wrlock(&_ipcp->state_lock);

                        if (_ipcp->state == IPCP_ENROLLED) {
                                pthread_cancel(_ap_instance->handler);
                                pthread_cancel(_ap_instance->sdu_reader);
                                pthread_cancel(_ap_instance->sduloop);

                                pthread_join(_ap_instance->sduloop, NULL);
                                pthread_join(_ap_instance->handler, NULL);
                                pthread_join(_ap_instance->sdu_reader, NULL);
                        }

                        pthread_cancel(_ap_instance->mainloop);

                        _ipcp->state = IPCP_SHUTDOWN;

                        rw_lock_unlock(&_ipcp->state_lock);
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
                LOG_WARN("Setsockopt(SO_REUSEADDR) failed.");

        memset((char *) &s_saddr, 0, sizeof(s_saddr));
        shim_data(_ipcp)->s_saddr.sin_family      = AF_INET;
        shim_data(_ipcp)->s_saddr.sin_addr.s_addr = conf->ip_addr;
        shim_data(_ipcp)->s_saddr.sin_port        = LISTEN_PORT;

        if (bind(fd,
                 (struct sockaddr *) &shim_data(_ipcp)->s_saddr,
                 sizeof(shim_data(_ipcp)->s_saddr)) < 0) {
                LOG_ERR("Couldn't bind to %s.", ipstr);
                close(fd);
                return -1;
        }

        rw_lock_wrlock(&_ipcp->state_lock);

        if (_ipcp->state != IPCP_INIT) {
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_ERR("IPCP in wrong state.");
                close(fd);
                return -1;
        }

        shim_data(_ipcp)->s_fd     = fd;
        shim_data(_ipcp)->ip_addr  = conf->ip_addr;
        shim_data(_ipcp)->dns_addr = conf->dns_addr;

        FD_CLR(shim_data(_ipcp)->s_fd, &shim_data(_ipcp)->flow_fd_s);

        _ipcp->state = IPCP_ENROLLED;

        pthread_create(&_ap_instance->handler,
                       NULL,
                       ipcp_udp_listener,
                       NULL);
        pthread_create(&_ap_instance->sdu_reader,
                       NULL,
                       ipcp_udp_sdu_reader,
                       NULL);

        pthread_create(&_ap_instance->sduloop,
                       NULL,
                       ipcp_udp_sdu_loop,
                       NULL);

        rw_lock_unlock(&_ipcp->state_lock);

        LOG_DBG("Bootstrapped shim IPCP over UDP with pid %d.",
                getpid());

        LOG_DBG("Bound to IP address %s.", ipstr);
        LOG_DBG("DNS server address is %s.", dnsstr);

        return 0;
}

#ifdef CONFIG_OUROBOROS_ENABLE_DNS
/* FIXME: Dependency on nsupdate to be removed in the end */
/* NOTE: Disgusted with this crap */
static int ddns_send(char * cmd)
{
        pid_t pid = 0;
        int wstatus;
        int pipe_fd[2];
        char * argv[] = {NSUPDATE_EXEC, 0};
        char * envp[] = {0};

        if (pipe(pipe_fd)) {
                LOG_ERR("Failed to create pipe.");
                return -1;
        }

        pid = fork();
        if (pid == -1) {
                LOG_ERR("Failed to fork.");
                return -1;
        }

        if (pid == 0) {
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

        waitpid(pid, &wstatus, 0);
        if (WIFEXITED(wstatus) == true &&
            WEXITSTATUS(wstatus) == 0)
                LOG_DBGF("Succesfully communicated with DNS server.");
        else
                LOG_ERR("Failed to register with DNS server.");

        close(pipe_fd[1]);
        return 0;
}

static uint32_t ddns_resolve(char * name, uint32_t dns_addr)
{
        pid_t pid = 0;
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

        pid = fork();
        if (pid == -1) {
                LOG_ERR("Failed to fork.");
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
                LOG_ERR("Failed to communicate with nslookup.");
                close(pipe_fd[0]);
                return 0;
        }

        close(pipe_fd[0]);

        waitpid(pid, &wstatus, 0);
        if (WIFEXITED(wstatus) == true &&
            WEXITSTATUS(wstatus) == 0)
                LOG_DBGF("Succesfully communicated with nslookup.");
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

        rw_lock_rdlock(&_ipcp->state_lock);

        if (_ipcp->state != IPCP_ENROLLED) {
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Won't register with non-enrolled IPCP.");
                return -1; /* -ENOTENROLLED */
        }

        if (ipcp_data_add_reg_entry(_ipcp->data, name)) {
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_ERR("Failed to add %s to local registry.", name);
                return -1;
        }

#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        /* register application with DNS server */

        dns_addr = shim_data(_ipcp)->dns_addr;

        rw_lock_unlock(&_ipcp->state_lock);

        if (dns_addr != 0) {
                ip_addr = shim_data(_ipcp)->ip_addr;

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
                        rw_lock_rdlock(&_ipcp->state_lock);
                        ipcp_data_del_reg_entry(_ipcp->data, name);
                        rw_lock_unlock(&_ipcp->state_lock);
                        return -1;
                }
        }
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

        rw_lock_rdlock(&_ipcp->state_lock);

        if (_ipcp->state != IPCP_ENROLLED) {
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_DBGF("IPCP is not enrolled");
                return -1; /* -ENOTENROLLED */
        }

        dns_addr = shim_data(_ipcp)->dns_addr;

        rw_lock_unlock(&_ipcp->state_lock);

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

        rw_lock_rdlock(&_ipcp->state_lock);

        ipcp_data_del_reg_entry(_ipcp->data, name);

        rw_lock_unlock(&_ipcp->state_lock);

        return 0;
}

static int ipcp_udp_flow_alloc(pid_t         n_pid,
                               int           port_id,
                               char *        dst_name,
                               char *        src_ap_name,
                               char *        src_ae_name,
                               enum qos_cube qos)
{
        struct sockaddr_in r_saddr; /* server address */
        struct sockaddr_in f_saddr; /* flow */
        socklen_t          f_saddr_len = sizeof(f_saddr);
        int                fd;
        struct hostent *   h;
        uint32_t           ip_addr = 0;
#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        uint32_t           dns_addr = 0;
#endif
        struct shm_ap_rbuff * rb;

        LOG_INFO("Allocating flow from %s to %s.", src_ap_name, dst_name);

        if (dst_name == NULL || src_ap_name == NULL || src_ae_name == NULL)
                return -1;
        if (strlen(dst_name) > 255
            || strlen(src_ap_name) > 255
            || strlen(src_ae_name) > 255) {
                LOG_ERR("Name too long for this shim.");
                return -1;
        }

        if (qos != QOS_CUBE_BE)
                LOG_DBGF("QoS requested. UDP/IP can't do that.");

        rb = shm_ap_rbuff_open(n_pid);
        if (rb == NULL)
                return -1; /* -ENORBUFF */

        fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        /* this socket is for the flow */
        memset((char *) &f_saddr, 0, sizeof(f_saddr));
        f_saddr.sin_family      = AF_INET;
        f_saddr.sin_addr.s_addr = local_ip;
        f_saddr.sin_port        = 0;

        if (bind(fd, (struct sockaddr *) &f_saddr, sizeof(f_saddr)) < 0) {
                close(fd);
                return -1;
        }

        if (getsockname(fd, (struct sockaddr *) &f_saddr, &f_saddr_len) < 0) {
                LOG_ERR("Could not get address from fd.");
                close(fd);
                return -1;
        }

        rw_lock_rdlock(&_ipcp->state_lock);

        if (_ipcp->state != IPCP_ENROLLED) {
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Won't allocate flow with non-enrolled IPCP.");
                close(fd);
                return -1; /* -ENOTENROLLED */
        }

#ifdef CONFIG_OUROBOROS_ENABLE_DNS
        dns_addr = shim_data(_ipcp)->dns_addr;

        rw_lock_unlock(&_ipcp->state_lock);

        if (dns_addr != 0) {
                ip_addr = ddns_resolve(dst_name, dns_addr);
                if (ip_addr == 0) {
                        LOG_DBGF("Could not resolve %s.", dst_name);
                        close(fd);
                        return -1;
                }
        } else {
#endif
                h = gethostbyname(dst_name);
                if (h == NULL) {
                        LOG_DBGF("Could not resolve %s.", dst_name);
                        close(fd);
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

        if (connect(fd, (struct sockaddr *) &r_saddr, sizeof(r_saddr)) < 0) {
                close(fd);
                return -1;
        }

        rw_lock_unlock(&_ipcp->state_lock);

        LOG_DBGF("Pending flow with port_id %d on UDP port %d.",
                 port_id, ntohs(f_saddr.sin_port));

        rw_lock_rdlock(&_ipcp->state_lock);
        rw_lock_wrlock(&_ap_instance->flows_lock);

        set_fd(fd);

        _ap_instance->flows[fd].port_id = port_id;
        _ap_instance->flows[fd].state   = FLOW_PENDING;
        _ap_instance->flows[fd].rb      = rb;

        rw_lock_unlock(&_ap_instance->flows_lock);
        rw_lock_unlock(&_ipcp->state_lock);

        if (ipcp_udp_port_alloc(ip_addr,
                                f_saddr.sin_port,
                                dst_name,
                                src_ap_name,
                                src_ae_name) < 0) {
                LOG_DBGF("Port alloc returned -1.");
                rw_lock_rdlock(&_ipcp->state_lock);
                rw_lock_wrlock(&_ap_instance->flows_lock);

                clr_fd(fd);

                _ap_instance->flows[fd].port_id = -1;
                _ap_instance->flows[fd].state   = FLOW_NULL;
                shm_ap_rbuff_close(_ap_instance->flows[fd].rb);
                 _ap_instance->flows[fd].rb     = NULL;

                rw_lock_unlock(&_ap_instance->flows_lock);
                rw_lock_unlock(&_ipcp->state_lock);
                close(fd);
                return -1;
        }

        return fd;
}

static int ipcp_udp_flow_alloc_resp(pid_t n_pid,
                                    int   port_id,
                                    int   response)
{
        struct shm_ap_rbuff * rb;
        int fd = -1;
        struct sockaddr_in f_saddr;
        struct sockaddr_in r_saddr;
        socklen_t len = sizeof(r_saddr);

        if (response)
                return 0;

        rw_lock_rdlock(&_ipcp->state_lock);

        /* awaken pending flow */

        rw_lock_wrlock(&_ap_instance->flows_lock);

        fd = port_id_to_fd(port_id);
        if (fd < 0) {
                rw_lock_unlock(&_ap_instance->flows_lock);
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Could not find flow with port_id %d.", port_id);
                return -1;
        }

        if (_ap_instance->flows[fd].state != FLOW_PENDING) {
                rw_lock_unlock(&_ap_instance->flows_lock);
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Flow was not pending.");
                return -1;
        }

        rb = shm_ap_rbuff_open(n_pid);
        if (rb == NULL) {
                LOG_ERR("Could not open N + 1 ringbuffer.");
                _ap_instance->flows[fd].state   = FLOW_NULL;
                _ap_instance->flows[fd].port_id = -1;
                rw_lock_unlock(&_ap_instance->flows_lock);
                rw_lock_unlock(&_ipcp->state_lock);
                return -1;
        }

        rw_lock_unlock(&_ap_instance->flows_lock);
        rw_lock_unlock(&_ipcp->state_lock);

        if (getsockname(fd, (struct sockaddr *) &f_saddr, &len) < 0) {
                LOG_DBGF("Flow with port_id %d has no socket.", port_id);
                return -1;
        }

        if (getpeername(fd, (struct sockaddr *) &r_saddr, &len) < 0) {
                LOG_DBGF("Flow with port_id %d has no peer.", port_id);
                return -1;
        }

        rw_lock_rdlock(&_ipcp->state_lock);
        rw_lock_wrlock(&_ap_instance->flows_lock);

        _ap_instance->flows[fd].state = FLOW_ALLOCATED;
        _ap_instance->flows[fd].rb    = rb;

        set_fd(fd);

        rw_lock_unlock(&_ap_instance->flows_lock);
        rw_lock_unlock(&_ipcp->state_lock);

        if (ipcp_udp_port_alloc_resp(r_saddr.sin_addr.s_addr,
                                     f_saddr.sin_port,
                                     r_saddr.sin_port,
                                     response) < 0) {
                rw_lock_rdlock(&_ipcp->state_lock);
                rw_lock_wrlock(&_ap_instance->flows_lock);

                _ap_instance->flows[fd].state = FLOW_NULL;
                shm_ap_rbuff_close(_ap_instance->flows[fd].rb);
                _ap_instance->flows[fd].rb    = NULL;

                clr_fd(fd);

                rw_lock_unlock(&_ap_instance->flows_lock);
                rw_lock_unlock(&_ipcp->state_lock);

                LOG_DBGF("Could not send response.");
                return -1;
        }

        LOG_DBGF("Accepted flow, port_id %d on UDP fd %d.", port_id, fd);

        return 0;
}

static int ipcp_udp_flow_dealloc(int port_id)
{
        int fd = -1;
        int remote_udp = -1;
        struct shm_ap_rbuff * rb;
        struct sockaddr_in    r_saddr;
        socklen_t             r_saddr_len = sizeof(r_saddr);

        rw_lock_rdlock(&_ipcp->state_lock);
        rw_lock_wrlock(&_ap_instance->flows_lock);

        fd = port_id_to_fd(port_id);
        if (fd < 0) {
                rw_lock_unlock(&_ap_instance->flows_lock);
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Could not find flow with port_id %d.", port_id);
                return 0;
        }

        _ap_instance->flows[fd].state   = FLOW_NULL;
        _ap_instance->flows[fd].port_id = -1;
        rb = _ap_instance->flows[fd].rb;
        _ap_instance->flows[fd].rb      = NULL;

        clr_fd(fd);

        rw_lock_unlock(&_ap_instance->flows_lock);

        if (rb != NULL)
                shm_ap_rbuff_close(rb);

        if (getpeername(fd, (struct sockaddr *) &r_saddr, &r_saddr_len) < 0) {
                rw_lock_unlock(&_ipcp->state_lock);
                LOG_DBGF("Flow with port_id %d has no peer.", port_id);
                close(fd);
                return 0 ;
        }

        remote_udp       = r_saddr.sin_port;
        r_saddr.sin_port = LISTEN_PORT;

        if (connect(fd, (struct sockaddr *) &r_saddr, sizeof(r_saddr)) < 0) {
                rw_lock_unlock(&_ipcp->state_lock);
                close(fd);
                return 0 ;
        }

        if (ipcp_udp_port_dealloc(r_saddr.sin_addr.s_addr,
                                  remote_udp) < 0) {
                LOG_DBGF("Could not notify remote.");
                rw_lock_unlock(&_ipcp->state_lock);
                close(fd);
                return 0;
        }

        rw_lock_unlock(&_ipcp->state_lock);

        close(fd);

        LOG_DBGF("Flow with port_id %d deallocated.", port_id);

        return 0;
}

static struct ipcp * ipcp_udp_create()
{
        struct ipcp * i;
        struct ipcp_udp_data * data;
        struct ipcp_ops *      ops;

        i = ipcp_instance_create();
        if (i == NULL)
                return NULL;

        data = ipcp_udp_data_create();
        if (data == NULL) {
                free(i);
                return NULL;
        }

        ops = malloc(sizeof(*ops));
        if (ops == NULL) {
                free(data);
                free(i);
                return NULL;
        }

        ops->ipcp_bootstrap       = ipcp_udp_bootstrap;
        ops->ipcp_enroll          = NULL;                       /* shim */
        ops->ipcp_reg             = NULL;                       /* shim */
        ops->ipcp_unreg           = NULL;                       /* shim */
        ops->ipcp_name_reg        = ipcp_udp_name_reg;
        ops->ipcp_name_unreg      = ipcp_udp_name_unreg;
        ops->ipcp_flow_alloc      = ipcp_udp_flow_alloc;
        ops->ipcp_flow_alloc_resp = ipcp_udp_flow_alloc_resp;
        ops->ipcp_flow_dealloc    = ipcp_udp_flow_dealloc;

        i->data = (struct ipcp_data *) data;
        i->ops  = ops;

        i->state = IPCP_INIT;

        return i;
}

#ifndef MAKE_CHECK

int main (int argc, char * argv[])
{
        /* argument 1: pid of irmd ? */
        /* argument 2: ap name */
        struct sigaction sig_act;
        sigset_t  sigset;
        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGPIPE);

        if (ipcp_arg_check(argc, argv)) {
                LOG_ERR("Wrong arguments.");
                exit(1);
        }

        if (shim_ap_init(argv[2]) < 0)
                exit(1);

        /* store the process id of the irmd */
        irmd_pid = atoi(argv[1]);

        /* init sig_act */
        memset(&sig_act, 0, sizeof(sig_act));

        /* install signal traps */
        sig_act.sa_sigaction = &ipcp_sig_handler;
        sig_act.sa_flags     = SA_SIGINFO;

        sigaction(SIGINT,  &sig_act, NULL);
        sigaction(SIGTERM, &sig_act, NULL);
        sigaction(SIGHUP,  &sig_act, NULL);
        sigaction(SIGPIPE, &sig_act, NULL);

        _ipcp = ipcp_udp_create();
        if (_ipcp == NULL) {
                LOG_ERR("Won't.");
                exit(1);
        }

        rw_lock_wrlock(&_ipcp->state_lock);

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        pthread_create(&_ap_instance->mainloop, NULL, ipcp_main_loop, _ipcp);

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        rw_lock_unlock(&_ipcp->state_lock);

        pthread_join(_ap_instance->mainloop, NULL);

        shim_ap_fini();

        free(_ipcp->data);
        free(_ipcp->ops);
        free(_ipcp);

        exit(0);
}

#endif /* MAKE_CHECK */
