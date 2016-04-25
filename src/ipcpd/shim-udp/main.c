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
#include <ouroboros/shm_du_map.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/dif_config.h>
#include <ouroboros/sockets.h>

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

#define THIS_TYPE IPCP_SHIM_UDP
#define LISTEN_PORT htons(0x0D1F)
#define SHIM_UDP_BUF_SIZE 256
#define SHIM_UDP_MAX_SDU_SIZE 8980

#define shim_data(type) ((struct ipcp_udp_data *) type->data)

#define local_ip (((struct ipcp_udp_data *)                              \
                         _ipcp->data)->s_saddr.sin_addr.s_addr)

/* global for trapping signal */
int irmd_pid;

/* this IPCP's data */
#ifdef MAKE_CHECK
extern struct ipcp * _ipcp; /* defined in test */
#else
struct ipcp * _ipcp;
#endif

struct ipcp_udp_data {
        /* keep ipcp_data first for polymorphism */
        struct ipcp_data ipcp_data;

        uint32_t ip_addr;
        uint32_t dns_addr;

        /* listen server */
        struct sockaddr_in s_saddr;
        int                s_fd;

        fd_set flow_fd_s;
        flow_t * fd_to_flow_ptr[FD_SETSIZE];

        pthread_mutex_t   lock;
};

struct udp_flow {
        /* keep flow first for polymorphism */
        flow_t flow;
        int    fd;
};

void ipcp_sig_handler(int sig, siginfo_t * info, void * c)
{
        switch(sig) {
        case SIGINT:
        case SIGTERM:
        case SIGHUP:
                LOG_DBG("Terminating by order of %d. Bye.", info->si_pid);
                if (info->si_pid == irmd_pid) {
                        shm_du_map_close(_ipcp->data->dum);
                        exit(0);
                }
        default:
                return;
        }
}

struct ipcp_udp_data * ipcp_udp_data_create(char * ap_name,
                                            char * ap_id)
{
        struct ipcp_udp_data * udp_data;
        struct ipcp_data *     data;
        instance_name_t *      instance_name;
        enum ipcp_type         ipcp_type;
        int                    n;

        instance_name = instance_name_create();
        if (instance_name  == NULL) {
                LOG_ERR("Failed to create instance name struct.");
                return NULL;
        }

        instance_name = instance_name_init_with(
                instance_name, ap_name, (uint16_t) atoi(ap_id));

        if (instance_name == NULL) {
                LOG_ERR("Failed to create instance name struct.");
                return NULL;
        }

        udp_data = malloc(sizeof *udp_data);
        if (udp_data == NULL) {
                LOG_DBGF("Failed to allocate.");
                return NULL;
        }

        ipcp_type = THIS_TYPE;
        data = (struct ipcp_data *) udp_data;
        if (ipcp_data_init(data, instance_name, ipcp_type) == NULL) {
                free(udp_data);
                return NULL;
        }

        FD_ZERO(&udp_data->flow_fd_s);
        for (n = 0; n < FD_SETSIZE; ++n)
                udp_data->fd_to_flow_ptr[n] = NULL;

        return udp_data;
}

static void * ipcp_udp_listener()
{
        char buf[SHIM_UDP_BUF_SIZE];
        int     n = 0;

        struct sockaddr_in f_saddr;
        struct sockaddr_in c_saddr;
        struct hostent  *  hostp;
        struct udp_flow *  flow;
        int                sfd = shim_data(_ipcp)->s_fd;

        irm_msg_t          msg = IRM_MSG__INIT;
        irm_msg_t *        ret_msg ;

        while (true) {
                n = sizeof c_saddr;
                n = recvfrom(sfd, buf, SHIM_UDP_BUF_SIZE, 0,
                             (struct sockaddr *) &c_saddr, (unsigned *) &n);
                if (n < 0)
                        continue;

                /* flow alloc request from other host */
                hostp = gethostbyaddr((const char *) &c_saddr.sin_addr.s_addr,
                                      sizeof(c_saddr.sin_addr.s_addr), AF_INET);
                if (hostp == NULL)
                        continue;

                /* create a new socket for the server */
                flow = malloc(sizeof *flow);
                if (flow == NULL)
                        continue;

                flow->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
                if (flow->fd == -1) {
                        free(flow);
                        continue;
                }

                memset((char *) &f_saddr, 0, sizeof f_saddr);
                f_saddr.sin_family      = AF_INET;
                f_saddr.sin_addr.s_addr = local_ip;

                /*
                 * FIXME: we could have a port dedicated per registered AP
                 * Not that critical for UDP, but will be for LLC
                 */

                f_saddr.sin_port        = 0;

                /*
                 * store the remote address in the file descriptor
                 * this avoids having to store the sockaddr_in in
                 * the flow structure
                 */

                if (connect(flow->fd,
                            (struct sockaddr *) &c_saddr, sizeof c_saddr) < 0) {
                        close(flow->fd);
                        free(flow);
                        continue;
                }

                /* reply to IRM */

                msg.code = IRM_MSG_CODE__IPCP_FLOW_REQ_ARR;
                msg.ap_name = ANONYMOUS_AP;
                msg.ae_name = ""; /* no AE */
                msg.dst_name = buf;

                ret_msg = send_recv_irm_msg(&msg);
                if (ret_msg == NULL) {
                        LOG_ERR("Could not send message to IRM.");
                        close(flow->fd);
                        free(flow);
                        continue;
                }

                if (!ret_msg->has_port_id) {
                        LOG_ERR("Didn't get port_id.");
                        free(ret_msg);
                        close(flow->fd);
                        free(flow);
                        continue;
                }

                flow->flow.port_id = ret_msg->port_id;
                flow->flow.oflags  = FLOW_O_DEFAULT;
                flow->flow.state   = FLOW_PENDING;

                if(ipcp_data_add_flow(_ipcp->data, (flow_t *) flow)) {
                        LOG_DBGF("Could not add flow.");
                        free(ret_msg);
                        close(flow->fd);
                        free(flow);
                        continue;
                }

                FD_SET(flow->fd, &shim_data(_ipcp)->flow_fd_s);
                shim_data(_ipcp)->fd_to_flow_ptr[flow->fd] = &flow->flow;
        }

        return 0;
}

static void * ipcp_udp_sdu_reader()
{
        int n;
        int fd;
        char buf[SHIM_UDP_MAX_SDU_SIZE];

        struct sockaddr_in r_saddr;

        while (true) {
                flow_t * flow;

                if (select(FD_SETSIZE,
                           &shim_data(_ipcp)->flow_fd_s,
                           NULL, NULL, NULL)
                    < 0)
                        continue;

                for (fd = 0; fd < FD_SETSIZE; ++fd) {
                        if (!FD_ISSET(fd, &shim_data(_ipcp)->flow_fd_s))
                                continue;

                        n = sizeof r_saddr;
                        n = recvfrom(fd,
                                     buf,
                                     SHIM_UDP_MAX_SDU_SIZE,
                                     0,
                                     (struct sockaddr *) &r_saddr,
                                     (unsigned *) &n);

                        flow = shim_data(_ipcp)->fd_to_flow_ptr[fd];
                        if (flow->state == FLOW_PENDING) {
                                if (connect(fd,
                                            (struct sockaddr *) &r_saddr,
                                            sizeof r_saddr)
                                    < 0)
                                       continue;
                                flow->state = FLOW_ALLOCATED;
                        }

                        /* send the sdu to the correct port_id */
                        LOG_MISSING;
                }
        }

        return (void *) 0;
}

int ipcp_udp_bootstrap(struct dif_config * conf)
{
        char ipstr[INET_ADDRSTRLEN];
        char dnsstr[INET_ADDRSTRLEN];
        pthread_t handler;
        pthread_t sdu_reader;

        if (conf->type != THIS_TYPE) {
                LOG_ERR("Config doesn't match IPCP type.");
                return -1;
        }

        if (_ipcp->state != IPCP_INIT) {
                LOG_ERR("IPCP in wrong state.");
                return -1;
        }

        inet_ntop(AF_INET,
                  &conf->ip_addr,
                  ipstr,
                  INET_ADDRSTRLEN);

        if (conf->dns_addr != 0)
                inet_ntop(AF_INET,
                          &conf->dns_addr,
                          dnsstr,
                          INET_ADDRSTRLEN);
        else
                strcpy(dnsstr, "not set");

        shim_data(_ipcp)->ip_addr  = conf->ip_addr;
        shim_data(_ipcp)->dns_addr = conf->dns_addr;

        /* UDP listen server */

        if ((shim_data(_ipcp)->s_fd =
             socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1) {
                LOG_DBGF("Can't create socket.");
                return -1;
        }

        shim_data(_ipcp)->s_saddr.sin_family      = AF_INET;
        shim_data(_ipcp)->s_saddr.sin_addr.s_addr = conf->ip_addr;
        shim_data(_ipcp)->s_saddr.sin_port        = LISTEN_PORT;

        if (bind(shim_data(_ipcp)->s_fd,
                 (struct sockaddr *) &shim_data(_ipcp)->s_saddr,
                 sizeof shim_data(_ipcp)->s_saddr ) < 0) {
                LOG_ERR("Couldn't bind to %s.", ipstr);
                return -1;
        }

        pthread_create(&handler, NULL, ipcp_udp_listener, NULL);
        pthread_create(&sdu_reader, NULL, ipcp_udp_sdu_reader, NULL);

        _ipcp->state = IPCP_ENROLLED;

        LOG_DBG("Bootstrapped shim IPCP over UDP %s-%d.",
                _ipcp->data->iname->name, _ipcp->data->iname->id);

        LOG_DBG("Bound to IP address %s.", ipstr);
        LOG_DBG("DNS server address is %s.", dnsstr);

        return 0;
}

int ipcp_udp_name_reg(char * name)
{
        if (_ipcp->state != IPCP_ENROLLED) {
                LOG_DBGF("Won't register with non-enrolled IPCP.");
                return -1;
        }

        if (ipcp_data_add_reg_entry(_ipcp->data, name)) {
                LOG_ERR("Failed to add %s to local registry.", name);
                return -1;
        }

        LOG_DBG("Registered %s", name);

        /* FIXME: register application with DNS server */
        LOG_MISSING;

        return 0;
}

int ipcp_udp_name_unreg(char * name)
{
        ipcp_data_del_reg_entry(_ipcp->data, name);

        LOG_DBG("Unregistered %s.", name);

        /* FIXME: unregister application from DNS server */
        LOG_MISSING;

        return 0;
}

int ipcp_udp_flow_alloc(uint32_t          port_id,
                        char *            dst_ap_name,
                        char *            src_ap_name,
                        char *            src_ae_name,
                        struct qos_spec * qos)
{
        struct udp_flow *  flow = NULL;
        struct sockaddr_in l_saddr;
        struct sockaddr_in r_saddr;

        irm_msg_t   msg = IRM_MSG__INIT;
        irm_msg_t * ret_msg = NULL;

        if (dst_ap_name == NULL || src_ap_name == NULL || src_ae_name == NULL)
                return -1;

        LOG_DBG("Received flow allocation request from %s to %s.",
                src_ap_name, dst_ap_name);

        if (strlen(dst_ap_name) > 255
            || strlen(src_ap_name) > 255
            || strlen(src_ae_name) > 255) {
                LOG_ERR("Name too long for this shim.");
                return -1;
        }

        if (qos != NULL)
                LOG_DBGF("QoS requested. UDP/IP can't do that.");

        flow = malloc(sizeof *flow);
        if (flow == NULL)
                return -1;

        flow->fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (flow->fd == -1) {
                free(flow);
                return -1;
        }

        /* this socket is for the flow */
        memset((char *) &l_saddr, 0, sizeof l_saddr);
        l_saddr.sin_family      = AF_INET;
        l_saddr.sin_addr.s_addr = local_ip;
        l_saddr.sin_port        = 0;

        if (bind(flow->fd, (struct sockaddr *) &l_saddr, sizeof l_saddr) < 0) {
                char ipstr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET,
                          &l_saddr.sin_addr.s_addr,
                          ipstr,
                          INET_ADDRSTRLEN);
                close(flow->fd);
                free(flow);
                return -1;
        }

        /* FIXME: use calls to specify DDNS server */

#define IP_ADDR 0x7f000001; /* localhost */

        LOG_MISSING;

        memset((char *) &r_saddr, 0, sizeof r_saddr);
        r_saddr.sin_family      = AF_INET;
        /* FIXME: pull in correct IP address */
        r_saddr.sin_addr.s_addr = IP_ADDR; /* FIXME */
        r_saddr.sin_port        = LISTEN_PORT;

        /* at least try to get the packet on the wire */
        while (sendto(flow->fd, dst_ap_name, strlen(dst_ap_name), 0,
                      (struct sockaddr *) &r_saddr, sizeof r_saddr) < 0)

        flow->flow.port_id = port_id;
        flow->flow.oflags  = FLOW_O_DEFAULT;
        flow->flow.state   = FLOW_PENDING;

        /* add flow to the list */

        pthread_mutex_lock(&_ipcp->data->flow_lock);

        if(ipcp_data_add_flow(_ipcp->data, (flow_t *) flow)) {
                LOG_DBGF("Could not add flow.");
                pthread_mutex_unlock(&_ipcp->data->flow_lock);
                close(flow->fd);
                free(flow);
                return -1;
        }

        pthread_mutex_unlock(&_ipcp->data->flow_lock);

        /* tell IRMd that flow allocation "worked" */

        msg.code = IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY;
        msg.has_port_id = true;
        msg.port_id = flow->flow.port_id;
        msg.has_response = true;
        msg.response = 0;

        ret_msg = send_recv_irm_msg(&msg);
        if (ret_msg == NULL) {
                close(flow->fd);
                ipcp_data_del_flow(_ipcp->data, flow->flow.port_id);
                return -1;
        }

        FD_SET(flow->fd, &shim_data(_ipcp)->flow_fd_s);
        shim_data(_ipcp)->fd_to_flow_ptr[flow->fd] = &flow->flow;

        return 0;
}

int ipcp_udp_flow_alloc_resp(uint32_t port_id,
                             int      response)
{
        struct udp_flow * flow =
                (struct udp_flow *) ipcp_data_find_flow(_ipcp->data, port_id);
        if (flow == NULL) {
                return -1;
        }

        if (response) {
                ipcp_data_del_flow(_ipcp->data, port_id);
                return 0;
        }

        /* awaken pending flow */

        if (flow->flow.state != FLOW_PENDING)
                return -1;

        flow->flow.state = FLOW_ALLOCATED;

        return 0;
}

int ipcp_udp_flow_dealloc(uint32_t port_id)
{
        return 0;
}

int ipcp_udp_du_write(uint32_t port_id,
                      size_t map_index)
{
        return 0;
}

int ipcp_udp_du_read(uint32_t port_id,
                     size_t map_index)
{
        return 0;
}

struct ipcp * ipcp_udp_create(char * ap_name, char * i_id)
{
        struct ipcp * i;
        struct ipcp_udp_data * data;
        struct ipcp_ops *      ops;

        i = malloc(sizeof *i);
        if (i == NULL)
                return NULL;

        data = ipcp_udp_data_create(ap_name, i_id);
        if (data == NULL) {
                free(i);
                return NULL;
        }

        ops = malloc(sizeof *ops);
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
        ops->ipcp_du_read         = ipcp_udp_du_read;
        ops->ipcp_du_write        = ipcp_udp_du_write;

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
        /* argument 3: instance id */
        struct sigaction sig_act;

        if (ipcp_arg_check(argc, argv)) {
                LOG_ERR("Wrong arguments.");
                exit(1);
        }

        /* store the process id of the irmd */
        irmd_pid = atoi(argv[1]);

        /* init sig_act */
        memset(&sig_act, 0, sizeof sig_act);

        /* install signal traps */
        sig_act.sa_sigaction = &ipcp_sig_handler;
        sig_act.sa_flags     = SA_SIGINFO;

        sigaction(SIGINT,  &sig_act, NULL);
        sigaction(SIGTERM, &sig_act, NULL);
        sigaction(SIGHUP,  &sig_act, NULL);

        _ipcp = ipcp_udp_create(argv[2], argv[3]);
        if (_ipcp == NULL) {
                LOG_ERR("Won't.");
                exit(1);
        }

        ipcp_main_loop(_ipcp);

        exit(0);
}

#endif /* MAKE_CHECK */
