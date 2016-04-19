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

#define OUROBOROS_PREFIX "ipcpd/shim-udp"

#include <ouroboros/logs.h>

#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>

#define THIS_TYPE IPCP_SHIM_UDP

#define shim_data(type) ((struct ipcp_udp_data *) type->data)

/* global for trapping signal */
int irmd_pid;

/* this IPCP's data */
#ifdef MAKE_CHECK
extern struct ipcp * _ipcp; /* defined in test */
#else
struct ipcp * _ipcp;
#endif

struct ipcp_udp_data {
        /* IPCP_DATA STRUCT MUST BE FIRST!! */
        struct ipcp_data ipcp_data;

        uint32_t ip_addr;
        uint32_t dns_addr;

        pthread_mutex_t   lock;
};

struct udp_flow {
        /* FLOW MUST BE FIRST !!!! */
        flow_t flow;

        uint16_t localport;

        struct sockaddr_in * remote;
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

        instance_name = instance_name_create();
        if (instance_name  == NULL) {
                LOG_ERR("Failed to create instance name struct.");
                return NULL;
        }

        instance_name = instance_name_init_with(
                instance_name, ap_name, (uint16_t)atoi(ap_id));

        if (instance_name  == NULL) {
                LOG_ERR("Failed to create instance name struct.");
                return NULL;
        }

        udp_data= malloc (sizeof *udp_data);
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

        return udp_data;
}

int ipcp_udp_bootstrap(struct dif_config * conf)
{
        char ipstr[INET_ADDRSTRLEN];
        char dnsstr[INET_ADDRSTRLEN];

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

        _ipcp->state = IPCP_ENROLLED;

        LOG_DBG("Bootstrapped shim IPCP over UDP %s-%d.",
                _ipcp->data->iname->name, _ipcp->data->iname->id);

        LOG_DBG("Bound to IP address %s.", ipstr);
        LOG_DBG("DNS server address is %s.", dnsstr);

        return 0;
}

int ipcp_udp_ap_reg(char * ap_name, uint32_t reg_ap_id)
{
        LOG_DBG("Registering local ap %s, %u.", ap_name, reg_ap_id);

        if (_ipcp->state != IPCP_ENROLLED) {
                LOG_DBGF("Won't register with non-enrolled IPCP.");
                return -1;
        }

        if (ipcp_data_add_reg_entry(_ipcp->data, ap_name, reg_ap_id)) {
                LOG_ERR("Failed to add AP to local registry.");
                return -1;
        }

        LOG_MISSING;

        return 0;
}

int ipcp_udp_ap_unreg(uint32_t reg_ap_id)
{
        char * name  = strdup(ipcp_data_get_reg_ap_name(_ipcp->data,
                                                        reg_ap_id));
        LOG_DBG("Unregistering %s.", name);

        ipcp_data_del_reg_entry(_ipcp->data, reg_ap_id);

        /* we are using dns */
        LOG_MISSING;

        free (name);

        return 0;
}

int ipcp_udp_flow_alloc(uint32_t          port_id,
                        char *            dst_ap_name,
                        char *            src_ap_name,
                        char *            src_ae_name,
                        struct qos_spec * qos)
{
        return 0;
}
int ipcp_udp_flow_alloc_resp(uint32_t port_id,
                             int      result)
{
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

        ops = malloc (sizeof *ops);
        if (ops == NULL) {
                free(data);
                free(i);
                return NULL;
        }

        ops->ipcp_bootstrap       = ipcp_udp_bootstrap;
        ops->ipcp_enroll          = NULL;                       /* shim */
        ops->ipcp_reg             = NULL;                       /* shim */
        ops->ipcp_unreg           = NULL;                       /* shim */
        ops->ipcp_ap_reg          = ipcp_udp_ap_reg;
        ops->ipcp_ap_unreg        = ipcp_udp_ap_unreg;
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
        memset (&sig_act, 0, sizeof sig_act);

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
