/*
 * Ouroboros - Copyright (C) 2016
 *
 * IPC process main loop
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
#include <ouroboros/ipcp.h>
#include <sys/socket.h>
#include <stdlib.h>
#include "ipcp.h"

#define OUROBOROS_PREFIX "ipcpd/ipcp"
#include <ouroboros/logs.h>

struct ipcp * ipcp_instance_create()
{
        struct ipcp * i = malloc(sizeof *i);
        if (i == NULL)
                return NULL;

        i->data    = NULL;
        i->ops     = NULL;
        i->irmd_fd = -1;
        i->state   = IPCP_INIT;

        rw_lock_init(&i->state_lock);

        return i;
}

int ipcp_arg_check(int argc, char * argv[])
{
        if (argc != 3)
                return -1;

        /* argument 1: pid of irmd */
        if (atoi(argv[1]) == 0)
                return -1;

        /* name conformity responsibility of NMS */

        /* argument 2: ap name */

        return 0;
}

void * ipcp_main_loop(void * o)
{
        int     lsockfd;
        int     sockfd;
        uint8_t buf[IPCP_MSG_BUF_SIZE];
        struct ipcp * _ipcp = (struct ipcp *) o;

        ipcp_msg_t * msg;
        ssize_t      count;
        buffer_t     buffer;
        ipcp_msg_t   ret_msg = IPCP_MSG__INIT;

        dif_config_msg_t * conf_msg;
        struct dif_config  conf;

        char * sock_path;

        if (_ipcp == NULL) {
                LOG_ERR("Invalid ipcp struct.");
                return (void *) 1;
        }

        sock_path = ipcp_sock_path(getpid());
        if (sock_path == NULL)
                return (void *) 1;

        sockfd = server_socket_open(sock_path);
        if (sockfd < 0) {
                LOG_ERR("Could not open server socket.");
                return (void *) 1;
        }

        free(sock_path);

        while (true) {
                ret_msg.code = IPCP_MSG_CODE__IPCP_REPLY;

                lsockfd = accept(sockfd, 0, 0);
                if (lsockfd < 0) {
                        LOG_ERR("Cannot accept new connection");
                        break;
                }

                count = read(lsockfd, buf, IPCP_MSG_BUF_SIZE);
                if (count <= 0) {
                        LOG_ERR("Failed to read from socket");
                        close(lsockfd);
                        continue;
                }

                msg = ipcp_msg__unpack(NULL, count, buf);
                if (msg == NULL) {
                        close(lsockfd);
                        continue;
                }

                switch (msg->code) {
                case IPCP_MSG_CODE__IPCP_BOOTSTRAP:
                        if (_ipcp->ops->ipcp_bootstrap == NULL) {
                                LOG_ERR("Bootstrap unsupported.");
                                break;
                        }
                        conf_msg = msg->conf;
                        conf.type = conf_msg->ipcp_type;
                        if (conf_msg->ipcp_type == IPCP_NORMAL) {
                                conf.addr_size = conf_msg->addr_size;
                                conf.cep_id_size = conf_msg->cep_id_size;
                                conf.pdu_length_size
                                        = conf_msg->pdu_length_size;
                                conf.qos_id_size     = conf_msg->qos_id_size;
                                conf.seqno_size      = conf_msg->seqno_size;
                                conf.ttl_size        = conf_msg->seqno_size;
                                conf.chk_size        = conf_msg->chk_size;
                                conf.min_pdu_size    = conf_msg->min_pdu_size;
                                conf.max_pdu_size    = conf_msg->max_pdu_size;
                        }
                        if (conf_msg->ipcp_type == IPCP_SHIM_UDP) {
                                conf.ip_addr  = conf_msg->ip_addr;
                                conf.dns_addr = conf_msg->dns_addr;
                        }

                        ret_msg.has_result = true;
                        ret_msg.result = _ipcp->ops->ipcp_bootstrap(&conf);
                        break;
                case IPCP_MSG_CODE__IPCP_ENROLL:
                        if (_ipcp->ops->ipcp_enroll == NULL) {
                                LOG_ERR("Enroll unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                _ipcp->ops->ipcp_enroll(msg->member_name,
                                                        msg->n_1_dif);

                        break;

                case IPCP_MSG_CODE__IPCP_REG:
                        if (_ipcp->ops->ipcp_reg == NULL) {
                                LOG_ERR("Reg unsupported.");
                                break;

                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                _ipcp->ops->ipcp_reg(msg->dif_names, msg->len);
                        break;
                case IPCP_MSG_CODE__IPCP_UNREG:
                        if (_ipcp->ops->ipcp_unreg == NULL) {
                                LOG_ERR("Unreg unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                _ipcp->ops->ipcp_unreg(msg->dif_names,
                                                       msg->len);
                        break;
                case IPCP_MSG_CODE__IPCP_NAME_REG:
                        if (_ipcp->ops->ipcp_name_reg == NULL) {
                                LOG_ERR("Ap_reg unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result = _ipcp->ops->ipcp_name_reg(msg->name);
                        break;
                case IPCP_MSG_CODE__IPCP_NAME_UNREG:
                        if (_ipcp->ops->ipcp_name_unreg == NULL) {
                                LOG_ERR("Ap_unreg unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result = _ipcp->ops->ipcp_name_unreg(msg->name);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC:
                        if (_ipcp->ops->ipcp_flow_alloc == NULL) {
                                LOG_ERR("Flow_alloc unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                _ipcp->ops->ipcp_flow_alloc(msg->port_id,
                                                            msg->pid,
                                                            msg->dst_name,
                                                            msg->src_ap_name,
                                                            msg->src_ae_name,
                                                            NULL);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_ALLOC_RESP:
                        if (_ipcp->ops->ipcp_flow_alloc_resp == NULL) {
                                LOG_ERR("Flow_alloc_resp unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                _ipcp->ops->ipcp_flow_alloc_resp(msg->port_id,
                                                                 msg->pid,
                                                                 msg->result);
                        break;
                case IPCP_MSG_CODE__IPCP_FLOW_DEALLOC:
                        if (_ipcp->ops->ipcp_flow_dealloc == NULL) {
                                LOG_ERR("Flow_dealloc unsupported.");
                                break;
                        }
                        ret_msg.has_result = true;
                        ret_msg.result =
                                _ipcp->ops->ipcp_flow_dealloc(msg->port_id);
                        break;
                default:
                        LOG_ERR("Don't know that message code");
                        break;
                }

                ipcp_msg__free_unpacked(msg, NULL);

                buffer.size = ipcp_msg__get_packed_size(&ret_msg);
                if (buffer.size == 0) {
                        LOG_ERR("Failed to send reply message");
                        close(lsockfd);
                        continue;
                }

                buffer.data = malloc(buffer.size);
                if (buffer.data == NULL) {
                        close(lsockfd);
                        continue;
                }

                ipcp_msg__pack(&ret_msg, buffer.data);

                if (write(lsockfd, buffer.data, buffer.size) == -1) {
                        free(buffer.data);
                        close(lsockfd);
                        continue;
                }

                free(buffer.data);
                close(lsockfd);
        }

        return NULL;
}
