/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "irmd"

#include <ouroboros/logs.h>
#include <ouroboros/common.h>
#include <ouroboros/sockets.h>
#include <ouroboros/irm.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/da.h>
#include <ouroboros/list.h>
#include <ouroboros/instance_name.h>
#include <ouroboros/utils.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>

struct ipcp_entry {
        struct list_head  next;
        pid_t             pid;
        instance_name_t * api;
        char *            dif_name;
};

struct irm {
        struct list_head ipcps;
};

struct irm * instance = NULL;

static pid_t find_pid_by_ipcp_name(instance_name_t * api)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &instance->ipcps) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);

                LOG_DBG("name is %s", api->name);

                if (instance_name_cmp(api, tmp->api) == 0)
                        return tmp->pid;
        }

        return 0;
}

static struct ipcp_entry * find_ipcp_by_name(instance_name_t * api)
{
        struct ipcp_entry * tmp = NULL;
        struct list_head * pos = NULL;

        list_for_each(pos, &instance->ipcps) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);

                if (instance_name_cmp(api, tmp->api) == 0)
                        return tmp;
        }

        return tmp;
}

static int create_ipcp(instance_name_t * api,
                       char *            ipcp_type)
{
        pid_t pid;
        struct ipcp_entry * tmp = NULL;

        pid = ipcp_create(api, ipcp_type);
        if (pid == -1) {
                LOG_ERR("Failed to create IPCP");
                return -1;
        }

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return -1;

        INIT_LIST_HEAD(&tmp->next);

        tmp->pid = pid;
        tmp->api = instance_name_dup(api);
        if (tmp->api == NULL) {
                free(tmp);
                return -1;
        }

        tmp->dif_name = NULL;

        LOG_DBG("Created IPC process with pid %d", pid);

        list_add(&tmp->next, &instance->ipcps);
        return 0;
}

static int destroy_ipcp(instance_name_t * api)
{
        pid_t pid = 0;
        struct list_head * pos = NULL;
        struct list_head * n = NULL;

        pid = find_pid_by_ipcp_name(api);
        if (pid == 0) {
                LOG_ERR("No such IPCP");
                return -1;
        }

        LOG_DBG("Destroying ipcp with pid %d", pid);

        if (ipcp_destroy(pid))
                LOG_ERR("Could not destroy IPCP");

        list_for_each_safe(pos, n, &(instance->ipcps)) {
                struct ipcp_entry * tmp =
                        list_entry(pos, struct ipcp_entry, next);

                if (instance_name_cmp(api, tmp->api) == 0)
                        list_del(&tmp->next);
        }

        return 0;
}

static int bootstrap_ipcp(instance_name_t *   api,
                          struct dif_config * conf)
{
        struct ipcp_entry * entry = NULL;

        entry = find_ipcp_by_name(api);
        if (entry == NULL) {
                LOG_ERR("No such IPCP");
                return -1;
        }

        entry->dif_name = strdup( conf->dif_name);
        if (entry->dif_name == NULL) {
                LOG_ERR("Failed to strdup");
                return -1;
        }

        if (ipcp_bootstrap(entry->pid, conf)) {
                LOG_ERR("Could not bootstrap IPCP");
                free(entry->dif_name);
                entry->dif_name = NULL;
                return -1;
        }

        return 0;
}

static int enroll_ipcp(instance_name_t  * api,
                       char *             dif_name)
{
        char *  member = NULL;
        char ** n_1_difs = NULL;
        ssize_t n_1_difs_size = 0;
        struct ipcp_entry * entry = NULL;

        entry = find_ipcp_by_name(api);
        if (entry == NULL) {
                LOG_ERR("No such IPCP");
                return -1;
        }

        entry->dif_name = strdup(dif_name);
        if (entry->dif_name == NULL) {
                LOG_ERR("Failed to strdup");
                return -1;
        }

        member = da_resolve_daf(dif_name);
        if (member == NULL) {
                LOG_ERR("Could not find a member of that DIF");
                free(entry->dif_name);
                entry->dif_name = NULL;
                return -1;
        }

        n_1_difs_size = da_resolve_dap(member, n_1_difs);
        if (n_1_difs_size < 1) {
                LOG_ERR("Could not find N-1 DIFs");
                free(entry->dif_name);
                entry->dif_name = NULL;
                return -1;
        }

        if (ipcp_enroll(entry->pid, member, n_1_difs[0])) {
                LOG_ERR("Could not enroll IPCP");
                free(entry->dif_name);
                entry->dif_name = NULL;
                return -1;
        }

        return 0;
}

static int reg_ipcp(instance_name_t * api,
                    char **           difs,
                    size_t            difs_size)
{
        pid_t pid = 0;

        pid = find_pid_by_ipcp_name(api);
        if (pid == 0) {
                LOG_ERR("No such IPCP");
                return -1;
        }

        if (ipcp_reg(pid, difs, difs_size)) {
                LOG_ERR("Could not register IPCP to N-1 DIF(s)");
                return -1;
        }

        return 0;
}

static int unreg_ipcp(instance_name_t  * api,
                      char **            difs,
                      size_t             difs_size)
{
        pid_t pid = 0;

        pid = find_pid_by_ipcp_name(api);
        if (pid == 0) {
                LOG_ERR("No such IPCP");
                return -1;
        }

        if (ipcp_unreg(pid, difs, difs_size)) {
                LOG_ERR("Could not unregister IPCP from N-1 DIF(s)");
                return -1;
        }

        return 0;
}

static int ap_reg(char * ap_name,
                  char ** difs,
                  size_t difs_size)
{
        return -1;
}

static int ap_unreg(char * ap_name,
                    char ** difs,
                    size_t difs_size)
{
        return -1;
}

static int flow_accept(int fd,
                       char * ap_name,
                       char * ae_name)
{
        return -1;
}

static int flow_alloc_resp(int fd,
                           int result)
{

        return -1;
}

static int flow_alloc(char * dst_ap_name,
                      char * src_ap_name,
                      char * src_ae_name,
                      struct qos_spec * qos,
                      int oflags)
{
        return -1;
}

static int flow_alloc_res(int fd)
{

        return -1;
}

static int flow_dealloc(int fd)
{
        return -1;
}

static int flow_cntl(int fd,
                     int oflags)
{
        return -1;
}

static int flow_req_arr(uint32_t reg_api_id,
                        char *   ap_name,
                        char *   ae_name)
{
        return -1;
}

static int flow_alloc_reply(uint32_t port_id,
                            int      result)
{
        return -1;
}

static int flow_dealloc_ipcp(uint32_t port_id)
{
        return -1;
}

/* FIXME: Close sockfd on closing and release irm */
int main()
{
        int     sockfd;
        uint8_t buf[IRM_MSG_BUF_SIZE];

        instance = malloc(sizeof(*instance));
        if (instance == NULL)
                return -1;

        INIT_LIST_HEAD(&instance->ipcps);

        sockfd = server_socket_open(IRM_SOCK_PATH);
        if (sockfd < 0)
                return -1;

        while (true) {
                int cli_sockfd;
                irm_msg_t * msg;
                ssize_t count;
                instance_name_t api;
                buffer_t buffer;
                irm_msg_t ret_msg = IRM_MSG__INIT;

                ret_msg.code = IRM_MSG_CODE__IRM_REPLY;

                cli_sockfd = accept(sockfd, 0, 0);
                if (cli_sockfd < 0) {
                        LOG_ERR("Cannot accept new connection");
                        continue;
                }

                count = read(cli_sockfd, buf, IRM_MSG_BUF_SIZE);
                if (count <= 0) {
                        LOG_ERR("Failed to read from socket");
                        close(cli_sockfd);
                        continue;
                }

                msg = irm_msg__unpack(NULL, count, buf);
                if (msg == NULL) {
                        close(cli_sockfd);
                        continue;
                }

                api.name = msg->ap_name;
                api.id   = msg->api_id;

                switch (msg->code) {
                case IRM_MSG_CODE__IRM_CREATE_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = create_ipcp(&api,
                                                     msg->ipcp_type);
                        break;
                case IRM_MSG_CODE__IRM_DESTROY_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = destroy_ipcp(&api);
                        break;
                case IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = bootstrap_ipcp(&api, NULL);
                        break;
                case IRM_MSG_CODE__IRM_ENROLL_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = enroll_ipcp(&api,
                                                     msg->dif_name[0]);
                        break;
                case IRM_MSG_CODE__IRM_REG_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = reg_ipcp(&api,
                                                  msg->dif_name,
                                                  msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_UNREG_IPCP:
                        ret_msg.has_result = true;
                        ret_msg.result = unreg_ipcp(&api,
                                                    msg->dif_name,
                                                    msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_AP_REG:
                        ret_msg.has_fd = true;
                        ret_msg.fd = ap_reg(msg->ap_name,
                                            msg->dif_name,
                                            msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_AP_UNREG:
                        ret_msg.has_result = true;
                        ret_msg.result = ap_unreg(msg->ap_name,
                                                  msg->dif_name,
                                                  msg->n_dif_name);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ACCEPT:
                        ret_msg.has_fd = true;
                        ret_msg.fd = flow_accept(msg->fd,
                                                 ret_msg.ap_name,
                                                 ret_msg.ae_name);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ALLOC_RESP:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_alloc_resp(msg->fd,
                                                         msg->result);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ALLOC:
                        ret_msg.has_fd = true;
                        ret_msg.fd = flow_alloc(msg->dst_ap_name,
                                                msg->ap_name,
                                                msg->ae_name,
                                                NULL,
                                                msg->oflags);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_ALLOC_RES:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_alloc_res(msg->fd);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_DEALLOC:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_dealloc(msg->fd);
                        break;
                case IRM_MSG_CODE__IRM_FLOW_CONTROL:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_cntl(msg->fd,
                                                   msg->oflags);
                        break;
                case IRM_MSG_CODE__IPCP_FLOW_REQ_ARR:
                        ret_msg.has_fd = true;
                        ret_msg.fd = flow_req_arr(msg->port_id,
                                                  msg->ap_name,
                                                  msg->ae_name);
                        break;
                case IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_alloc_reply(msg->port_id,
                                                          msg->result);
                        break;
                case IRM_MSG_CODE__IPCP_FLOW_DEALLOC:
                        ret_msg.has_result = true;
                        ret_msg.result = flow_dealloc_ipcp(msg->port_id);
                        break;
                default:
                        LOG_ERR("Don't know that message code");
                        break;
                }

                irm_msg__free_unpacked(msg, NULL);

                buffer.size = irm_msg__get_packed_size(&ret_msg);
                if (buffer.size == 0) {
                        LOG_ERR("Failed to send reply message");
                        close(cli_sockfd);
                        continue;
                }

                buffer.data = malloc(buffer.size);
                if (buffer.data == NULL) {
                        close(cli_sockfd);
                        continue;
                }

                irm_msg__pack(&ret_msg, buffer.data);

                if (write(cli_sockfd, buffer.data, buffer.size) == -1) {
                        free(buffer.data);
                        close(cli_sockfd);
                        continue;
                }

                free(buffer.data);
                close(cli_sockfd);
        }

        return 0;
}
