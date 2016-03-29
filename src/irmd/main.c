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

#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>

struct name_to_pid_entry {
        struct list_head  next;
        pid_t             pid;
        instance_name_t * api;
};

struct irm {
        struct list_head name_to_pid;
};

static pid_t find_pid_by_name(struct irm *      instance,
                              instance_name_t * api)
{
        struct list_head * pos;

        list_for_each(pos, &instance->name_to_pid) {
                struct name_to_pid_entry * tmp =
                        list_entry(pos, struct name_to_pid_entry, next);

                LOG_DBG("name is %s", api->name);

                if (instance_name_cmp(api, tmp->api) == 0)
                        return tmp->pid;
        }

        return 0;
}

static void create_ipcp(struct irm *      instance,
                        instance_name_t * api,
                        char *            ipcp_type)
{
        pid_t pid;
        struct name_to_pid_entry * tmp;

        pid = ipcp_create(api, ipcp_type);
        if (pid == -1) {
                LOG_ERR("Failed to create IPCP");
                return;
        }

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return;

        INIT_LIST_HEAD(&tmp->next);

        tmp->pid = pid;
        tmp->api = instance_name_dup(api);
        if (tmp->api == NULL) {
                free(tmp);
                return;
        }

        LOG_DBG("Created IPC process with pid %d", pid);

        list_add(&tmp->next, &instance->name_to_pid);
}

static void destroy_ipcp(struct irm *      instance,
                         instance_name_t * api)
{
        pid_t pid = 0;
        struct list_head * pos;
        struct list_head * n;

        pid = find_pid_by_name(instance, api);
        if (pid == 0) {
                LOG_ERR("No such IPCP");
                return;
        }

        LOG_DBG("Destroying ipcp with pid %d", pid);

        if (ipcp_destroy(pid))
                LOG_ERR("Could not destroy IPCP");

        list_for_each_safe(pos, n, &(instance->name_to_pid)) {
                struct name_to_pid_entry * tmp =
                        list_entry(pos, struct name_to_pid_entry, next);

                if (instance_name_cmp(api, tmp->api) == 0)
                        list_del(&tmp->next);
        }
}

static void bootstrap_ipcp(struct irm *        instance,
                           instance_name_t *   api,
                           struct dif_config * conf)
{
        pid_t pid = 0;

        pid = find_pid_by_name(instance, api);
        if (pid == 0) {
                LOG_ERR("No such IPCP");
                return;
        }

        if (ipcp_bootstrap(pid, conf))
                LOG_ERR("Could not bootstrap IPCP");
}

static void enroll_ipcp(struct irm *       instance,
                        instance_name_t  * api,
                        char *             dif_name)
{
        pid_t   pid = 0;
        char *  member;
        char ** n_1_difs = NULL;
        ssize_t n_1_difs_size = 0;

        pid = find_pid_by_name(instance, api);
        if (pid == 0) {
                LOG_ERR("No such IPCP");
                return;
        }

        member = da_resolve_daf(dif_name);
        if (member == NULL) {
                LOG_ERR("Could not find a member of that DIF");
                return;
        }

        n_1_difs_size = da_resolve_dap(member, n_1_difs);
        if (n_1_difs_size != 0)
                if (ipcp_enroll(pid, dif_name, member,
                                n_1_difs, n_1_difs_size))
                        LOG_ERR("Could not enroll IPCP");
}

static void reg_ipcp(struct irm *      instance,
                     instance_name_t * api,
                     char **           difs,
                     size_t            difs_size)
{
        pid_t pid = 0;

        pid = find_pid_by_name(instance, api);
        if (pid == 0) {
                LOG_ERR("No such IPCP");
                return;
        }

        if (ipcp_reg(pid, difs, difs_size))
                LOG_ERR("Could not register IPCP to N-1 DIF(s)");
}

static void unreg_ipcp(struct irm *       instance,
                       instance_name_t  * api,
                       char **            difs,
                       size_t             difs_size)
{
        pid_t pid = 0;

        pid = find_pid_by_name(instance, api);
        if (pid == 0) {
                LOG_ERR("No such IPCP");
                return;
        }

        if (ipcp_unreg(pid, difs, difs_size))
                LOG_ERR("Could not unregister IPCP from N-1 DIF(s)");
}

/* FIXME: Close sockfd on closing and release irm */
int main()
{
        struct irm * instance = NULL;
        int          sockfd;
        uint8_t      buf[IRM_MSG_BUF_SIZE];

        instance = malloc(sizeof(*instance));
        if (instance == NULL)
                return -1;

        INIT_LIST_HEAD(&instance->name_to_pid);

        sockfd = server_socket_open(IRM_SOCK_PATH);
        if (sockfd < 0)
                return -1;

        while (true) {
                int cli_sockfd;
                irm_msg_t * msg;
                ssize_t count;
                instance_name_t api;

                cli_sockfd = accept(sockfd, 0, 0);
                if (cli_sockfd < 0) {
                        LOG_ERR("Cannot accept new connection");
                        continue;
                }

                count = read(cli_sockfd, buf, IRM_MSG_BUF_SIZE);
                if (count > 0) {
                        msg = irm_msg__unpack(NULL, count, buf);
                        if (msg == NULL)
                                continue;

                        api.name = msg->ap_name;
                        api.id   = msg->api_id;

                        switch (msg->code) {
                        case IRM_MSG_CODE__IRM_CREATE_IPCP:
                                create_ipcp(instance, &api, msg->ipcp_type);
                                break;
                        case IRM_MSG_CODE__IRM_DESTROY_IPCP:
                                destroy_ipcp(instance, &api);
                                break;
                        case IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP:
                                bootstrap_ipcp(instance, &api, NULL);
                                break;
                        case IRM_MSG_CODE__IRM_ENROLL_IPCP:
                                if (msg->n_dif_name != 1)
                                        continue;
                                enroll_ipcp(instance, &api, msg->dif_name[0]);
                                break;
                        case IRM_MSG_CODE__IRM_REG_IPCP:
                                reg_ipcp(instance, &api,
                                         msg->dif_name,
                                         msg->n_dif_name);
                                break;
                        case IRM_MSG_CODE__IRM_UNREG_IPCP:
                                unreg_ipcp(instance, &api,
                                           msg->dif_name,
                                           msg->n_dif_name);
                                break;
                        default:
                                LOG_ERR("Don't know that message code");
                                break;
                        }

                        irm_msg__free_unpacked(msg, NULL);
                }

                close(cli_sockfd);
        }

        return 0;
}
