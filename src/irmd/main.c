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
#include <ouroboros/rina_name.h>

#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>

struct name_to_pid_entry {
        struct list_head next;
        int pid;
        rina_name_t * name;
};

struct irm {
        struct list_head name_to_pid;
};

static int find_pid_by_name(struct irm * instance,
                            rina_name_t * name)
{
        struct list_head * pos;

        list_for_each(pos, &instance->name_to_pid) {
                struct name_to_pid_entry * tmp =
                        list_entry(pos, struct name_to_pid_entry, next);

                LOG_DBG("name is %s", name->ap_name);

                if (name_is_equal(name, tmp->name))
                        return tmp->pid;
        }

        return 0;
}

static void create_ipcp(struct irm * instance,
                        rina_name_t name,
                        char * ipcp_type)
{
        int pid;
        struct name_to_pid_entry * tmp;
        rina_name_t * ipcp_name = NULL;

        pid = ipcp_create(name, ipcp_type);
        if (pid == 0) {
                LOG_ERR("Failed to create IPCP");
                return;
        }

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                return;

        INIT_LIST_HEAD(&tmp->next);

        tmp->pid = pid;
        tmp->name = name_dup(ipcp_name);
        if (tmp->name == NULL) {
                free(tmp);
                return;
        }

        list_add(&tmp->next, &instance->name_to_pid);
}

static void destroy_ipcp(struct irm * instance,
                         rina_name_t name)
{
        int pid = 0;
        struct list_head * pos;

        pid = find_pid_by_name(instance, &name);
        if (pid == 0) {
                LOG_ERR("No such IPCP");
                return;
        }

        if (ipcp_destroy(pid))
                LOG_ERR("Could not destroy IPCP");

        list_for_each(pos, &instance->name_to_pid) {
                struct name_to_pid_entry * tmp =
                        list_entry(pos, struct name_to_pid_entry, next);

                if (name_is_equal(&name, tmp->name))
                        list_del(&tmp->next);
        }
}

static void bootstrap_ipcp(struct irm * instance,
                           rina_name_t name,
                           struct dif_config conf)
{
        int pid = 0;

        pid = find_pid_by_name(instance, &name);
        if (pid == 0) {
                LOG_ERR("No such IPCP");
                return;
        }

        if (ipcp_bootstrap(pid, conf))
                LOG_ERR("Could not bootstrap IPCP");
}

static void enroll_ipcp(struct irm * instance,
                        rina_name_t name,
                        char * dif_name)
{
        int pid = 0;
        rina_name_t * member;
        char ** n_1_difs = NULL;
        ssize_t n_1_difs_size = 0;

        pid = find_pid_by_name(instance, &name);
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
                if (ipcp_enroll(pid, dif_name, *member,
                                n_1_difs, n_1_difs_size))
                        LOG_ERR("Could not enroll IPCP");
}

static void reg_ipcp(struct irm * instance,
                     rina_name_t name,
                     char ** difs,
                     size_t difs_size)
{
        int pid = 0;

        pid = find_pid_by_name(instance, &name);
        if (pid == 0) {
                LOG_ERR("No such IPCP");
                return;
        }

        if (ipcp_reg(pid, difs, difs_size))
                LOG_ERR("Could not register IPCP to N-1 DIF(s)");
}

static void unreg_ipcp(struct irm * instance,
                       rina_name_t name,
                       char ** difs,
                       size_t difs_size)
{
        int pid = 0;

        pid = find_pid_by_name(instance, &name);
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
        struct irm * instance;
        int sockfd;
        uint8_t buf[IRM_MSG_BUF_SIZE];

        instance = malloc(sizeof(*instance));
        if (instance == NULL)
                return -1;

        INIT_LIST_HEAD(&instance->name_to_pid);

        sockfd = server_socket_open(IRM_SOCK_PATH);
        if (sockfd < 0)
                return -1;

        while (true) {
                int cli_sockfd;
                struct irm_msg * msg;
                ssize_t count;
                buffer_t buffer;

                cli_sockfd = accept(sockfd, 0, 0);
                if (cli_sockfd < 0) {
                        LOG_ERR("Cannot accept new connection");
                        continue;
                }

                count = read(cli_sockfd, buf, IRM_MSG_BUF_SIZE);
                if (count) {
                        buffer.size = count;
                        buffer.data = buf;
                        msg = deserialize_irm_msg(&buffer);
                        if (msg == NULL)
                                continue;

                        switch (msg->code) {
                        case IRM_CREATE_IPCP:
                                create_ipcp(instance,
                                            *(msg->name),
                                            msg->ipcp_type);
                                break;
                        case IRM_DESTROY_IPCP:
                                destroy_ipcp(instance,
                                             *(msg->name));
                                break;
                        case IRM_BOOTSTRAP_IPCP:
                                bootstrap_ipcp(instance,
                                               *(msg->name),
                                               *(msg->conf));
                                break;
                        case IRM_ENROLL_IPCP:
                                enroll_ipcp(instance,
                                            *(msg->name),
                                            msg->dif_name);
                                break;
                        case IRM_REG_IPCP:
                                reg_ipcp(instance,
                                         *(msg->name),
                                         msg->difs,
                                         msg->difs_size);
                                break;
                        case IRM_UNREG_IPCP:
                                unreg_ipcp(instance,
                                           *(msg->name),
                                           msg->difs,
                                           msg->difs_size);
                                break;
                        default:
                                LOG_ERR("Don't know that message code");
                                break;
                        }
                        free(msg);
                }

                close(cli_sockfd);
        }

        return 0;
}
