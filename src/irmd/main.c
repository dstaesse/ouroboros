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

#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <errno.h>

struct irm {

};

static void create_ipcp(rina_name_t name,
                        char * ipcp_type)
{
        struct ipcp * instance = NULL;

        instance = ipcp_create(name, ipcp_type);
        if (instance == NULL)
                LOG_ERR("Failed to create IPCP");
}

static void destroy_ipcp(rina_name_t name)
{
        struct ipcp * instance = NULL;

        if (ipcp_destroy(instance))
                LOG_ERR("Could not destroy IPCP");
}

static void bootstrap_ipcp(rina_name_t name,
                           struct dif_config conf)
{
        struct ipcp * instance = NULL;

        if (ipcp_bootstrap(instance, conf))
                LOG_ERR("Could not bootstrap IPCP");
}

static void enroll_ipcp(rina_name_t name,
                        char * dif_name)
{
        struct ipcp * instance = NULL;
        rina_name_t * member;

        member = da_resolve_daf(dif_name);
        if (member == NULL) {
                LOG_ERR("Could not find a member of that DIF");
                return;
        }

        if (ipcp_enroll(instance, dif_name, *member))
                LOG_ERR("Could not enroll IPCP");
}

static void reg_ipcp(rina_name_t name,
                     char ** difs,
                     size_t difs_size)
{
        struct ipcp * instance = NULL;

        if (ipcp_reg(instance, difs, difs_size))
                LOG_ERR("Could not register IPCP to N-1 DIF(s)");
}

static void unreg_ipcp(rina_name_t name,
                       char ** difs,
                       size_t difs_size)
{
        struct ipcp * instance = NULL;

        if (ipcp_unreg(instance, difs, difs_size))
                LOG_ERR("Could not unregister IPCP from N-1 DIF(s)");
}

int main()
{
        int sockfd;
        uint8_t buf[IRM_MSG_BUF_SIZE];

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
                                create_ipcp(*(msg->name), msg->ipcp_type);
                                break;
                        case IRM_DESTROY_IPCP:
                                destroy_ipcp(*(msg->name));
                                break;
                        case IRM_BOOTSTRAP_IPCP:
                                bootstrap_ipcp(*(msg->name),
                                               *(msg->conf));
                                break;
                        case IRM_ENROLL_IPCP:
                                enroll_ipcp(*(msg->name),
                                            msg->dif_name);
                                break;
                        case IRM_REG_IPCP:
                                reg_ipcp(*(msg->name),
                                         msg->difs,
                                         msg->difs_size);
                                break;
                        case IRM_UNREG_IPCP:
                                unreg_ipcp(*(msg->name),
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
