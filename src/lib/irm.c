/*
 * Ouroboros - Copyright (C) 2016
 *
 * The API to instruct the IRM
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

#define OUROBOROS_PREFIX "libouroboros-irm"

#include <ouroboros/irm.h>
#include <ouroboros/common.h>
#include <ouroboros/logs.h>
#include <ouroboros/sockets.h>
#include <stdlib.h>

static int send_irm_msg(struct irm_msg * msg)
{
       int sockfd;
       buffer_t * buf;

       sockfd = client_socket_open(IRM_SOCK_PATH);
       if (sockfd < 0)
               return -1;

       buf = serialize_irm_msg(msg);
       if (buf == NULL) {
               close(sockfd);
               return -1;
       }

       if (write(sockfd, buf->data, buf->size) == -1) {
               close(sockfd);
               return -1;
       }

       free(buf->data);
       free(buf);

       close(sockfd);
       return 0;
}

int irm_create_ipcp(rina_name_t name,
                    char * ipcp_type)
{
        struct irm_msg msg;

        if (ipcp_type == NULL)
                return -1;

        msg.code = IRM_CREATE_IPCP;
        msg.name = &name;
        msg.ipcp_type = ipcp_type;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int irm_destroy_ipcp(rina_name_t name)
{
        struct irm_msg msg;

        msg.code = IRM_DESTROY_IPCP;
        msg.name = &name;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int irm_bootstrap_ipcp(rina_name_t name,
                       struct dif_config conf)
{
        struct irm_msg msg;

        msg.code = IRM_BOOTSTRAP_IPCP;
        msg.name = &name;
        msg.conf = &conf;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int irm_enroll_ipcp(rina_name_t name,
                    char * dif_name)
{
        struct irm_msg msg;

        msg.code = IRM_ENROLL_IPCP;
        msg.name = &name;
        msg.dif_name = dif_name;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int irm_reg_ipcp(rina_name_t name,
                 char ** difs,
                 size_t difs_size)
{
        struct irm_msg msg;

        msg.code = IRM_REG_IPCP;
        msg.name = &name;
        msg.difs = difs;
        msg.difs_size = difs_size;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int irm_unreg_ipcp(rina_name_t name,
                   char ** difs,
                   size_t difs_size)
{
        struct irm_msg msg;

        msg.code = IRM_UNREG_IPCP;
        msg.name = &name;
        msg.difs = difs;
        msg.difs_size = difs_size;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}
