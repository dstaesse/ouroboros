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

int irm_create_ipcp(rina_name_t name,
                    char * ipcp_type)
{
        int sockfd;
        struct irm_msg msg;
        buffer_t * buf;

        if (!ipcp_type)
                return -1;

        sockfd = client_socket_open(IRM_SOCK_PATH);
        if (sockfd < 0)
                return -1;

        msg.code = IRM_CREATE_IPCP;
        msg.msgs.create_ipcp.name = &name;
        msg.msgs.create_ipcp.ipcp_type = ipcp_type;

        buf = serialize_irm_msg(&msg);
        if (!buf)
                return -1;

        write(sockfd, buf->data, buf->size);

        close(sockfd);

        return 0;
}

int irm_destroy_ipcp(int ipcp_id)
{

        return 0;
}

int irm_bootstrap_ipcp(int ipcp_id,
                       struct dif_info info)
{

        return 0;
}

int irm_enroll_ipcp(int ipcp_id,
                    char * dif_name)
{

        return 0;
}

int irm_reg_ipcp(int ipcp_id,
                 char ** difs)
{

        return 0;
}

int irm_unreg_ipcp(int ipcp_id,
                   char ** difs)
{

        return 0;
}

char ** irm_list_ipcps()
{

        return 0;
}

char ** irm_list_ipcp_types()
{

        return 0;
}
