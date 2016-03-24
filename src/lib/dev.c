/*
 * Ouroboros - Copyright (C) 2016
 *
 * API for applications
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

#define OUROBOROS_PREFIX "libouroboros-dev"

#include <ouroboros/logs.h>
#include <ouroboros/dev.h>
#include <ouroboros/sockets.h>

#include <stdlib.h>

int ap_reg(char * ap_name,
           char ** difs,
           size_t difs_size)
{
        struct irm_msg msg;
        struct irm_msg * recv_msg = NULL;
        int fd = 0;

        if (ap_name == NULL ||
            difs == NULL ||
            difs_size == 0) {
                LOG_ERR("Invalid arguments");
                return -1;
        }

        msg.code = IRM_AP_REG;
        msg.ap_name = ap_name;
        msg.difs = difs;
        msg.difs_size = difs_size;

        recv_msg = send_recv_irmd_msg(&msg);
        if (recv_msg == NULL) {
                LOG_ERR("Failed to send and receive message");
                return -1;
        }

        fd = recv_msg->fd;
        free(recv_msg);

        return fd;
}

int ap_unreg(char * ap_name,
             char ** difs,
             size_t difs_size)
{
        struct irm_msg msg;

        if (ap_name == NULL ||
            difs == NULL ||
            difs_size == 0) {
                LOG_ERR("Invalid arguments");
                return -1;
        }

        msg.code = IRM_AP_UNREG;
        msg.ap_name = ap_name;
        msg.difs = difs;
        msg.difs_size = difs_size;

        if (send_irmd_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int flow_accept(int fd,
                char * ap_name,
                char * ae_name)
{
        struct irm_msg msg;
        struct irm_msg * recv_msg = NULL;
        int cli_fd = 0;

        if (ap_name == NULL) {
                LOG_ERR("Invalid arguments");
                return -1;
        }

        msg.code = IRM_FLOW_ACCEPT;
        msg.fd = fd;

        recv_msg = send_recv_irmd_msg(&msg);
        if (recv_msg == NULL) {
                LOG_ERR("Failed to send and receive message");
                return -1;
        }

        cli_fd = recv_msg->fd;
        ap_name = recv_msg->ap_name;
        if (ae_name == NULL)
                ae_name = "";
        else
                ae_name = recv_msg->ae_name;
        free(recv_msg);

        return cli_fd;
}

int flow_alloc_resp(int fd,
                    int result)
{
        struct irm_msg msg;

        msg.code = IRM_FLOW_ALLOC_RESP;
        msg.fd = fd;
        msg.result = result;

        if (send_irmd_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int flow_alloc(char * dst_ap_name,
               char * src_ap_name,
               char * src_ae_name,
               struct qos_spec * qos,
               int oflags)
{
        struct irm_msg msg;
        struct irm_msg * recv_msg = NULL;
        int fd = 0;

        if (dst_ap_name == NULL ||
            src_ap_name == NULL) {
                LOG_ERR("Invalid arguments");
                return -1;
        }

        msg.code = IRM_FLOW_ALLOC;
        msg.dst_ap_name = dst_ap_name;
        msg.ap_name = src_ap_name;
        if (src_ae_name == NULL)
                msg.ae_name = "";
        else
                msg.ae_name = src_ae_name;
        msg.qos = qos;
        msg.oflags = oflags;

        recv_msg = send_recv_irmd_msg(&msg);
        if (recv_msg == NULL) {
                LOG_ERR("Failed to send and receive message");
                return -1;
        }

        fd = recv_msg->fd;
        free(recv_msg);

        return fd;
}

int flow_alloc_res(int fd)
{
        struct irm_msg msg;
        struct irm_msg * recv_msg = NULL;
        int result = 0;

        msg.code = IRM_FLOW_ALLOC_RES;
        msg.fd = fd;

        recv_msg = send_recv_irmd_msg(&msg);
        if (recv_msg == NULL) {
                LOG_ERR("Failed to send and receive message");
                return -1;
        }

        result = recv_msg->result;
        free(recv_msg);

        return result;
}

int flow_dealloc(int fd)
{
        struct irm_msg msg;

        msg.code = IRM_FLOW_DEALLOC;
        msg.fd = fd;

        if (send_irmd_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int flow_cntl(int fd, int oflags)
{
        struct irm_msg msg;

        msg.fd = fd;
        msg.oflags = oflags;

        if (send_irmd_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

ssize_t flow_write(int fd,
                   void * buf,
                   size_t count)
{
        LOG_MISSING;

        return -1;
}

ssize_t flow_read(int fd,
                  void * buf,
                  size_t count)
{
        LOG_MISSING;

        return -1;
}
