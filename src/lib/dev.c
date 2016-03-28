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
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int fd = 0;

        if (ap_name == NULL ||
            difs == NULL ||
            difs_size == 0 ||
            difs[0] == NULL) {
                return -EINVAL;
        }

        msg.code = IRM_MSG_CODE__IRM_AP_REG;
        msg.ap_name = ap_name;
        msg.dif_name = difs;
        msg.n_dif_name = difs_size;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        fd = recv_msg->fd;
        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;
}

int ap_unreg(char * ap_name,
             char ** difs,
             size_t difs_size)
{
        irm_msg_t msg = IRM_MSG__INIT;

        if (ap_name == NULL ||
            difs == NULL ||
            difs_size == 0 ||
            difs[0] == NULL) {
                return -EINVAL;
        }

        msg.code = IRM_MSG_CODE__IRM_AP_UNREG;
        msg.ap_name = ap_name;
        msg.dif_name = difs;
        msg.n_dif_name = difs_size;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int flow_accept(int fd,
                char * ap_name,
                char * ae_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int cli_fd = 0;

        if (ap_name == NULL) {
                return -EINVAL;
        }

        msg.code = IRM_MSG_CODE__IRM_FLOW_ACCEPT;
        msg.has_fd = true;
        msg.fd = fd;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (recv_msg->has_fd == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }
        cli_fd = recv_msg->fd;
        ap_name = recv_msg->ap_name;
        ae_name = recv_msg->ae_name;

        irm_msg__free_unpacked(recv_msg, NULL);
        return cli_fd;
}

int flow_alloc_resp(int fd,
                    int result)
{
        irm_msg_t msg = IRM_MSG__INIT;

        msg.code = IRM_MSG_CODE__IRM_FLOW_ALLOC_RESP;
        msg.has_fd = true;
        msg.fd = fd;
        msg.has_result = true;
        msg.result = result;

        if (send_irm_msg(&msg)) {
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
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int fd = 0;

        if (dst_ap_name == NULL ||
            src_ap_name == NULL ||
            qos == NULL) {
                LOG_ERR("Invalid arguments");
                return -1;
        }

        msg.code = IRM_MSG_CODE__IRM_FLOW_ALLOC;
        msg.dst_ap_name = dst_ap_name;
        msg.ap_name = src_ap_name;
        msg.ae_name = src_ae_name;
        msg.has_oflags = true;
        msg.oflags = oflags;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (recv_msg->has_fd == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        fd = recv_msg->fd;
        irm_msg__free_unpacked(recv_msg, NULL);
        return fd;
}

int flow_alloc_res(int fd)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int result = 0;

        msg.code = IRM_MSG_CODE__IRM_FLOW_ALLOC_RES;
        msg.has_fd = true;
        msg.fd = fd;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        result = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return result;
}

int flow_dealloc(int fd)
{
        irm_msg_t msg = IRM_MSG__INIT;

        msg.code = IRM_MSG_CODE__IRM_FLOW_DEALLOC;
        msg.has_fd = true;
        msg.fd = fd;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int flow_cntl(int fd, int oflags)
{
        irm_msg_t msg = IRM_MSG__INIT;

        msg.has_fd = true;
        msg.fd = fd;
        msg.oflags = oflags;

        if (send_irm_msg(&msg)) {
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
