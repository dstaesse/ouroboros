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
#include <sys/socket.h>
#include <sys/un.h>

#define BUF_SIZE 256

int main()
{
        int sockfd;

        sockfd = server_socket_open(IRM_SOCK_PATH);
        if (sockfd < 0)
                return -1;

        while (true) {
                int     cli_sockfd;
                struct irm_msg_sock msg;
                ssize_t count;
                char    buf[BUF_SIZE];

                cli_sockfd = accept(sockfd, 0, 0);
                if (cli_sockfd < 0) {
                        LOG_ERR("Cannot accept new connection");
                }

                count = read(cli_sockfd, buf, BUF_SIZE);
                if (count) {
                        msg = (struct struct irm_msg_sock) buf;
                        LOG_INFO("Got message code %d", buf.code);
                }

                close(cli_sockfd);
        }

        return 0;
}
