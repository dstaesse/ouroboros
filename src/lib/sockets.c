/*
 * Ouroboros - Copyright (C) 2016
 *
 * The sockets layer to communicate between daemons
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

#define OUROBOROS_PREFIX "libouroboros-sockets"

#include <ouroboros/logs.h>
#include <ouroboros/common.h>
#include <ouroboros/sockets.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <string.h>
#include <malloc.h>

int client_socket_open(char * file_name)
{
        int sockfd;
        struct sockaddr_un serv_addr;

        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd < 0) {
                LOG_ERR("Failed to open socket");
                return -1;
        }

        serv_addr.sun_family = AF_UNIX;
        sprintf(serv_addr.sun_path, "%s", file_name);

        if (connect(sockfd,
                    (struct sockaddr *) &serv_addr,
                    sizeof(serv_addr))) {
                LOG_ERR("Failed to connect to daemon");
                return -1;
        }

        return sockfd;
}

int server_socket_open(char * file_name)
{
        int sockfd;
        struct sockaddr_un serv_addr;
        struct stat sb;

        if (!stat(file_name, &sb)) {
                /* File exists */
                if (unlink(file_name)) {
                        LOG_ERR("Failed to unlink filename: %s",
                                strerror(errno));
                        return -1;
                }
        }

        sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sockfd < 0) {
                LOG_ERR("Failed to open socket");
                return -1;
        }

        serv_addr.sun_family = AF_UNIX;
        sprintf(serv_addr.sun_path, "%s", file_name);

        if (bind(sockfd,
                 (struct sockaddr *) &serv_addr,
                 sizeof(serv_addr))) {
                LOG_ERR("Failed to bind socket");
                return -1;
        }

        if (listen(sockfd, 0)) {
                LOG_ERR("Failed to listen to socket");
                return -1;
        }

        return sockfd;
}

static int serialized_string_len(uint8_t * data)
{
        uint8_t * seek = data;

        while (*seek != '\0')
                seek++;

        return (seek - data) + 1;
}

static void ser_copy_value(size_t flen,
                           void * dst,
                           void * src,
                           int * offset)
{
        memcpy(dst + *offset, src, flen);
        *offset += flen;
}

static void deser_copy_value(size_t flen,
                             void * dst,
                             void * src,
                             int * offset)
{
        memcpy(dst, src + *offset, flen);
        *offset += flen;
}

static int deser_copy_string(uint8_t * data,
                             char ** dst,
                             int * offset)
{
        size_t flen;

        flen = serialized_string_len(data + *offset);
        *dst = malloc(sizeof(**dst) * (flen + 1));
        if (*dst == NULL)
                return -1;
        deser_copy_value(flen, *dst, data, offset);
        return 0;
}

static void deser_copy_int(uint8_t * data,
                           int * dst,
                           int * offset)
{
        *dst = 0;
        deser_copy_value(sizeof(int), dst, data, offset);
}

static void deser_copy_size_t(uint8_t * data,
                              size_t * dst,
                              int * offset)
{
        *dst = 0;
        deser_copy_value(sizeof(size_t), dst, data, offset);
}

static void deser_copy_enum(uint8_t * data,
                            enum irm_msg_code * dst,
                            int * offset)
{
        *dst = 0;
        deser_copy_value(sizeof(enum irm_msg_code), dst, data, offset);
}

buffer_t * serialize_irm_msg(struct irm_msg * msg)
{
        buffer_t * buf;
        uint8_t * data;
        int offset = 0;
        int i;
        char ** pos;

        if (msg == NULL)
                return NULL;

        buf = malloc(sizeof(*buf));
        if (buf == NULL)
                return NULL;

        buf->data = malloc(IRM_MSG_BUF_SIZE);
        if (buf->data == NULL) {
                free(buf);
                return NULL;
        }

        data = buf->data;

        ser_copy_value(sizeof(enum irm_msg_code), data, &msg->code, &offset);

        if (msg->name == NULL ||
            msg->name->ap_name == NULL ||
            msg->name->ae_name == NULL ) {
                LOG_ERR("Null pointer passed");
                free(buf->data);
                free(buf);
                return NULL;
        }

        /*
         * Every IRM message passes the name, may change
         * Move to separate function when it does
         */
        ser_copy_value(strlen(msg->name->ap_name) + 1, data,
                       msg->name->ap_name, &offset);

        ser_copy_value(sizeof(int), data, &msg->name->api_id, &offset);

        ser_copy_value(strlen(msg->name->ae_name) + 1, data,
                       msg->name->ae_name, &offset);

        ser_copy_value(sizeof(int), data, &msg->name->aei_id, &offset);

        switch (msg->code) {
        case IRM_CREATE_IPCP:
                if (!msg->ipcp_type) {
                        LOG_ERR("Null pointer passed");
                        free(buf->data);
                        free(buf);
                        return NULL;
                }

                ser_copy_value(strlen(msg->ipcp_type) + 1, data,
                               msg->ipcp_type, &offset);
                break;
        case IRM_DESTROY_IPCP:
                break;
        case IRM_BOOTSTRAP_IPCP:
                /* FIXME: Fields missing, need to define dif_conf properly */
                break;
        case IRM_ENROLL_IPCP:
                if (msg->dif_name == NULL) {
                        free(buf->data);
                        free(buf);
                        return NULL;
                }

                ser_copy_value(strlen(msg->dif_name) + 1, data,
                               msg->dif_name, &offset);

                break;
        case IRM_REG_IPCP:
        case IRM_UNREG_IPCP:
                if (msg->difs == NULL || msg->difs[0] == NULL) {
                        free(buf->data);
                        free(buf);
                        return NULL;
                }

                ser_copy_value(sizeof(size_t), data, &msg->difs_size, &offset);

                pos = msg->difs;
                for (i = 0; i < msg->difs_size; i++) {
                        ser_copy_value(strlen(*pos) + 1, data, *pos, &offset);
                        pos++;
                }

                break;
        default:
                LOG_ERR("Don't know that code");
                free(buf->data);
                free(buf);
                return NULL;
        }

        buf->size = offset;

        return buf;
}

struct irm_msg * deserialize_irm_msg(buffer_t * data)
{
        struct irm_msg * msg;
        int i, j;
        int offset = 0;
        size_t difs_size;

        if (data == NULL || data->data == NULL) {
                LOG_ERR("Got a null pointer");
                return NULL;
        }

        msg = malloc(sizeof(*msg));
        if (msg == NULL) {
                LOG_ERR("Failed to allocate memory");
                return NULL;
        }

        deser_copy_enum(data->data, &msg->code, &offset);

        msg->name = malloc(sizeof(*(msg->name)));
        if (msg->name == NULL) {
                LOG_ERR("Failed to alloc memory");
                free(msg);
                return NULL;
        }

        if (deser_copy_string(data->data,
                              &msg->name->ap_name,
                              &offset)) {
                free(msg->name);
                free(msg);
                return NULL;
        }

        deser_copy_int(data->data, &msg->name->api_id, &offset);

        if (deser_copy_string(data->data,
                              &msg->name->ae_name,
                              &offset)) {
                free(msg->name->ap_name);
                free(msg->name);
                free(msg);
                return NULL;
        }

        deser_copy_int(data->data, &msg->name->aei_id, &offset);

        switch (msg->code) {
        case IRM_CREATE_IPCP:
                   if (deser_copy_string(data->data,
                                         &msg->ipcp_type,
                                         &offset)) {
                        free(msg->name->ae_name);
                        free(msg->name->ap_name);
                        free(msg->name);
                        free(msg);
                        return NULL;
                }

                break;
        case IRM_DESTROY_IPCP:
                break;
        case IRM_BOOTSTRAP_IPCP:
                break;
        case IRM_ENROLL_IPCP:
                if (deser_copy_string(data->data,
                                      &msg->dif_name,
                                      &offset)) {
                        free(msg->name->ae_name);
                        free(msg->name->ap_name);
                        free(msg->name);
                        free(msg);
                        return NULL;
                }

                break;
        case IRM_REG_IPCP:
        case IRM_UNREG_IPCP:
                deser_copy_size_t(data->data, &difs_size, &offset);

                msg->difs = malloc(sizeof(*(msg->difs)) * difs_size);
                if (msg->difs == NULL) {
                        free(msg->name->ae_name);
                        free(msg->name->ap_name);
                        free(msg->name);
                        free(msg);
                        return NULL;
                }

                for (i = 0; i < difs_size; i++) {
                        if (deser_copy_string(data->data,
                                              &msg->difs[i],
                                              &offset)) {
                                for (j = 0; j < i; j++)
                                        free(msg->difs[j]);
                                free(msg->difs);
                                free(msg->name->ae_name);
                                free(msg->name->ap_name);
                                free(msg->name);
                                free(msg);
                                return NULL;
                        }
                }

                break;
        default:
                LOG_ERR("Don't know that code");
                free(msg);
                return NULL;
        }

        return msg;
}
