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
#include <ouroboros/utils.h>

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

int send_irmd_msg(struct irm_msg * msg)
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
               free(buf->data);
               free(buf);
               close(sockfd);
               return -1;
       }

       free(buf->data);
       free(buf);

       close(sockfd);
       return 0;
}

struct irm_msg * send_recv_irmd_msg(struct irm_msg * msg)
{
        int sockfd;
        buffer_t * buf;
        ssize_t count = 0;
        struct irm_msg * recv_msg = NULL;

        sockfd = client_socket_open(IRM_SOCK_PATH);
        if (sockfd < 0)
                return NULL;

        buf = serialize_irm_msg(msg);
        if (buf == NULL) {
                close(sockfd);
                return NULL;
        }

        if (write(sockfd, buf->data, buf->size) == -1) {
                free(buf->data);
                free(buf);
                close(sockfd);
                return NULL;
        }

        count = read(sockfd, buf->data, IRM_MSG_BUF_SIZE);
        if (count <= 0) {
                free(buf->data);
                free(buf);
                close(sockfd);
                return NULL;
        }

        recv_msg = deserialize_irm_msg(buf);

        free(buf->data);
        free(buf);

        close(sockfd);
        return recv_msg;
}


int send_irm_msg(irm_msg_t * msg)
{

        return -1;
}

char * ipcp_sock_path(pid_t pid)
{
        char * full_name = NULL;
        char * pid_string = NULL;
        size_t len = 0;
        char * delim = "-";

        len = n_digits(pid);
        pid_string = malloc(len + 1);
        if (pid_string == NULL)
                return NULL;

        sprintf(pid_string, "%d", pid);

        len += strlen(IPCP_SOCK_PATH_PREFIX);
        len += strlen(delim);
        full_name = malloc(len + 1);
        if (full_name == NULL) {
                free(pid_string);
                return NULL;
        }

        strcpy(full_name, IPCP_SOCK_PATH_PREFIX);
        strcat(full_name, delim);
        strcat(full_name, pid_string);

        free(pid_string);

        return full_name;
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

static void ser_copy_name(rina_name_t * name,
                          uint8_t * data,
                          int * offset)
{
        ser_copy_value(strlen(name->ap_name) + 1,
                       data, name->ap_name, offset);
        ser_copy_value(sizeof(int), data,
                       &name->api_id, offset);
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
                           unsigned int * dst,
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

static rina_name_t * deser_copy_name(uint8_t * data,
                                     int * offset)
{
        rina_name_t * name;

        name = name_create();
        if (name == NULL) {
                LOG_ERR("Failed to alloc memory");
                return NULL;
        }

        if (deser_copy_string(data, &name->ap_name, offset)) {
                name_destroy(name);
                return NULL;
        }

        deser_copy_int(data, &name->api_id, offset);

        return name;
}


/* Move these to a separate file? */
static buffer_t * buffer_create()
{
        buffer_t * buf;

        buf = malloc(sizeof(*buf));
        if (buf == NULL)
                return NULL;

        buf->data = malloc(IRM_MSG_BUF_SIZE);
        if (buf->data == NULL) {
                free(buf);
                return NULL;
        }

        return buf;
}

static void buffer_destroy(buffer_t * buf)
{
        if (buf->data != NULL)
                free(buf->data);

        if (buf != NULL)
                free(buf);
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

        buf = buffer_create();
        if (buf == NULL)
                return NULL;

        data = buf->data;

        ser_copy_value(sizeof(enum irm_msg_code), data, &msg->code, &offset);

        ser_copy_name(msg->name, data, &offset);

        switch (msg->code) {
        case IRM_CREATE_IPCP:
                if (msg->ipcp_type == NULL ||
                    !name_is_ok(msg->name)) {
                        LOG_ERR("Null pointer passed");
                        buffer_destroy(buf);
                        return NULL;
                }
                ser_copy_name(msg->name, data, &offset);
                ser_copy_value(strlen(msg->ipcp_type) + 1, data,
                               msg->ipcp_type, &offset);
                break;
        case IRM_DESTROY_IPCP:
                if (!name_is_ok(msg->name)) {
                        LOG_ERR("Null pointer passed");
                        buffer_destroy(buf);
                        return NULL;
                }
                ser_copy_name(msg->name, data, &offset);
                break;
        case IRM_BOOTSTRAP_IPCP:
                if (!name_is_ok(msg->name)) {
                        LOG_ERR("Null pointer passed");
                        buffer_destroy(buf);
                        return NULL;
                }
                ser_copy_name(msg->name, data, &offset);
                /* FIXME: Fields missing, need to define dif_conf properly */
                break;
        case IRM_ENROLL_IPCP:
                if (msg->dif_name == NULL ||
                    !name_is_ok(msg->name)) {
                        buffer_destroy(buf);
                        return NULL;
                }

                ser_copy_name(msg->name, data, &offset);
                ser_copy_value(strlen(msg->dif_name) + 1, data,
                               msg->dif_name, &offset);

                break;
        case IRM_REG_IPCP:
        case IRM_UNREG_IPCP:
                if (msg->difs == NULL ||
                    msg->difs[0] == NULL ||
                    !name_is_ok(msg->name)) {
                        buffer_destroy(buf);
                        return NULL;
                }

                ser_copy_name(msg->name, data, &offset);

                ser_copy_value(sizeof(size_t), data, &msg->difs_size, &offset);

                pos = msg->difs;
                for (i = 0; i < msg->difs_size; i++) {
                        ser_copy_value(strlen(*pos) + 1, data, *pos, &offset);
                        pos++;
                }

                break;
        case IRM_AP_REG:
        case IRM_AP_UNREG:
                if (msg->ap_name == NULL ||
                    msg->difs == NULL ||
                    msg->difs[0] == NULL) {
                        LOG_ERR("Invalid arguments");
                        buffer_destroy(buf);
                        return NULL;
                }

                ser_copy_value(strlen(msg->ap_name) + 1,
                               data, msg->ap_name, &offset);

                ser_copy_value(sizeof(size_t), data, &msg->difs_size, &offset);

                pos = msg->difs;
                for (i = 0; i < msg->difs_size; i++) {
                        ser_copy_value(strlen(*pos) + 1, data, *pos, &offset);
                        pos++;
                }

                break;
        case IRM_FLOW_ACCEPT:
                if (msg->ap_name == NULL ||
                    msg->ae_name == NULL) {
                        LOG_ERR("Invalid arguments");
                        buffer_destroy(buf);
                        return NULL;
                }

                ser_copy_value(sizeof(int), data, &msg->fd, &offset);

                ser_copy_value(strlen(msg->ap_name) + 1,
                               data, msg->ap_name, &offset);

                ser_copy_value(strlen(msg->ae_name) + 1,
                               data, msg->ae_name, &offset);

                break;
        case IRM_FLOW_ALLOC_RESP:
                ser_copy_value(sizeof(int), data, &msg->fd, &offset);

                ser_copy_value(sizeof(int), data, &msg->result, &offset);

                break;
        case IRM_FLOW_ALLOC:
                if (msg->ap_name == NULL ||
                    msg->ae_name == NULL ||
                    msg->dst_ap_name == NULL ||
                    msg->qos == NULL) {
                        LOG_ERR("Invalid arguments");
                        buffer_destroy(buf);
                        return NULL;
                }

                ser_copy_value(strlen(msg->dst_ap_name) + 1,
                               data, msg->dst_ap_name, &offset);

                ser_copy_value(strlen(msg->ap_name) + 1,
                               data, msg->ap_name, &offset);

                ser_copy_value(strlen(msg->ae_name) + 1,
                               data, msg->ae_name, &offset);

                /* FIXME: Serialize qos spec here */

                ser_copy_value(sizeof(int), data, &msg->oflags, &offset);

                break;
        case IRM_FLOW_ALLOC_RES:
        case IRM_FLOW_DEALLOC:
                ser_copy_value(sizeof(int), data, &msg->fd, &offset);
                break;
        case IRM_FLOW_CONTROL:
                ser_copy_value(sizeof(int), data, &msg->fd, &offset);
                ser_copy_value(sizeof(int), data, &msg->oflags, &offset);
                break;
        case IRM_FLOW_WRITE:
                LOG_MISSING;
                break;
        case IRM_FLOW_READ:
                LOG_MISSING;
                break;
        case IRM_AP_REG_R:
        case IRM_FLOW_ALLOC_R:
                ser_copy_value(sizeof(int), data, &msg->fd, &offset);
                break;
        case IRM_FLOW_ACCEPT_R:
                ser_copy_value(sizeof(int), data, &msg->fd, &offset);

                ser_copy_value(strlen(msg->ap_name) + 1,
                               data, msg->ap_name, &offset);

                ser_copy_value(strlen(msg->ae_name) + 1,
                               data, msg->ae_name, &offset);
                break;
        case IRM_FLOW_ALLOC_RES_R:
                ser_copy_value(sizeof(int), data, &msg->result, &offset);
                break;
        default:
                LOG_ERR("Don't know that code");
                buffer_destroy(buf);
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

        deser_copy_value(sizeof(enum irm_msg_code),
                         &msg->code, data->data, &offset);

        switch (msg->code) {
        case IRM_CREATE_IPCP:
                msg->name = deser_copy_name(data->data, &offset);
                if (msg->name == NULL) {
                        LOG_ERR("Failed to reconstruct name");
                        free(msg);
                        return NULL;
                }

                if (deser_copy_string(data->data,
                                      &msg->ipcp_type,
                                      &offset)) {
                        name_destroy(msg->name);
                        free(msg);
                        return NULL;
                }

                break;
        case IRM_DESTROY_IPCP:
                msg->name = deser_copy_name(data->data, &offset);
                if (msg->name == NULL) {
                        LOG_ERR("Failed to reconstruct name");
                        free(msg);
                        return NULL;
                }

                break;
        case IRM_BOOTSTRAP_IPCP:
                msg->name = deser_copy_name(data->data, &offset);
                if (msg->name == NULL) {
                        LOG_ERR("Failed to reconstruct name");
                        free(msg);
                        return NULL;
                }

                break;
        case IRM_ENROLL_IPCP:
                msg->name = deser_copy_name(data->data, &offset);
                if (msg->name == NULL) {
                        LOG_ERR("Failed to reconstruct name");
                        free(msg);
                        return NULL;
                }

                if (deser_copy_string(data->data,
                                      &msg->dif_name,
                                      &offset)) {
                        name_destroy(msg->name);
                        free(msg);
                        return NULL;
                }

                break;
        case IRM_REG_IPCP:
        case IRM_UNREG_IPCP:
                msg->name = deser_copy_name(data->data, &offset);
                if (msg->name == NULL) {
                        LOG_ERR("Failed to reconstruct name");
                        free(msg);
                        return NULL;
                }

                deser_copy_size_t(data->data, &difs_size, &offset);
                msg->difs_size = difs_size;

                msg->difs = malloc(sizeof(*(msg->difs)) * difs_size);
                if (msg->difs == NULL) {
                        name_destroy(msg->name);
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
                                name_destroy(msg->name);
                                free(msg);
                                return NULL;
                        }
                }

                break;
        case IRM_AP_REG:
        case IRM_AP_REG_R:
        case IRM_AP_UNREG:
        case IRM_FLOW_ACCEPT:
        case IRM_FLOW_ACCEPT_R:
        case IRM_FLOW_ALLOC_RESP:
        case IRM_FLOW_ALLOC:
        case IRM_FLOW_ALLOC_R:
        case IRM_FLOW_ALLOC_RES:
        case IRM_FLOW_ALLOC_RES_R:
        case IRM_FLOW_DEALLOC:
        case IRM_FLOW_CONTROL:
        case IRM_FLOW_WRITE:
        case IRM_FLOW_READ:
                LOG_MISSING;
                break;
        default:
                LOG_ERR("Don't know that code");
                free(msg);
                return NULL;
        }

        return msg;
}

buffer_t * serialize_ipcp_msg(struct ipcp_msg * msg)
{
        buffer_t * buf = NULL;
        uint8_t * data = NULL;
        int offset = 0;
        char ** pos = NULL;
        int i = 0;

        if (msg == NULL)
                return NULL;

        buf = buffer_create();
        if (buf == NULL)
                return NULL;

        data = buf->data;

        ser_copy_value(sizeof(enum ipcp_msg_code),
                       data, &msg->code, &offset);

        switch (msg->code) {
        case IPCP_BOOTSTRAP:
                break;
        case IPCP_ENROLL:
                if (msg->dif_name == NULL) {
                        buffer_destroy(buf);
                        return NULL;
                }

                ser_copy_value(strlen(msg->dif_name) + 1, data,
                               msg->dif_name, &offset);

                if (msg->ap_name == NULL) {
                        LOG_ERR("Null pointer passed");
                        buffer_destroy(buf);
                        return NULL;
                }
                ser_copy_value(strlen(msg->ap_name) + 1, data,
                               msg->ap_name, &offset);

                /* All these operations end with a list of DIFs */
        case IPCP_REG:
        case IPCP_UNREG:
                if (msg->difs == NULL || msg->difs[0] == NULL) {
                        buffer_destroy(buf);
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
                buffer_destroy(buf);
                return NULL;
        }

        buf->size = offset;

        return buf;
}

struct ipcp_msg * deserialize_ipcp_msg(buffer_t * data)
{
        struct ipcp_msg * msg;
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

        deser_copy_value(sizeof(enum ipcp_msg_code),
                         &msg->code, data->data, &offset);

        switch (msg->code) {
        case IPCP_BOOTSTRAP:
                break;
        case IPCP_ENROLL:
                if (deser_copy_string(data->data,
                                      &msg->dif_name,
                                      &offset)) {
                        free(msg);
                        return NULL;
                }

                deser_copy_string(data->data,
                                  &msg->ap_name,
                                  &offset);
                if (msg->ap_name == NULL) {
                        LOG_ERR("Failed to reconstruct name");
                        free(msg->dif_name);
                        free(msg);
                        return NULL;
                }

                deser_copy_size_t(data->data, &difs_size, &offset);
                msg->difs_size = difs_size;

                msg->difs = malloc(sizeof(*(msg->difs)) * difs_size);
                if (msg->difs == NULL) {
                        free(msg->ap_name);
                        free(msg->dif_name);
                        free(msg);
                        return NULL;
                }

                for (i = 0; i < difs_size; i++) {
                        if (deser_copy_string(data->data,
                                              &msg->difs[i],
                                              &offset)) {
                                for (j = 0; j < i; j++)
                                        free(msg->difs[j]);
                                free(msg->dif_name);
                                free(msg->difs);
                                free(msg->ap_name);
                                free(msg);
                                return NULL;
                        }
                }
                break;
        case IPCP_REG:
        case IPCP_UNREG:
                deser_copy_size_t(data->data, &difs_size, &offset);
                msg->difs_size = difs_size;

                msg->difs = malloc(sizeof(*(msg->difs)) * difs_size);
                if (msg->difs == NULL) {
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
