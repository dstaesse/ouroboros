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

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/dev.h>
#include <ouroboros/sockets.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/shm_du_map.h>
#include <ouroboros/shm_ap_rbuff.h>
#include <ouroboros/utils.h>

#include <stdlib.h>
#include <string.h>

struct flow {
        struct shm_ap_rbuff * rb;
        int                   port_id;
        int                   oflags;

        pid_t                 api;
};

struct ap_data {
        char *                ap_name;
        pid_t                 api;
        struct shm_du_map *   dum;
        struct bmp *          fds;
        struct shm_ap_rbuff * rb;
        pthread_rwlock_t      data_lock;

        struct flow           flows[AP_MAX_FLOWS];
        pthread_rwlock_t      flows_lock;
} * _ap_instance;

int ap_init(char * ap_name)
{
        int i = 0;

        ap_name = path_strip(ap_name);

        _ap_instance = malloc(sizeof(struct ap_data));
        if (_ap_instance == NULL) {
                return -ENOMEM;
        }

        _ap_instance->api = getpid();
        _ap_instance->ap_name = ap_name;

        _ap_instance->fds = bmp_create(AP_MAX_FLOWS, 0);
        if (_ap_instance->fds == NULL) {
                free(_ap_instance);
                return -ENOMEM;
        }

        _ap_instance->dum = shm_du_map_open();
        if (_ap_instance->dum == NULL) {
                bmp_destroy(_ap_instance->fds);
                free(_ap_instance);
                return -1;
        }

        _ap_instance->rb = shm_ap_rbuff_create();
        if (_ap_instance->rb == NULL) {
                shm_du_map_close(_ap_instance->dum);
                bmp_destroy(_ap_instance->fds);
                free(_ap_instance);
                return -1;
        }

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                _ap_instance->flows[i].rb = NULL;
                _ap_instance->flows[i].port_id = -1;
                _ap_instance->flows[i].api = -1;
        }

        pthread_rwlock_init(&_ap_instance->flows_lock, NULL);
        pthread_rwlock_init(&_ap_instance->data_lock, NULL);

        return 0;
}

void ap_fini(void)
{
        int i = 0;

        if (_ap_instance == NULL)
                return;

        pthread_rwlock_wrlock(&_ap_instance->data_lock);

        if (_ap_instance->fds != NULL)
                bmp_destroy(_ap_instance->fds);
        if (_ap_instance->rb != NULL)
                shm_ap_rbuff_destroy(_ap_instance->rb);
        if (_ap_instance->dum != NULL)
                shm_du_map_close_on_exit(_ap_instance->dum);

        pthread_rwlock_rdlock(&_ap_instance->flows_lock);

        for (i = 0; i < AP_MAX_FLOWS; ++i)
                if (_ap_instance->flows[i].rb != NULL)
                        shm_ap_rbuff_close(_ap_instance->flows[i].rb);

        pthread_rwlock_unlock(&_ap_instance->flows_lock);
        pthread_rwlock_unlock(&_ap_instance->data_lock);

        free(_ap_instance);
}

#if 0
static int port_id_to_fd(int port_id)
{
        int i;
        for (i = 0; i < AP_MAX_FLOWS; ++i)
                if (_ap_instance->flows[i].port_id == port_id
                        && _ap_instance->flows[i].state != FLOW_NULL)
                        return i;
        return -1;
}
#endif

int flow_accept(char ** ae_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int cfd = -1;

        msg.code    = IRM_MSG_CODE__IRM_FLOW_ACCEPT;
        msg.has_api = true;

        pthread_rwlock_rdlock(&_ap_instance->data_lock);

        msg.ap_name = _ap_instance->ap_name;
        msg.api     = _ap_instance->api;

        pthread_rwlock_unlock(&_ap_instance->data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (!recv_msg->has_api || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        pthread_rwlock_rdlock(&_ap_instance->data_lock);
        pthread_rwlock_wrlock(&_ap_instance->flows_lock);

        cfd = bmp_allocate(_ap_instance->fds);
        if (!bmp_is_id_valid(_ap_instance->fds, cfd)) {
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        _ap_instance->flows[cfd].rb = shm_ap_rbuff_open(recv_msg->api);
        if (_ap_instance->flows[cfd].rb == NULL) {
                bmp_release(_ap_instance->fds, cfd);
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        if (ae_name != NULL) {
                *ae_name = strdup(recv_msg->ae_name);
                if (*ae_name == NULL) {
                        shm_ap_rbuff_close(_ap_instance->flows[cfd].rb);
                        bmp_release(_ap_instance->fds, cfd);
                        pthread_rwlock_unlock(&_ap_instance->flows_lock);
                        pthread_rwlock_unlock(&_ap_instance->data_lock);
                        irm_msg__free_unpacked(recv_msg, NULL);
                        return -ENOMEM;
                }
        }

        _ap_instance->flows[cfd].port_id = recv_msg->port_id;
        _ap_instance->flows[cfd].oflags  = FLOW_O_DEFAULT;

        pthread_rwlock_unlock(&_ap_instance->flows_lock);
        pthread_rwlock_unlock(&_ap_instance->data_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        return cfd;
}

int flow_alloc_resp(int fd,
                    int response)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        msg.code         = IRM_MSG_CODE__IRM_FLOW_ALLOC_RESP;
        msg.has_api      = true;
        msg.api          = _ap_instance->api;
        msg.has_port_id  = true;

        pthread_rwlock_rdlock(&_ap_instance->data_lock);
        pthread_rwlock_rdlock(&_ap_instance->flows_lock);

        if (_ap_instance->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return -ENOTALLOC;
        }

        msg.port_id      = _ap_instance->flows[fd].port_id;

        pthread_rwlock_unlock(&_ap_instance->flows_lock);

        msg.has_response = true;
        msg.response     = response;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return -1;
        }

        if (!recv_msg->has_result) {
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;

        pthread_rwlock_unlock(&_ap_instance->data_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int flow_alloc(char * dst_name,
               char * src_ae_name,
               struct qos_spec * qos)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int fd = -1;

        if (dst_name == NULL)
                return -EINVAL;

        if (src_ae_name == NULL)
                src_ae_name  = UNKNOWN_AE;

        msg.code        = IRM_MSG_CODE__IRM_FLOW_ALLOC;
        msg.dst_name    = dst_name;
        msg.ae_name     = src_ae_name;
        msg.has_api     = true;

        pthread_rwlock_rdlock(&_ap_instance->data_lock);

        msg.api         = _ap_instance->api;

        pthread_rwlock_unlock(&_ap_instance->data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (!recv_msg->has_api || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        pthread_rwlock_rdlock(&_ap_instance->data_lock);
        pthread_rwlock_wrlock(&_ap_instance->flows_lock);

        fd = bmp_allocate(_ap_instance->fds);
        if (!bmp_is_id_valid(_ap_instance->fds, fd)) {
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        _ap_instance->flows[fd].rb = shm_ap_rbuff_open(recv_msg->api);
        if (_ap_instance->flows[fd].rb == NULL) {
                bmp_release(_ap_instance->fds, fd);
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        _ap_instance->flows[fd].port_id = recv_msg->port_id;
        _ap_instance->flows[fd].oflags  = FLOW_O_DEFAULT;
        _ap_instance->flows[fd].api     =
                shm_ap_rbuff_get_api(_ap_instance->flows[fd].rb);

        pthread_rwlock_unlock(&_ap_instance->flows_lock);
        pthread_rwlock_unlock(&_ap_instance->data_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;
}

int flow_alloc_res(int fd)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int result = 0;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        msg.code         = IRM_MSG_CODE__IRM_FLOW_ALLOC_RES;
        msg.has_port_id  = true;

        pthread_rwlock_rdlock(&_ap_instance->data_lock);
        pthread_rwlock_rdlock(&_ap_instance->flows_lock);

        if (_ap_instance->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return -ENOTALLOC;
        }

        msg.port_id = _ap_instance->flows[fd].port_id;

        pthread_rwlock_unlock(&_ap_instance->flows_lock);
        pthread_rwlock_unlock(&_ap_instance->data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (!recv_msg->has_result) {
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
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code         = IRM_MSG_CODE__IRM_FLOW_DEALLOC;
        msg.has_port_id  = true;

        pthread_rwlock_rdlock(&_ap_instance->data_lock);
        pthread_rwlock_wrlock(&_ap_instance->flows_lock);

        if (_ap_instance->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return -ENOTALLOC;
        }

        msg.port_id = _ap_instance->flows[fd].port_id;

        _ap_instance->flows[fd].port_id = -1;
        shm_ap_rbuff_close(_ap_instance->flows[fd].rb);
        _ap_instance->flows[fd].rb = NULL;
        _ap_instance->flows[fd].api = -1;

        bmp_release(_ap_instance->fds, fd);

        pthread_rwlock_unlock(&_ap_instance->flows_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return -1;
        }

        if (!recv_msg->has_result) {
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;

        pthread_rwlock_unlock(&_ap_instance->data_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int flow_cntl(int fd, int cmd, int oflags)
{
        int old;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_rdlock(&_ap_instance->data_lock);
        pthread_rwlock_wrlock(&_ap_instance->flows_lock);

        if (_ap_instance->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return -ENOTALLOC;
        }

        old = _ap_instance->flows[fd].oflags;

        switch (cmd) {
        case FLOW_F_GETFL: /* GET FLOW FLAGS */
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return old;
        case FLOW_F_SETFL: /* SET FLOW FLAGS */
                _ap_instance->flows[fd].oflags = oflags;
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return old;
        default:
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return FLOW_O_INVALID; /* unknown command */
        }
}

ssize_t flow_write(int fd, void * buf, size_t count)
{
        ssize_t index;
        struct rb_entry e;

        if (buf == NULL)
                return 0;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_rdlock(&_ap_instance->data_lock);
        pthread_rwlock_rdlock(&_ap_instance->flows_lock);

        if (_ap_instance->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return -ENOTALLOC;
        }

        if (_ap_instance->flows[fd].oflags & FLOW_O_NONBLOCK) {
                index = shm_du_map_write(_ap_instance->dum,
                                         _ap_instance->flows[fd].api,
                                         DU_BUFF_HEADSPACE,
                                         DU_BUFF_TAILSPACE,
                                         (uint8_t *) buf,
                                         count);
                if (index == -1) {
                        pthread_rwlock_unlock(&_ap_instance->flows_lock);
                        pthread_rwlock_unlock(&_ap_instance->data_lock);
                        return -EAGAIN;
                }

                e.index   = index;
                e.port_id = _ap_instance->flows[fd].port_id;

                if (shm_ap_rbuff_write(_ap_instance->flows[fd].rb, &e) < 0) {
                        shm_du_map_remove(_ap_instance->dum, index);
                        pthread_rwlock_unlock(&_ap_instance->flows_lock);
                        pthread_rwlock_unlock(&_ap_instance->data_lock);
                        return -1;
                }
        } else { /* blocking */
                while ((index = shm_du_map_write(_ap_instance->dum,
                                                 _ap_instance->flows[fd].api,
                                                 DU_BUFF_HEADSPACE,
                                                 DU_BUFF_TAILSPACE,
                                                 (uint8_t *) buf,
                                                 count)) < 0)
                        ;

                e.index   = index;
                e.port_id = _ap_instance->flows[fd].port_id;

                while (shm_ap_rbuff_write(_ap_instance->flows[fd].rb, &e) < 0)
                        ;
        }

        pthread_rwlock_unlock(&_ap_instance->flows_lock);
        pthread_rwlock_unlock(&_ap_instance->data_lock);

        return 0;
}

ssize_t flow_read(int fd, void * buf, size_t count)
{
        int idx = -1;
        int n;
        uint8_t * sdu;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_rdlock(&_ap_instance->data_lock);
        pthread_rwlock_rdlock(&_ap_instance->flows_lock);

        if (_ap_instance->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&_ap_instance->flows_lock);
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return -ENOTALLOC;
        }

        if (_ap_instance->flows[fd].oflags & FLOW_O_NONBLOCK) {
                idx = shm_ap_rbuff_read_port(_ap_instance->rb,
                                             _ap_instance->flows[fd].port_id);
        } else { /* block */
                while ((idx =
                        shm_ap_rbuff_read_port(_ap_instance->rb,
                                               _ap_instance->
                                               flows[fd].port_id)) < 0)
                        ;
        }

        pthread_rwlock_unlock(&_ap_instance->flows_lock);

        if (idx < 0) {
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return -EAGAIN;
        }

        n = shm_du_map_read(&sdu, _ap_instance->dum, idx);
        if (n < 0) {
                pthread_rwlock_unlock(&_ap_instance->data_lock);
                return -1;
        }

        memcpy(buf, sdu, MIN(n, count));

        shm_du_map_remove(_ap_instance->dum, idx);

        pthread_rwlock_unlock(&_ap_instance->data_lock);

        return n;
}
