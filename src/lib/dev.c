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
#include <ouroboros/logs.h>
#include <ouroboros/dev.h>
#include <ouroboros/sockets.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/instance_name.h>
#include <ouroboros/shm_du_map.h>
#include <ouroboros/shm_ap_rbuff.h>
#include <ouroboros/utils.h>
#include <ouroboros/rw_lock.h>

#include <stdlib.h>
#include <string.h>

struct flow {
        struct shm_ap_rbuff * rb;
        int                   port_id;
        int                   oflags;

        /* don't think this needs locking */
};

struct ap_data {
        instance_name_t *     api;
        struct shm_du_map *   dum;
        struct bmp *          fds;
        struct shm_ap_rbuff * rb;
        rw_lock_t             data_lock;

        struct flow           flows[AP_MAX_FLOWS];
        rw_lock_t             flows_lock;
} * _ap_instance;

int ap_init(char * ap_name)
{
        int i = 0;
        _ap_instance = malloc(sizeof(struct ap_data));
        if (_ap_instance == NULL) {
                return -1;
        }

        _ap_instance->api = instance_name_create();
        if (_ap_instance->api == NULL) {
                free(_ap_instance);
                return -1;
        }

        if (instance_name_init_from(_ap_instance->api,
                                    ap_name,
                                    getpid()) == NULL) {
                instance_name_destroy(_ap_instance->api);
                free(_ap_instance);
                return -1;
        }

        _ap_instance->fds = bmp_create(AP_MAX_FLOWS, 0);
        if (_ap_instance->fds == NULL) {
                instance_name_destroy(_ap_instance->api);
                free(_ap_instance);
                return -1;
        }

        _ap_instance->dum = shm_du_map_open();
        if (_ap_instance->dum == NULL) {
                instance_name_destroy(_ap_instance->api);
                bmp_destroy(_ap_instance->fds);
                free(_ap_instance);
                return -1;
        }

        _ap_instance->rb = shm_ap_rbuff_create();
        if (_ap_instance->rb == NULL) {
                instance_name_destroy(_ap_instance->api);
                shm_du_map_close(_ap_instance->dum);
                bmp_destroy(_ap_instance->fds);
                free(_ap_instance);
                return -1;
        }

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                _ap_instance->flows[i].rb = NULL;
                _ap_instance->flows[i].port_id = -1;
        }

        rw_lock_init(&_ap_instance->flows_lock);
        rw_lock_init(&_ap_instance->data_lock);

        return 0;
}

void ap_fini(void)
{
        int i = 0;

        if (_ap_instance == NULL)
                return;

        rw_lock_wrlock(&_ap_instance->data_lock);

        if (_ap_instance->api != NULL)
                instance_name_destroy(_ap_instance->api);
        if (_ap_instance->fds != NULL)
                bmp_destroy(_ap_instance->fds);
        if (_ap_instance->dum != NULL)
                shm_du_map_close(_ap_instance->dum);
        if (_ap_instance->rb != NULL)
                shm_ap_rbuff_destroy(_ap_instance->rb);
        for (i = 0; i < AP_MAX_FLOWS; ++i)
                if (_ap_instance->flows[i].rb != NULL)
                        shm_ap_rbuff_close(_ap_instance->flows[i].rb);

        rw_lock_unlock(&_ap_instance->data_lock);

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

int ap_reg(char ** difs,
           size_t  len)
{
        irm_msg_t msg        = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int fd = -1;

        if (difs == NULL ||
            len == 0 ||
            difs[0] == NULL) {
                return -EINVAL;
        }

        if (_ap_instance == NULL)
                return -1; /* -ENOTINIT */

        msg.code       = IRM_MSG_CODE__IRM_AP_REG;
        msg.has_pid    = true;
        msg.dif_name   = difs;
        msg.n_dif_name = len;

        rw_lock_rdlock(&_ap_instance->data_lock);

        msg.pid        = _ap_instance->api->id;
        msg.ap_name    = _ap_instance->api->name;

        rw_lock_unlock(&_ap_instance->data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        if (recv_msg->result < 0)
                fd = -1;

        irm_msg__free_unpacked(recv_msg, NULL);

        rw_lock_wrlock(&_ap_instance->data_lock);

        fd = bmp_allocate(_ap_instance->fds);

        rw_lock_unlock(&_ap_instance->data_lock);

        return fd;
}

int ap_unreg(char ** difs,
             size_t  len)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (difs == NULL ||
            len == 0 ||
            difs[0] == NULL) {
                return -EINVAL;
        }

        msg.code       = IRM_MSG_CODE__IRM_AP_UNREG;
        msg.has_pid    = true;
        msg.dif_name   = difs;
        msg.n_dif_name = len;

        rw_lock_rdlock(&_ap_instance->data_lock);

        msg.pid        = _ap_instance->api->id;
        msg.ap_name    = _ap_instance->api->name;

        rw_lock_unlock(&_ap_instance->data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int flow_accept(int     fd,
                char ** ap_name,
                char ** ae_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int cfd = -1;

        msg.code    = IRM_MSG_CODE__IRM_FLOW_ACCEPT;
        msg.has_pid = true;

        rw_lock_rdlock(&_ap_instance->data_lock);

        msg.pid     = _ap_instance->api->id;

        rw_lock_unlock(&_ap_instance->data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_pid || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        if (ap_name != NULL) {
                *ap_name = strdup(recv_msg->ap_name);
                if (*ap_name == NULL) {
                        irm_msg__free_unpacked(recv_msg, NULL);
                        return -1;
                }
        }


        if (ae_name != NULL) {
                *ae_name = strdup(recv_msg->ae_name);
                if (*ae_name == NULL) {
                        irm_msg__free_unpacked(recv_msg, NULL);
                        return -1;
                }
        }

        rw_lock_wrlock(&_ap_instance->data_lock);

        cfd = bmp_allocate(_ap_instance->fds);

        rw_lock_unlock(&_ap_instance->data_lock);

        rw_lock_wrlock(&_ap_instance->flows_lock);

        _ap_instance->flows[cfd].rb = shm_ap_rbuff_open(recv_msg->pid);
        if (_ap_instance->flows[cfd].rb == NULL) {
                rw_lock_wrlock(&_ap_instance->data_lock);

                bmp_release(_ap_instance->fds, cfd);

                rw_lock_unlock(&_ap_instance->data_lock);

                irm_msg__free_unpacked(recv_msg, NULL);

                rw_lock_unlock(&_ap_instance->flows_lock);
                return -1;
        }

        _ap_instance->flows[cfd].port_id = recv_msg->port_id;
        _ap_instance->flows[cfd].oflags  = FLOW_O_DEFAULT;

        rw_lock_unlock(&_ap_instance->flows_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        rw_lock_wrlock(&_ap_instance->data_lock);

        bmp_release(_ap_instance->fds, fd);

        rw_lock_unlock(&_ap_instance->data_lock);

        return cfd;
}

int flow_alloc_resp(int fd,
                    int response)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code         = IRM_MSG_CODE__IRM_FLOW_ALLOC_RESP;
        msg.has_pid      = true;

        rw_lock_rdlock(&_ap_instance->data_lock);

        msg.pid          = _ap_instance->api->id;

        rw_lock_unlock(&_ap_instance->data_lock);

        msg.has_port_id  = true;

        rw_lock_rdlock(&_ap_instance->flows_lock);

        msg.port_id      = _ap_instance->flows[fd].port_id;

        rw_lock_unlock(&_ap_instance->flows_lock);

        msg.has_response = true;
        msg.response     = response;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
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
        msg.has_pid     = true;

        rw_lock_rdlock(&_ap_instance->data_lock);

        msg.pid         = _ap_instance->api->id;
        msg.ap_name     = _ap_instance->api->name;

        rw_lock_unlock(&_ap_instance->data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_pid || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        rw_lock_wrlock(&_ap_instance->data_lock);

        fd = bmp_allocate(_ap_instance->fds);

        rw_lock_unlock(&_ap_instance->data_lock);

        rw_lock_wrlock(&_ap_instance->flows_lock);

        _ap_instance->flows[fd].rb = shm_ap_rbuff_open(recv_msg->pid);
        if (_ap_instance->flows[fd].rb == NULL) {
                rw_lock_wrlock(&_ap_instance->data_lock);

                bmp_release(_ap_instance->fds, fd);

                rw_lock_unlock(&_ap_instance->data_lock);

                rw_lock_unlock(&_ap_instance->flows_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        _ap_instance->flows[fd].port_id = recv_msg->port_id;
        _ap_instance->flows[fd].oflags  = FLOW_O_DEFAULT;

        rw_lock_unlock(&_ap_instance->flows_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;
}

int flow_alloc_res(int fd)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int result = 0;

        msg.code          = IRM_MSG_CODE__IRM_FLOW_ALLOC_RES;
        msg.has_port_id  = true;

        rw_lock_rdlock(&_ap_instance->flows_lock);

        msg.port_id      = _ap_instance->flows[fd].port_id;

        rw_lock_unlock(&_ap_instance->flows_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

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

        rw_lock_wrlock(&_ap_instance->flows_lock);

        msg.port_id      = _ap_instance->flows[fd].port_id;

        _ap_instance->flows[fd].port_id = -1;
        shm_ap_rbuff_close(_ap_instance->flows[fd].rb);
        _ap_instance->flows[fd].rb = NULL;

        rw_lock_wrlock(&_ap_instance->data_lock);

        bmp_release(_ap_instance->fds, fd);

        rw_lock_unlock(&_ap_instance->data_lock);

        rw_lock_unlock(&_ap_instance->flows_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int flow_cntl(int fd, int cmd, int oflags)
{
        int old;

        rw_lock_wrlock(&_ap_instance->flows_lock);

        old = _ap_instance->flows[fd].oflags;

        switch (cmd) {
        case FLOW_F_GETFL: /* GET FLOW FLAGS */
                rw_lock_unlock(&_ap_instance->flows_lock);
                return old;
        case FLOW_F_SETFL: /* SET FLOW FLAGS */
                _ap_instance->flows[fd].oflags = oflags;
                rw_lock_unlock(&_ap_instance->flows_lock);
                return old;
        default:
                rw_lock_unlock(&_ap_instance->flows_lock);
                return FLOW_O_INVALID; /* unknown command */
        }
}

ssize_t flow_write(int fd, void * buf, size_t count)
{
        size_t index;
        struct rb_entry e;

        if (buf == NULL)
                return 0;

        rw_lock_rdlock(&_ap_instance->data_lock);

        index = shm_create_du_buff(_ap_instance->dum,
                                   count + DU_BUFF_HEADSPACE +
                                   DU_BUFF_TAILSPACE,
                                   DU_BUFF_HEADSPACE,
                                   (uint8_t *) buf,
                                   count);
        if (index == -1) {
                rw_lock_unlock(&_ap_instance->data_lock);
                return -1;
        }

        rw_lock_rdlock(&_ap_instance->flows_lock);

        e.index   = index;
        e.port_id = _ap_instance->flows[fd].port_id;

        if (_ap_instance->flows[fd].oflags & FLOW_O_NONBLOCK) {
                if (shm_ap_rbuff_write(_ap_instance->flows[fd].rb, &e) < 0) {
                        shm_release_du_buff(_ap_instance->dum, index);

                        rw_lock_unlock(&_ap_instance->flows_lock);

                        rw_lock_unlock(&_ap_instance->data_lock);

                        return -EPIPE;
                }

                rw_lock_unlock(&_ap_instance->flows_lock);

                rw_lock_unlock(&_ap_instance->data_lock);

                return 0;
        } else {
                while (shm_ap_rbuff_write(_ap_instance->flows[fd].rb, &e) < 0)
                        ;
        }

        rw_lock_unlock(&_ap_instance->data_lock);

        rw_lock_unlock(&_ap_instance->flows_lock);

        return 0;
}

ssize_t flow_read(int fd, void * buf, size_t count)
{
        struct rb_entry * e = NULL;
        int n;
        uint8_t * sdu;

        rw_lock_rdlock(&_ap_instance->data_lock);

        rw_lock_rdlock(&_ap_instance->flows_lock);

        if (_ap_instance->flows[fd].oflags & FLOW_O_NONBLOCK) {
                e = shm_ap_rbuff_read(_ap_instance->rb);
        } else {

                /* FIXME: this will throw away packets for other fd's */
                while (e == NULL ||
                       e->port_id != _ap_instance->flows[fd].port_id) {
                        e = shm_ap_rbuff_read(_ap_instance->rb);
                }
        }

        rw_lock_unlock(&_ap_instance->flows_lock);

        if (e == NULL) {
                rw_lock_unlock(&_ap_instance->data_lock);
                return -1;
        }

        n = shm_du_map_read_sdu(&sdu,
                                _ap_instance->dum,
                                e->index);
        if (n < 0) {
                rw_lock_unlock(&_ap_instance->data_lock);
                return -1;
        }

        memcpy(buf, sdu, MIN(n, count));

        shm_release_du_buff(_ap_instance->dum, e->index);

        rw_lock_unlock(&_ap_instance->data_lock);

        return n;
}
