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
#include <ouroboros/bitmap.h>
#include <ouroboros/instance_name.h>
#include <ouroboros/shm_du_map.h>
#include <ouroboros/shm_ap_rbuff.h>
#include <ouroboros/utils.h>

#include <stdlib.h>
#include <string.h>

#define AP_MAX_FLOWS 256

#ifndef DU_BUFF_HEADSPACE
  #define DU_BUFF_HEADSPACE 128
#endif

#ifndef DU_BUFF_TAILSPACE
  #define DU_BUFF_TAILSPACE 0
#endif

struct flow {
        struct shm_ap_rbuff * rb;
        uint32_t              port_id;
        uint32_t              oflags;

        /* don't think this needs locking */
};

struct ap_data {
        instance_name_t *     api;
        struct shm_du_map *   dum;
        struct bmp *          fds;

        struct shm_ap_rbuff * rb;
        struct flow           flows[AP_MAX_FLOWS];
} * _ap_instance;


int ap_init(char * ap_name)
{
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
                bmp_destroy(_ap_instance->fds);
                free(_ap_instance);
                return -1;
        }

        return 0;
}

void ap_fini()
{
        int i = 0;

        if (_ap_instance == NULL)
                return;
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

        free(_ap_instance);
}

#if 0
static int port_id_to_fd(uint32_t port_id)
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
        int fd = bmp_allocate(_ap_instance->fds);

        if (difs == NULL ||
            len == 0 ||
            difs[0] == NULL) {
                return -EINVAL;
        }

        if (_ap_instance == NULL) {
                LOG_DBG("ap_init was not called");
                return -1;
        }

        msg.code       = IRM_MSG_CODE__IRM_AP_REG;
        msg.has_pid    = true;
        msg.pid        = _ap_instance->api->id;
        msg.ap_name    = _ap_instance->api->name;
        msg.dif_name   = difs;
        msg.n_dif_name = len;

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
        msg.pid        = _ap_instance->api->id;
        msg.ap_name    = _ap_instance->api->name;
        msg.dif_name   = difs;
        msg.n_dif_name = len;

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
        msg.pid     = _ap_instance->api->id;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_pid || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        cfd = bmp_allocate(_ap_instance->fds);

        _ap_instance->flows[cfd].rb = shm_ap_rbuff_open(recv_msg->pid);
        if (_ap_instance->flows[cfd].rb == NULL) {
                bmp_release(_ap_instance->fds, cfd);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        _ap_instance->flows[cfd].port_id = recv_msg->port_id;
        _ap_instance->flows[cfd].oflags  = FLOW_O_DEFAULT;

        *ap_name = strdup(recv_msg->ap_name);
        if (ae_name != NULL)
                *ae_name = strdup(recv_msg->ae_name);

        irm_msg__free_unpacked(recv_msg, NULL);

        bmp_release(_ap_instance->fds, fd);

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
        msg.pid          = _ap_instance->api->id;
        msg.has_port_id  = true;
        msg.port_id      = _ap_instance->flows[fd].port_id;
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
        msg.ap_name     = _ap_instance->api->name;
        msg.has_pid     = true;
        msg.pid         = _ap_instance->api->id;
        msg.ae_name     = src_ae_name;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_pid || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        fd = bmp_allocate(_ap_instance->fds);

        _ap_instance->flows[fd].rb = shm_ap_rbuff_open(recv_msg->pid);
        if (_ap_instance->flows[fd].rb == NULL) {
                bmp_release(_ap_instance->fds, fd);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        _ap_instance->flows[fd].port_id = recv_msg->port_id;
        _ap_instance->flows[fd].oflags  = FLOW_O_DEFAULT;

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
        msg.port_id      = _ap_instance->flows[fd].port_id;

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
        msg.port_id      = _ap_instance->flows[fd].port_id;

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
        return -1;
}

ssize_t flow_write(int fd, void * buf, size_t count)
{
        /* the AP chooses the amount of headspace and tailspace */
        size_t index = shm_create_du_buff(_ap_instance->dum,
                                          count + DU_BUFF_HEADSPACE +
                                          DU_BUFF_TAILSPACE,
                                          DU_BUFF_HEADSPACE,
                                          (uint8_t *) buf,
                                          count);
        struct rb_entry e = {index, _ap_instance->flows[fd].port_id};
        if (index == -1)
                return -1;

        if (shm_ap_rbuff_write(_ap_instance->flows[fd].rb, &e) < 0) {
                shm_release_du_buff(_ap_instance->dum, index);
                return -EPIPE;
        }

        return 0;
}

ssize_t flow_read(int fd, void * buf, size_t count)
{
        struct rb_entry * e = NULL;
        int n;
        uint8_t * sdu;
        /* FIXME: move this to a thread  */
        while (e == NULL || e->port_id != _ap_instance->flows[fd].port_id)
                e = shm_ap_rbuff_read(_ap_instance->rb);

        n = shm_du_map_read_sdu(&sdu,
                                _ap_instance->dum,
                                e->index);
        if (n < 0)
                return -1;

        memcpy(buf, sdu, MIN(n, count));

        shm_release_du_buff(_ap_instance->dum, e->index);

        return n;
}
