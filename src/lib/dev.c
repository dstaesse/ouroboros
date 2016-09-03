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

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/sockets.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/shm_rdrbuff.h>
#include <ouroboros/shm_ap_rbuff.h>
#include <ouroboros/utils.h>

#include <stdlib.h>
#include <string.h>

struct flow {
        struct shm_ap_rbuff * rb;
        int                   port_id;
        int                   oflags;

        pid_t                 api;

        struct timespec *     timeout;
};

struct ap_instance {
        char *                ap_name;
        char *                daf_name;
        pid_t                 api;

        struct shm_rdrbuff *  rdrb;
        struct bmp *          fds;
        struct shm_ap_rbuff * rb;
        pthread_rwlock_t      data_lock;

        struct flow           flows[AP_MAX_FLOWS];
        int                   ports[AP_MAX_FLOWS];

        pthread_rwlock_t      flows_lock;
} * ai;

static int api_announce(char * ap_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code    = IRM_MSG_CODE__IRM_API_ANNOUNCE;
        msg.has_api = true;

        pthread_rwlock_rdlock(&ai->data_lock);

        msg.api = ai->api;
        msg.ap_name = ap_name;

        pthread_rwlock_unlock(&ai->data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (!recv_msg->has_result || (ret = recv_msg->result)) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return ret;
        }

        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int ap_init(char * ap_name)
{
        int i = 0;

        ap_name = path_strip(ap_name);

        ai = malloc(sizeof(*ai));
        if (ai == NULL) {
                return -ENOMEM;
        }

        ai->api = getpid();
        ai->ap_name = ap_name;
        ai->daf_name = NULL;

        ai->fds = bmp_create(AP_MAX_FLOWS, 0);
        if (ai->fds == NULL) {
                free(ai);
                return -ENOMEM;
        }

        ai->rdrb = shm_rdrbuff_open();
        if (ai->rdrb == NULL) {
                bmp_destroy(ai->fds);
                free(ai);
                return -1;
        }

        ai->rb = shm_ap_rbuff_create_s();
        if (ai->rb == NULL) {
                shm_rdrbuff_close(ai->rdrb);
                bmp_destroy(ai->fds);
                free(ai);
                return -1;
        }

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                ai->flows[i].rb = NULL;
                ai->flows[i].port_id = -1;
                ai->flows[i].oflags = 0;
                ai->flows[i].api = -1;
                ai->flows[i].timeout = NULL;
                ai->ports[i] = -1;
        }

        pthread_rwlock_init(&ai->flows_lock, NULL);
        pthread_rwlock_init(&ai->data_lock, NULL);

        if (ap_name != NULL)
                return api_announce(ap_name);

        return 0;
}

void ap_fini(void)
{
        int i = 0;

        if (ai == NULL)
                return;

        pthread_rwlock_wrlock(&ai->data_lock);

        /* remove all remaining sdus */
        while ((i = shm_ap_rbuff_peek_idx(ai->rb)) >= 0)
                shm_rdrbuff_remove(ai->rdrb, i);

        if (ai->fds != NULL)
                bmp_destroy(ai->fds);
        if (ai->rb != NULL)
                shm_ap_rbuff_destroy(ai->rb);
        if (ai->rdrb != NULL)
                shm_rdrbuff_close(ai->rdrb);

        if (ai->daf_name != NULL)
                free(ai->daf_name);

        pthread_rwlock_rdlock(&ai->flows_lock);

        for (i = 0; i < AP_MAX_FLOWS; ++i) {
                if (ai->flows[i].rb != NULL)
                        shm_ap_rbuff_close(ai->flows[i].rb);
                ai->ports[ai->flows[i].port_id] = -1;
        }

        pthread_rwlock_unlock(&ai->flows_lock);
        pthread_rwlock_unlock(&ai->data_lock);

        pthread_rwlock_destroy(&ai->flows_lock);
        pthread_rwlock_destroy(&ai->data_lock);

        free(ai);
}

int flow_accept(char ** ae_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int fd = -1;

        msg.code    = IRM_MSG_CODE__IRM_FLOW_ACCEPT;
        msg.has_api = true;

        pthread_rwlock_rdlock(&ai->data_lock);

        msg.api     = ai->api;

        pthread_rwlock_unlock(&ai->data_lock);

        recv_msg = send_recv_irm_msg_b(&msg);
        if (recv_msg == NULL)
                return -1;

        if (!recv_msg->has_api || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        pthread_rwlock_rdlock(&ai->data_lock);
        pthread_rwlock_wrlock(&ai->flows_lock);

        fd = bmp_allocate(ai->fds);
        if (!bmp_is_id_valid(ai->fds, fd)) {
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ai->flows[fd].rb = shm_ap_rbuff_open_n(recv_msg->api);
        if (ai->flows[fd].rb == NULL) {
                bmp_release(ai->fds, fd);
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        if (ae_name != NULL) {
                *ae_name = strdup(recv_msg->ae_name);
                if (*ae_name == NULL) {
                        shm_ap_rbuff_close(ai->flows[fd].rb);
                        bmp_release(ai->fds, fd);
                        pthread_rwlock_unlock(&ai->flows_lock);
                        pthread_rwlock_unlock(&ai->data_lock);
                        irm_msg__free_unpacked(recv_msg, NULL);
                        return -ENOMEM;
                }
        }

        ai->flows[fd].port_id = recv_msg->port_id;
        ai->flows[fd].oflags  = FLOW_O_DEFAULT;
        ai->flows[fd].api     = recv_msg->api;

        ai->ports[recv_msg->port_id] = fd;

        pthread_rwlock_unlock(&ai->flows_lock);
        pthread_rwlock_unlock(&ai->data_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        return fd;
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
        msg.api          = ai->api;
        msg.has_port_id  = true;

        pthread_rwlock_rdlock(&ai->data_lock);
        pthread_rwlock_rdlock(&ai->flows_lock);

        if (ai->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                return -ENOTALLOC;
        }

        msg.port_id      = ai->flows[fd].port_id;

        pthread_rwlock_unlock(&ai->flows_lock);

        msg.has_response = true;
        msg.response     = response;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                pthread_rwlock_unlock(&ai->data_lock);
                return -1;
        }

        if (!recv_msg->has_result) {
                pthread_rwlock_unlock(&ai->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;

        pthread_rwlock_unlock(&ai->data_lock);

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

        pthread_rwlock_rdlock(&ai->data_lock);

        msg.api         = ai->api;

        pthread_rwlock_unlock(&ai->data_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (!recv_msg->has_api || !recv_msg->has_port_id) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        pthread_rwlock_rdlock(&ai->data_lock);
        pthread_rwlock_wrlock(&ai->flows_lock);

        fd = bmp_allocate(ai->fds);
        if (!bmp_is_id_valid(ai->fds, fd)) {
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ai->flows[fd].rb = shm_ap_rbuff_open_n(recv_msg->api);
        if (ai->flows[fd].rb == NULL) {
                bmp_release(ai->fds, fd);
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ai->flows[fd].port_id = recv_msg->port_id;
        ai->flows[fd].oflags  = FLOW_O_DEFAULT;
        ai->flows[fd].api     = recv_msg->api;

        ai->ports[recv_msg->port_id] = fd;

        pthread_rwlock_unlock(&ai->flows_lock);
        pthread_rwlock_unlock(&ai->data_lock);

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

        pthread_rwlock_rdlock(&ai->data_lock);
        pthread_rwlock_rdlock(&ai->flows_lock);

        if (ai->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                return -ENOTALLOC;
        }

        msg.port_id = ai->flows[fd].port_id;

        pthread_rwlock_unlock(&ai->flows_lock);
        pthread_rwlock_unlock(&ai->data_lock);

        recv_msg = send_recv_irm_msg_b(&msg);
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
        msg.has_api      = true;
        msg.api          = getpid();

        pthread_rwlock_rdlock(&ai->data_lock);
        pthread_rwlock_wrlock(&ai->flows_lock);

        if (ai->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                return -ENOTALLOC;
        }

        msg.port_id = ai->flows[fd].port_id;

        ai->ports[msg.port_id] = -1;

        ai->flows[fd].port_id = -1;
        shm_ap_rbuff_close(ai->flows[fd].rb);
        ai->flows[fd].rb = NULL;
        ai->flows[fd].api = -1;

        bmp_release(ai->fds, fd);

        pthread_rwlock_unlock(&ai->flows_lock);

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                pthread_rwlock_unlock(&ai->data_lock);
                return -1;
        }

        if (!recv_msg->has_result) {
                pthread_rwlock_unlock(&ai->data_lock);
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;

        pthread_rwlock_unlock(&ai->data_lock);

        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int flow_cntl(int fd, int cmd, int oflags)
{
        int old;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_rdlock(&ai->data_lock);
        pthread_rwlock_wrlock(&ai->flows_lock);

        if (ai->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                return -ENOTALLOC;
        }

        old = ai->flows[fd].oflags;

        switch (cmd) {
        case FLOW_F_GETFL: /* GET FLOW FLAGS */
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                return old;
        case FLOW_F_SETFL: /* SET FLOW FLAGS */
                ai->flows[fd].oflags = oflags;
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                return old;
        default:
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                return FLOW_O_INVALID; /* unknown command */
        }
}

ssize_t flow_write(int fd, void * buf, size_t count)
{
        ssize_t idx;
        struct rb_entry e;

        if (buf == NULL)
                return 0;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_rdlock(&ai->data_lock);
        pthread_rwlock_rdlock(&ai->flows_lock);

        if (ai->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                return -ENOTALLOC;
        }

        if (ai->flows[fd].oflags & FLOW_O_NONBLOCK) {
                idx = shm_rdrbuff_write(ai->rdrb,
                                       ai->flows[fd].api,
                                       DU_BUFF_HEADSPACE,
                                       DU_BUFF_TAILSPACE,
                                       (uint8_t *) buf,
                                       count);
                if (idx == -1) {
                        pthread_rwlock_unlock(&ai->flows_lock);
                        pthread_rwlock_unlock(&ai->data_lock);
                        return -EAGAIN;
                }

                e.index   = idx;
                e.port_id = ai->flows[fd].port_id;

                if (shm_ap_rbuff_write(ai->flows[fd].rb, &e) < 0) {
                        shm_rdrbuff_remove(ai->rdrb, idx);
                        pthread_rwlock_unlock(&ai->flows_lock);
                        pthread_rwlock_unlock(&ai->data_lock);
                        return -1;
                }
        } else { /* blocking */
                struct shm_rdrbuff * rdrb = ai->rdrb;
                pid_t                api = ai->flows[fd].api;
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);

                idx = shm_rdrbuff_write_b(rdrb,
                                         api,
                                         DU_BUFF_HEADSPACE,
                                         DU_BUFF_TAILSPACE,
                                         (uint8_t *) buf,
                                         count);

                pthread_rwlock_rdlock(&ai->data_lock);
                pthread_rwlock_rdlock(&ai->flows_lock);

                e.index   = idx;
                e.port_id = ai->flows[fd].port_id;

                while (shm_ap_rbuff_write(ai->flows[fd].rb, &e) < 0)
                        ;
        }

        pthread_rwlock_unlock(&ai->flows_lock);
        pthread_rwlock_unlock(&ai->data_lock);

        return 0;
}

int flow_select(const struct timespec * timeout)
{
        int port_id = shm_ap_rbuff_peek_b(ai->rb, timeout);
        if (port_id < 0)
                return port_id;
        return ai->ports[port_id];
}

ssize_t flow_read(int fd, void * buf, size_t count)
{
        int idx = -1;
        int n;
        uint8_t * sdu;

        if (fd < 0 || fd >= AP_MAX_FLOWS)
                return -EBADF;

        pthread_rwlock_rdlock(&ai->data_lock);
        pthread_rwlock_rdlock(&ai->flows_lock);

        if (ai->flows[fd].port_id < 0) {
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);
                return -ENOTALLOC;
        }

        if (ai->flows[fd].oflags & FLOW_O_NONBLOCK) {
                idx = shm_ap_rbuff_read_port(ai->rb,
                                             ai->flows[fd].port_id);
                pthread_rwlock_unlock(&ai->flows_lock);
        } else {
                struct shm_ap_rbuff * rb      = ai->rb;
                int                   port_id = ai->flows[fd].port_id;
                struct timespec *     timeout = ai->flows[fd].timeout;
                pthread_rwlock_unlock(&ai->flows_lock);
                pthread_rwlock_unlock(&ai->data_lock);

                idx = shm_ap_rbuff_read_port_b(rb, port_id, timeout);

                pthread_rwlock_rdlock(&ai->data_lock);
        }

        if (idx < 0) {
                pthread_rwlock_unlock(&ai->data_lock);
                return -EAGAIN;
        }

        n = shm_rdrbuff_read(&sdu, ai->rdrb, idx);
        if (n < 0) {
                pthread_rwlock_unlock(&ai->data_lock);
                return -1;
        }

        memcpy(buf, sdu, MIN(n, count));

        shm_rdrbuff_remove(ai->rdrb, idx);

        pthread_rwlock_unlock(&ai->data_lock);

        return n;
}
