/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * IPC process using the Raptor FPGA.
 *
 *    Alexander D'hoore <dhoore.alexander@gmail.com>
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define _DEFAULT_SOURCE

#define OUROBOROS_PREFIX "ipcpd/raptor"

#include <ouroboros/config.h>
#include <ouroboros/hash.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/dev.h>
#include <ouroboros/local-dev.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/logs.h>
#include <ouroboros/time_utils.h>

#include "ipcp.h"
#include "raptor_messages.pb-c.h"

#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <malloc.h>

#ifdef __linux__
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#endif

#include <poll.h>
#include <sys/mman.h>

typedef RaptorMsg raptor_msg_t;

#define THIS_TYPE IPCP_RAPTOR
#define MGMT_SAP 0x01
#define MAC_SIZE 6
#define MAX_SAPS 64

#define EVENT_WAIT_TIMEOUT 100 /* us */
#define NAME_QUERY_TIMEOUT 2000 /* ms */
#define MGMT_TIMEOUT 100 /* ms */

#define IOCTL_SEND 0xAD420000
#define IOCTL_RECV 0xAD430000
#define IOCTL_SEND_DONE 0xAD440000
#define IOCTL_RECV_DONE 0xAD450000
#define IOCTL_RECV_NEED 0xAD460000

#define RAPTOR_PAGE ((1 << 12) - 200) /* 4kB - 200 */

#define RAPTOR_PAGE_MASK (~0xFFF)

#define RAPTOR_BATCH 100

#define RAPTOR_HEADER 3

struct ef {
        int8_t  sap;
        int8_t  r_sap;
        uint8_t r_addr[MAC_SIZE];
};

struct mgmt_frame {
        struct list_head next;
        uint8_t          r_addr[MAC_SIZE];
        uint8_t          buf[RAPTOR_PAGE];
        size_t           len;
};

struct {
        int                ioctl_fd;

        struct bmp *       saps;
        flow_set_t *       np1_flows;
        fqueue_t *         fq;
        int *              ef_to_fd;
        struct ef *        fd_to_ef;
        pthread_rwlock_t   flows_lock;

        pthread_t          send_thread;
        pthread_t          recv_thread;
        pthread_t          send_done_thread;
        pthread_t          recv_done_thread;

        /* Handle mgmt frames in a different thread */
        pthread_t          mgmt_handler;
        pthread_mutex_t    mgmt_lock;
        pthread_cond_t     mgmt_cond;
        struct list_head   mgmt_frames;

} raptor_data;

static int raptor_data_init(void)
{
        int                i;
        int                ret = -1;
        pthread_condattr_t cattr;

        log_info("%s", __FUNCTION__);

        raptor_data.fd_to_ef = malloc(sizeof(struct ef) * IRMD_MAX_FLOWS);
        if (raptor_data.fd_to_ef == NULL)
                return -ENOMEM;

        raptor_data.ef_to_fd = malloc(sizeof(struct ef) * MAX_SAPS);
        if (raptor_data.ef_to_fd == NULL) {
                ret = -ENOMEM;
                goto free_fd_to_ef;
        }

        raptor_data.saps = bmp_create(MAX_SAPS, 2);
        if (raptor_data.saps == NULL) {
                ret = -ENOMEM;
                goto free_ef_to_fd;
        }

        raptor_data.np1_flows = flow_set_create();
        if (raptor_data.np1_flows == NULL) {
                ret = -ENOMEM;
                goto bmp_destroy;
        }

        raptor_data.fq = fqueue_create();
        if (raptor_data.fq == NULL) {
                ret = -ENOMEM;
                goto flow_set_destroy;
        }

        for (i = 0; i < MAX_SAPS; ++i)
                raptor_data.ef_to_fd[i] = -1;

        for (i = 0; i < IRMD_MAX_FLOWS; ++i) {
                raptor_data.fd_to_ef[i].sap   = -1;
                raptor_data.fd_to_ef[i].r_sap = -1;
                memset(&raptor_data.fd_to_ef[i].r_addr, 0, MAC_SIZE);
        }

        if (pthread_rwlock_init(&raptor_data.flows_lock, NULL))
                goto fqueue_destroy;

        if (pthread_mutex_init(&raptor_data.mgmt_lock, NULL))
                goto flow_lock_destroy;

        if (pthread_condattr_init(&cattr))
                goto mgmt_lock_destroy;;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif

        if (pthread_cond_init(&raptor_data.mgmt_cond, &cattr))
                goto mgmt_lock_destroy;

        list_head_init(&raptor_data.mgmt_frames);

        return 0;

 mgmt_lock_destroy:
        pthread_mutex_destroy(&raptor_data.mgmt_lock);
 flow_lock_destroy:
        pthread_rwlock_destroy(&raptor_data.flows_lock);
 fqueue_destroy:
        fqueue_destroy(raptor_data.fq);
 flow_set_destroy:
        flow_set_destroy(raptor_data.np1_flows);
 bmp_destroy:
        bmp_destroy(raptor_data.saps);
 free_ef_to_fd:
        free(raptor_data.ef_to_fd);
 free_fd_to_ef:
        free(raptor_data.fd_to_ef);

        return ret;
}

void raptor_data_fini(void)
{
        log_info("%s", __FUNCTION__);

        close(raptor_data.ioctl_fd);
        pthread_cond_destroy(&raptor_data.mgmt_cond);
        pthread_mutex_destroy(&raptor_data.mgmt_lock);
        pthread_rwlock_destroy(&raptor_data.flows_lock);
        fqueue_destroy(raptor_data.fq);
        flow_set_destroy(raptor_data.np1_flows);
        bmp_destroy(raptor_data.saps);
        free(raptor_data.fd_to_ef);
        free(raptor_data.ef_to_fd);
}

static int raptor_ipcp_send_frame(struct shm_du_buff * sdb,
                                  uint8_t              dsap)
{
        /* length (16b) + dsap (8b) */

        uint8_t * frame;
        size_t frame_len;
        uint8_t * payload;
        size_t len;

        payload = shm_du_buff_head(sdb);
        len = shm_du_buff_tail(sdb) - shm_du_buff_head(sdb);

        if (payload == NULL) {
                log_err("Payload was NULL.");
                return -1;
        }

        frame_len = RAPTOR_HEADER + len;

        if (frame_len >= RAPTOR_PAGE) {
                log_err("Payload too large.");
                return -1;
        }

        frame = memalign(1 << 12, 1 << 12);

        if (frame == NULL) {
                log_err("frame == NULL");
                return -1;
        }

        if ((uint64_t)frame & 0xFFF) {
                log_err("page offset not zero");
                return -1;
        }

        frame[0] = (frame_len & 0x00FF) >> 0;
        frame[1] = (frame_len & 0xFF00) >> 8;
        frame[2] = dsap;

        memcpy(&frame[RAPTOR_HEADER], payload, len);

        ipcp_sdb_release(sdb);

        if (ioctl(raptor_data.ioctl_fd, IOCTL_SEND | 1, &frame) != 1) {
                log_err("Ioctl send failed.");
                free(frame);
                return -1;
        }
        return 0;
}

static int raptor_ipcp_send_mgmt_frame(raptor_msg_t * msg,
                                        const uint8_t *      dst_addr)
{
        size_t    len;
        uint8_t * buf;
        struct shm_du_buff * sdb;

        (void)dst_addr;

        log_info("%s", __FUNCTION__);

        len = raptor_msg__get_packed_size(msg);
        if (len == 0)
                return -1;

        if (ipcp_sdb_reserve(&sdb, len) < 0) {
                log_err("failed to reserve sdb for management frame.");
                return -1;
        }

        buf = shm_du_buff_head(sdb);

        raptor_msg__pack(msg, buf);

        if (raptor_ipcp_send_frame(sdb, MGMT_SAP)) {
                log_err("Failed to send management frame.");
                return -1;
        }
        return 0;
}

static int raptor_ipcp_sap_alloc(const uint8_t * dst_addr,
                                  uint8_t         ssap,
                                  const uint8_t * hash,
                                  qoscube_t       cube)
{
        raptor_msg_t msg = RAPTOR_MSG__INIT;

        log_info("%s", __FUNCTION__);

        msg.code        = RAPTOR_MSG_CODE__FLOW_REQ;
        msg.has_ssap    = true;
        msg.ssap        = ssap;
        msg.has_hash    = true;
        msg.hash.len    = ipcp_dir_hash_len();
        msg.hash.data   = (uint8_t *) hash;
        msg.has_qoscube = true;
        msg.qoscube     = cube;

        return raptor_ipcp_send_mgmt_frame(&msg, dst_addr);
}

static int raptor_ipcp_sap_alloc_resp(uint8_t * dst_addr,
                                       uint8_t   ssap,
                                       uint8_t   dsap,
                                       int       response)
{
        raptor_msg_t msg = RAPTOR_MSG__INIT;

        log_info("%s", __FUNCTION__);

        msg.code         = RAPTOR_MSG_CODE__FLOW_REPLY;
        msg.has_ssap     = true;
        msg.ssap         = ssap;
        msg.has_dsap     = true;
        msg.dsap         = dsap;
        msg.has_response = true;
        msg.response     = response;

        return raptor_ipcp_send_mgmt_frame(&msg, dst_addr);
}

static int raptor_ipcp_sap_req(uint8_t         r_sap,
                                uint8_t *       r_addr,
                                const uint8_t * dst,
                                qoscube_t       cube)
{
        struct timespec ts = {0, EVENT_WAIT_TIMEOUT * 1000};
        struct timespec abstime;
        int             fd;

        log_info("%s", __FUNCTION__);

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        pthread_mutex_lock(&ipcpi.alloc_lock);

        while (ipcpi.alloc_id != -1 && ipcp_get_state() == IPCP_OPERATIONAL) {
                ts_add(&abstime, &ts, &abstime);
                pthread_cond_timedwait(&ipcpi.alloc_cond,
                                       &ipcpi.alloc_lock,
                                       &abstime);
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                log_dbg("Won't allocate over non-operational IPCP.");
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                return -1;
        }

        /* reply to IRM, called under lock to prevent race */
        fd = ipcp_flow_req_arr(getpid(), dst, ipcp_dir_hash_len(), cube);
        if (fd < 0) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                log_err("Could not get new flow from IRMd.");
                return -1;
        }

        pthread_rwlock_wrlock(&raptor_data.flows_lock);

        raptor_data.fd_to_ef[fd].r_sap = r_sap;
        memcpy(raptor_data.fd_to_ef[fd].r_addr, r_addr, MAC_SIZE);

        ipcpi.alloc_id = fd;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_rwlock_unlock(&raptor_data.flows_lock);
        pthread_mutex_unlock(&ipcpi.alloc_lock);

        log_dbg("New flow request, fd %d, remote SAP %d.", fd, r_sap);

        return 0;
}

static int raptor_ipcp_sap_alloc_reply(uint8_t   ssap,
                                        uint8_t * r_addr,
                                        int       dsap,
                                        int       response)
{
        int ret = 0;
        int fd = -1;

        log_info("%s", __FUNCTION__);

        pthread_rwlock_wrlock(&raptor_data.flows_lock);

        fd = raptor_data.ef_to_fd[dsap];
        if (fd < 0) {
                pthread_rwlock_unlock(& raptor_data.flows_lock);
                log_err("No flow found with that SAP.");
                return -1; /* -EFLOWNOTFOUND */
        }

        if (response) {
                bmp_release(raptor_data.saps, raptor_data.fd_to_ef[fd].sap);
        } else {
                raptor_data.fd_to_ef[fd].r_sap = ssap;
                memcpy(raptor_data.fd_to_ef[fd].r_addr, r_addr, MAC_SIZE);
        }

        pthread_rwlock_unlock(&raptor_data.flows_lock);

        log_dbg("Flow reply, fd %d, SSAP %d, DSAP %d.", fd, ssap, dsap);

        if ((ret = ipcp_flow_alloc_reply(fd, response)) < 0)
                return -1;

        return ret;

}

static int raptor_ipcp_name_query_req(const uint8_t * hash,
                                       uint8_t *       r_addr)
{
        raptor_msg_t msg = RAPTOR_MSG__INIT;

        log_info("%s", __FUNCTION__);

        if (shim_data_reg_has(ipcpi.shim_data, hash)) {
                msg.code      = RAPTOR_MSG_CODE__NAME_QUERY_REPLY;
                msg.has_hash  = true;
                msg.hash.len  = ipcp_dir_hash_len();
                msg.hash.data = (uint8_t *) hash;

                raptor_ipcp_send_mgmt_frame(&msg, r_addr);
        }

        return 0;
}

static int raptor_ipcp_name_query_reply(const uint8_t * hash,
                                         uint8_t *       r_addr)
{
        uint64_t           address = 0;
        struct list_head * pos;

        log_info("%s", __FUNCTION__);

        memcpy(&address, r_addr, MAC_SIZE);

        shim_data_dir_add_entry(ipcpi.shim_data, hash, address);

        pthread_mutex_lock(&ipcpi.shim_data->dir_queries_lock);
        list_for_each(pos, &ipcpi.shim_data->dir_queries) {
                struct dir_query * e =
                        list_entry(pos, struct dir_query, next);
                if (memcmp(e->hash, hash, ipcp_dir_hash_len()) == 0) {
                        shim_data_dir_query_respond(e);
                }
        }
        pthread_mutex_unlock(&ipcpi.shim_data->dir_queries_lock);

        return 0;
}

static int raptor_ipcp_mgmt_frame(const uint8_t * buf,
                                   size_t          len,
                                   uint8_t *       r_addr)
{
        raptor_msg_t * msg;

        log_info("%s", __FUNCTION__);

        msg = raptor_msg__unpack(NULL, len, buf);
        if (msg == NULL) {
                log_err("Failed to unpack.");
                return -1;
        }

        switch (msg->code) {
        case RAPTOR_MSG_CODE__FLOW_REQ:
                if (shim_data_reg_has(ipcpi.shim_data, msg->hash.data)) {
                        raptor_ipcp_sap_req(msg->ssap,
                                             r_addr,
                                             msg->hash.data,
                                             msg->qoscube);
                }
                break;
        case RAPTOR_MSG_CODE__FLOW_REPLY:
                raptor_ipcp_sap_alloc_reply(msg->ssap,
                                             r_addr,
                                             msg->dsap,
                                             msg->response);
                break;
        case RAPTOR_MSG_CODE__NAME_QUERY_REQ:
                raptor_ipcp_name_query_req(msg->hash.data, r_addr);
                break;
        case RAPTOR_MSG_CODE__NAME_QUERY_REPLY:
                raptor_ipcp_name_query_reply(msg->hash.data, r_addr);
                break;
        default:
                log_err("Unknown message received %d.", msg->code);
                raptor_msg__free_unpacked(msg, NULL);
                return -1;
        }

        raptor_msg__free_unpacked(msg, NULL);
        return 0;
}

static void * raptor_ipcp_mgmt_handler(void * o)
{
        int                 ret;
        struct timespec     timeout = {(MGMT_TIMEOUT / 1000),
                                       (MGMT_TIMEOUT % 1000) * MILLION};
        struct timespec     abstime;
        struct mgmt_frame * frame;

        (void) o;

        log_info("%s", __FUNCTION__);

        log_info("Mgmt handler started.");

        while (true) {
                ret = 0;

                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        break;

                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, &timeout, &abstime);

                pthread_mutex_lock(&raptor_data.mgmt_lock);

                while (list_is_empty(&raptor_data.mgmt_frames) &&
                       ret != -ETIMEDOUT)
                        ret = -pthread_cond_timedwait(&raptor_data.mgmt_cond,
                                                      &raptor_data.mgmt_lock,
                                                      &abstime);

                if (ret == -ETIMEDOUT) {
                        pthread_mutex_unlock(&raptor_data.mgmt_lock);
                        continue;
                }

                frame = list_first_entry((&raptor_data.mgmt_frames),
                                         struct mgmt_frame, next);
                if (frame == NULL) {
                        pthread_mutex_unlock(&raptor_data.mgmt_lock);
                        continue;
                }

                list_del(&frame->next);
                pthread_mutex_unlock(&raptor_data.mgmt_lock);

                raptor_ipcp_mgmt_frame(frame->buf, frame->len, frame->r_addr);
                free(frame);
        }

        log_info("Mgmt handler stopped.");
        return NULL;
}

static void raptor_ipcp_recv_frame(uint8_t* frame)
{
        uint8_t dsap;
        uint8_t* payload;
        size_t frame_len;
        size_t length;
        int fd;
        struct mgmt_frame * mgmt_frame;
        struct shm_du_buff * sdb;
        size_t idx;

        sdb = (struct shm_du_buff*)((uint64_t)frame & RAPTOR_PAGE_MASK);
        idx = shm_du_buff_get_idx(sdb);

        frame_len = frame[0] | (frame[1] << 8);

        if (frame_len < RAPTOR_HEADER) {
                log_err("Received packet smaller than header alone.");
                ipcp_sdb_release(sdb);
                return;
        }
        if (frame_len >= RAPTOR_PAGE) {
                log_err("Received packet too large.");
                ipcp_sdb_release(sdb);
                return;
        }

        dsap = frame[2];
        payload = &frame[RAPTOR_HEADER];
        length = frame_len - RAPTOR_HEADER;

        shm_du_buff_head_release(sdb, RAPTOR_HEADER);
        shm_du_buff_tail_release(sdb, RAPTOR_PAGE - frame_len);

        if (dsap == MGMT_SAP) {
                pthread_mutex_lock(&raptor_data.mgmt_lock);

                mgmt_frame = malloc(sizeof(*mgmt_frame));
                if (mgmt_frame == NULL) {
                        pthread_mutex_unlock(&raptor_data.mgmt_lock);
                        ipcp_sdb_release(sdb);
                        return;
                }

                memcpy(mgmt_frame->buf, payload, length);
                memset(mgmt_frame->r_addr, 0, MAC_SIZE);
                mgmt_frame->len = length;
                list_add(&mgmt_frame->next, &raptor_data.mgmt_frames);
                pthread_cond_signal(&raptor_data.mgmt_cond);
                pthread_mutex_unlock(&raptor_data.mgmt_lock);

                ipcp_sdb_release(sdb);
        } else {
                pthread_rwlock_rdlock(&raptor_data.flows_lock);

                fd = raptor_data.ef_to_fd[dsap];
                if (fd < 0) {
                        pthread_rwlock_unlock(&raptor_data.flows_lock);
                        ipcp_sdb_release(sdb);
                        return;
                }

                pthread_rwlock_unlock(&raptor_data.flows_lock);

                local_flow_write(fd, idx);
        }
}

static void * raptor_ipcp_recv_done_thread(void * o)
{
        uint8_t * frames[RAPTOR_BATCH];
        int count;
        int i;

        (void)o;

        log_info("Recv_done thread started.");

        while (true) {
                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        break;

                count = ioctl(raptor_data.ioctl_fd, IOCTL_RECV_DONE | RAPTOR_BATCH, frames);

                if (count <= 0)
                        continue;

                for (i = 0; i < count; i++)
                        raptor_ipcp_recv_frame(frames[i]);
        }

        log_info("Recv_done thread stopped.");
        return NULL;
}

static void * raptor_ipcp_send_thread(void * o)
{
        struct timespec      timeout = {0, EVENT_WAIT_TIMEOUT * 1000};
        int                  fd;
        struct shm_du_buff * sdb;
        uint8_t              dsap;

        (void) o;

        log_info("Send thread started.");

        while (flow_event_wait(raptor_data.np1_flows,
                               raptor_data.fq,
                               &timeout)) {

                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        break;

                pthread_rwlock_rdlock(&raptor_data.flows_lock);
                while ((fd = fqueue_next(raptor_data.fq)) >= 0) {
                        if (ipcp_flow_read(fd, &sdb)) {
                                log_err("Bad read from fd %d.", fd);
                                continue;
                        }

                        dsap = raptor_data.fd_to_ef[fd].r_sap;

                        raptor_ipcp_send_frame(sdb, dsap);
                }
                pthread_rwlock_unlock(&raptor_data.flows_lock);
        }

        log_info("Send thread stopped.");
        return NULL;
}

static void * raptor_ipcp_send_done_thread(void * o)
{
        uint8_t * frames[RAPTOR_BATCH];
        int count;
        int i;

        (void)o;

        log_info("Send_done thread started.");

        while (true) {
                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        break;

                count = ioctl(raptor_data.ioctl_fd, IOCTL_SEND_DONE | RAPTOR_BATCH, frames);

                if (count <= 0)
                        continue;

                for (i = 0; i < count; i++) {
                        free(frames[i]);
                }
        }

        log_info("Send_done thread stopped.");
        return NULL;
}

static void * raptor_ipcp_recv_thread(void * o)
{
        struct shm_du_buff * sdb;
        uint8_t * frames[RAPTOR_BATCH];
        uint8_t ** head;
        int needed = 0;
        int count;
        int i;

        (void)o;

        log_info("Recv thread started.");

        while (true) {
                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        break;

                needed = ioctl(raptor_data.ioctl_fd, IOCTL_RECV_NEED | RAPTOR_BATCH, NULL);

                if (needed <= 0)
                        continue;

                for (i = 0; i < needed; i++) {
                        if (ipcp_sdb_reserve(&sdb, RAPTOR_PAGE) < 0) {
                                log_err("Recv thread: reserve sdb failed. Stopping thread.");
                                return NULL;
                        }

                        if ((uint64_t)sdb & (~RAPTOR_PAGE_MASK)) {
                                log_err("Recv thread: sdb not at offset 0 in page. Stopping thread.");
                                return NULL;
                        }

                        frames[i] = shm_du_buff_head(sdb);

                        if ((uint64_t)frames[i] & 0x7) {
                                log_err("Recv thread: frame not 64bit aligned. Stopping thread.");
                                return NULL;
                        }
                }

                head = frames;

                do {
                        count = ioctl(raptor_data.ioctl_fd, IOCTL_RECV | needed, head);

                        if (count <= 0)
                                continue;

                        assert(count <= needed);

                        needed -= count;
                        head += count;

                } while (needed > 0 && ipcp_get_state() == IPCP_OPERATIONAL);
        }

        log_info("Recv thread stopped.");
        return NULL;
}

static int raptor_ipcp_bootstrap(const struct ipcp_config * conf)
{
        assert(conf);
        assert(conf->type == THIS_TYPE);

        log_info("%s", __FUNCTION__);

        raptor_data.ioctl_fd = open("/dev/raptor", 0);

        if (raptor_data.ioctl_fd < 0) {
                log_err("Failed to open /dev/raptor.");
                return -1;
        }

        ipcp_set_state(IPCP_OPERATIONAL);

        pthread_create(&raptor_data.mgmt_handler,
                       NULL,
                       raptor_ipcp_mgmt_handler,
                       NULL);

        pthread_create(&raptor_data.send_thread,
                       NULL,
                       raptor_ipcp_send_thread,
                       NULL);

        pthread_create(&raptor_data.recv_thread,
                       NULL,
                       raptor_ipcp_recv_thread,
                       NULL);

        pthread_create(&raptor_data.send_done_thread,
                       NULL,
                       raptor_ipcp_send_done_thread,
                       NULL);

        pthread_create(&raptor_data.recv_done_thread,
                       NULL,
                       raptor_ipcp_recv_done_thread,
                       NULL);

        log_dbg("Bootstrapped raptor IPCP with api %d.", getpid());

        return 0;
}

static int raptor_ipcp_reg(const uint8_t * hash)
{
        uint8_t * hash_dup;

        log_info("%s", __FUNCTION__);

        hash_dup = ipcp_hash_dup(hash);
        if (hash_dup == NULL) {
                log_err("Failed to duplicate hash.");
                return -ENOMEM;
        }

        if (shim_data_reg_add_entry(ipcpi.shim_data, hash_dup)) {
                log_err("Failed to add " HASH_FMT " to local registry.",
                        HASH_VAL(hash));
                free(hash_dup);
                return -1;
        }

        log_dbg("Registered " HASH_FMT ".", HASH_VAL(hash));

        return 0;
}

static int raptor_ipcp_unreg(const uint8_t * hash)
{
        log_info("%s", __FUNCTION__);

        shim_data_reg_del_entry(ipcpi.shim_data, hash);

        return 0;
}

static int raptor_ipcp_query(const uint8_t * hash)
{
        uint8_t            r_addr[MAC_SIZE];
        struct timespec    timeout = {(NAME_QUERY_TIMEOUT / 1000),
                                      (NAME_QUERY_TIMEOUT % 1000) * MILLION};
        raptor_msg_t msg = RAPTOR_MSG__INIT;
        struct dir_query * query;
        int                ret;

        log_info("%s", __FUNCTION__);

        if (shim_data_dir_has(ipcpi.shim_data, hash))
                return 0;

        msg.code      = RAPTOR_MSG_CODE__NAME_QUERY_REQ;
        msg.has_hash  = true;
        msg.hash.len  = ipcp_dir_hash_len();
        msg.hash.data = (uint8_t *) hash;

        memset(r_addr, 0xff, MAC_SIZE);

        query = shim_data_dir_query_create(hash);
        if (query == NULL)
                return -1;

        pthread_mutex_lock(&ipcpi.shim_data->dir_queries_lock);
        list_add(&query->next, &ipcpi.shim_data->dir_queries);
        pthread_mutex_unlock(&ipcpi.shim_data->dir_queries_lock);

        raptor_ipcp_send_mgmt_frame(&msg, r_addr);

        ret = shim_data_dir_query_wait(query, &timeout);

        pthread_mutex_lock(&ipcpi.shim_data->dir_queries_lock);
        list_del(&query->next);
        shim_data_dir_query_destroy(query);
        pthread_mutex_unlock(&ipcpi.shim_data->dir_queries_lock);

        return ret;
}

static int raptor_ipcp_flow_alloc(int             fd,
                                   const uint8_t * hash,
                                   qoscube_t       cube)
{
        uint8_t  ssap = 0;
        uint8_t  r_addr[MAC_SIZE];
        uint64_t addr = 0;

        log_info("%s", __FUNCTION__);

        log_dbg("Allocating flow to " HASH_FMT ".", HASH_VAL(hash));

        assert(hash);

        if (cube != QOS_CUBE_BE) {
                log_dbg("Unsupported QoS requested.");
                return -1;
        }

        if (!shim_data_dir_has(ipcpi.shim_data, hash)) {
                log_err("Destination unreachable.");
                return -1;
        }
        addr = shim_data_dir_get_addr(ipcpi.shim_data, hash);

        pthread_rwlock_wrlock(&raptor_data.flows_lock);

        ssap =  bmp_allocate(raptor_data.saps);
        if (!bmp_is_id_valid(raptor_data.saps, ssap)) {
                pthread_rwlock_unlock(&raptor_data.flows_lock);
                return -1;
        }

        raptor_data.fd_to_ef[fd].sap = ssap;
        raptor_data.ef_to_fd[ssap]   = fd;

        pthread_rwlock_unlock(&raptor_data.flows_lock);

        memcpy(r_addr, &addr, MAC_SIZE);

        if (raptor_ipcp_sap_alloc(r_addr, ssap, hash, cube) < 0) {
                pthread_rwlock_wrlock(&raptor_data.flows_lock);
                bmp_release(raptor_data.saps, raptor_data.fd_to_ef[fd].sap);
                raptor_data.fd_to_ef[fd].sap = -1;
                raptor_data.ef_to_fd[ssap]   = -1;
                pthread_rwlock_unlock(&raptor_data.flows_lock);
                return -1;
        }

        flow_set_add(raptor_data.np1_flows, fd);

        log_dbg("Pending flow with fd %d on SAP %d.", fd, ssap);

        return 0;
}

static int raptor_ipcp_flow_alloc_resp(int fd,
                                        int response)
{
        struct timespec ts    = {0, EVENT_WAIT_TIMEOUT * 1000};
        struct timespec abstime;
        uint8_t         ssap  = 0;
        uint8_t         r_sap = 0;
        uint8_t         r_addr[MAC_SIZE];

        log_info("%s", __FUNCTION__);

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        pthread_mutex_lock(&ipcpi.alloc_lock);

        while (ipcpi.alloc_id != fd && ipcp_get_state() == IPCP_OPERATIONAL) {
                ts_add(&abstime, &ts, &abstime);
                pthread_cond_timedwait(&ipcpi.alloc_cond,
                                       &ipcpi.alloc_lock,
                                       &abstime);
        }

        if (ipcp_get_state() != IPCP_OPERATIONAL) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                return -1;
        }

        ipcpi.alloc_id = -1;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_mutex_unlock(&ipcpi.alloc_lock);

        pthread_rwlock_wrlock(&raptor_data.flows_lock);

        ssap = bmp_allocate(raptor_data.saps);
        if (!bmp_is_id_valid(raptor_data.saps, ssap)) {
                pthread_rwlock_unlock(&raptor_data.flows_lock);
                return -1;
        }

        raptor_data.fd_to_ef[fd].sap = ssap;
        memcpy(r_addr, raptor_data.fd_to_ef[fd].r_addr, MAC_SIZE);
        r_sap = raptor_data.fd_to_ef[fd].r_sap;
        raptor_data.ef_to_fd[ssap] = fd;

        pthread_rwlock_unlock(&raptor_data.flows_lock);

        if (raptor_ipcp_sap_alloc_resp(r_addr, ssap, r_sap, response) < 0) {
                pthread_rwlock_wrlock(&raptor_data.flows_lock);
                bmp_release(raptor_data.saps, raptor_data.fd_to_ef[fd].sap);
                pthread_rwlock_unlock(&raptor_data.flows_lock);
                return -1;
        }

        flow_set_add(raptor_data.np1_flows, fd);

        log_dbg("Accepted flow, fd %d, SAP %d.", fd, (uint8_t)ssap);

        return 0;
}

static int raptor_ipcp_flow_dealloc(int fd)
{
        uint8_t sap;
        uint8_t addr[MAC_SIZE];

        log_info("%s", __FUNCTION__);

        ipcp_flow_fini(fd);

        pthread_rwlock_wrlock(&raptor_data.flows_lock);

        flow_set_del(raptor_data.np1_flows, fd);

        sap = raptor_data.fd_to_ef[fd].sap;
        memcpy(addr, raptor_data.fd_to_ef[fd].r_addr, MAC_SIZE);
        bmp_release(raptor_data.saps, sap);
        raptor_data.fd_to_ef[fd].sap = -1;
        raptor_data.fd_to_ef[fd].r_sap = -1;
        memset(&raptor_data.fd_to_ef[fd].r_addr, 0, MAC_SIZE);

        raptor_data.ef_to_fd[sap] = -1;

        pthread_rwlock_unlock(&raptor_data.flows_lock);

        flow_dealloc(fd);

        log_dbg("Flow with fd %d deallocated.", fd);

        return 0;
}

static struct ipcp_ops raptor_ops = {
        .ipcp_bootstrap       = raptor_ipcp_bootstrap,
        .ipcp_enroll          = NULL,
        .ipcp_reg             = raptor_ipcp_reg,
        .ipcp_unreg           = raptor_ipcp_unreg,
        .ipcp_query           = raptor_ipcp_query,
        .ipcp_flow_alloc      = raptor_ipcp_flow_alloc,
        .ipcp_flow_alloc_resp = raptor_ipcp_flow_alloc_resp,
        .ipcp_flow_dealloc    = raptor_ipcp_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        if (ipcp_init(argc, argv, THIS_TYPE, &raptor_ops) < 0) {
                ipcp_create_r(getpid(), -1);
                exit(EXIT_FAILURE);
        }

        if (raptor_data_init() < 0) {
                log_err("Failed to init shim-eth-llc data.");
                ipcp_create_r(getpid(), -1);
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                ipcp_create_r(getpid(), -1);
                raptor_data_fini();
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        if (ipcp_create_r(getpid(), 0)) {
                log_err("Failed to notify IRMd we are initialized.");
                ipcp_set_state(IPCP_NULL);
                ipcp_shutdown();
                raptor_data_fini();
                ipcp_fini();
                exit(EXIT_FAILURE);
        }

        log_info("Raptor created.");

        ipcp_shutdown();

        if (ipcp_get_state() == IPCP_SHUTDOWN) {
                pthread_join(raptor_data.send_thread, NULL);
                pthread_join(raptor_data.recv_thread, NULL);
                pthread_join(raptor_data.send_done_thread, NULL);
                pthread_join(raptor_data.recv_done_thread, NULL);
                pthread_join(raptor_data.mgmt_handler, NULL);
        }

        raptor_data_fini();

        ipcp_fini();

        exit(EXIT_SUCCESS);
}
