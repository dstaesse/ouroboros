/*
 * Ouroboros - Copyright (C) 2016 - 2021
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

#include "config.h"

#define OUROBOROS_PREFIX "ipcpd/raptor"

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
#include "shim-data.h"

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

#define THIS_TYPE          IPCP_RAPTOR
#define MGMT_EID           0x01
#define MAC_SIZE           6
#define MAX_EIDS           64

#define EVENT_WAIT_TIMEOUT 100  /* us */
#define NAME_QUERY_TIMEOUT 2000 /* ms */
#define MGMT_TIMEOUT       100  /* ms */

#define IOCTL_SEND         0xAD420000
#define IOCTL_RECV         0xAD430000
#define IOCTL_SEND_DONE    0xAD440000
#define IOCTL_RECV_DONE    0xAD450000
#define IOCTL_RECV_NEED    0xAD460000

#define RAPTOR_PAGE        ((1 << 12) - 200) /* 4kB - 200 */
#define RAPTOR_PAGE_MASK   (~0xFFF)

#define RAPTOR_BATCH       100
#define RAPTOR_HEADER      3

#define FLOW_REQ           0
#define FLOW_REPLY         1
#define NAME_QUERY_REQ     2
#define NAME_QUERY_REPLY   3

struct mgmt_msg {
        uint8_t  code;
        uint8_t  seid;
        uint8_t  deid;
        int8_t   response;
        /* QoS parameters from spec, aligned */
        uint32_t loss;
        uint64_t bandwidth;
        uint32_t ber;
        uint32_t max_gap;
        uint32_t delay;
        uint8_t  in_order;
        uint8_t  availability;
} __attribute__((packed));

struct ef {
        int8_t  eid;
        int8_t  r_eid;
};

struct mgmt_frame {
        struct list_head next;
        uint8_t          buf[RAPTOR_PAGE];
        size_t           len;
};

struct {
        struct shim_data * shim_data;

        int                ioctl_fd;

        struct bmp *       eids;
        fset_t *           np1_flows;
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
        int                ret = -ENOMEM;
        pthread_condattr_t cattr;

        raptor_data.fd_to_ef =
                malloc(sizeof(*raptor_data.fd_to_ef) * SYS_MAX_FLOWS);
        if (raptor_data.fd_to_ef == NULL)
                goto fail_fd_to_ef;

        raptor_data.ef_to_fd =
                malloc(sizeof(*raptor_data.ef_to_fd) * MAX_EIDS);
        if (raptor_data.ef_to_fd == NULL)
                goto fail_ef_to_fd;

        raptor_data.eids = bmp_create(MAX_EIDS, 2);
        if (raptor_data.eids == NULL)
                goto fail_eids;

        raptor_data.np1_flows = fset_create();
        if (raptor_data.np1_flows == NULL)
                goto fail_np1_flows;

        raptor_data.fq = fqueue_create();
        if (raptor_data.fq == NULL)
                goto fail_fq;

        for (i = 0; i < MAX_EIDS; ++i)
                raptor_data.ef_to_fd[i] = -1;

        for (i = 0; i < SYS_MAX_FLOWS; ++i) {
                raptor_data.fd_to_ef[i].eid   = -1;
                raptor_data.fd_to_ef[i].r_eid = -1;
        }

        raptor_data.shim_data = shim_data_create();
        if (raptor_data.shim_data == NULL)
                goto fail_shim_data;

        ret = -1;

        if (pthread_rwlock_init(&raptor_data.flows_lock, NULL))
                goto fail_flows_lock;

        if (pthread_mutex_init(&raptor_data.mgmt_lock, NULL))
                goto fail_mgmt_lock;

        if (pthread_condattr_init(&cattr))
                goto fail_condattr;

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif

        if (pthread_cond_init(&raptor_data.mgmt_cond, &cattr))
                goto fail_mgmt_cond;

        pthread_condattr_destroy(&cattr);

        list_head_init(&raptor_data.mgmt_frames);

        return 0;

 fail_mgmt_cond:
        pthread_condattr_destroy(&cattr);
 fail_condattr:
        pthread_mutex_destroy(&raptor_data.mgmt_lock);
 fail_mgmt_lock:
        pthread_rwlock_destroy(&raptor_data.flows_lock);
 fail_flows_lock:
        shim_data_destroy(raptor_data.shim_data);
 fail_shim_data:
        fqueue_destroy(raptor_data.fq);
 fail_fq:
        fset_destroy(raptor_data.np1_flows);
 fail_np1_flows:
        bmp_destroy(raptor_data.eids);
 fail_eids:
        free(raptor_data.ef_to_fd);
 fail_ef_to_fd:
        free(raptor_data.fd_to_ef);
 fail_fd_to_ef:
        return ret;
}

static void raptor_data_fini(void)
{
        close(raptor_data.ioctl_fd);
        pthread_cond_destroy(&raptor_data.mgmt_cond);
        pthread_mutex_destroy(&raptor_data.mgmt_lock);
        pthread_rwlock_destroy(&raptor_data.flows_lock);
        fqueue_destroy(raptor_data.fq);
        fset_destroy(raptor_data.np1_flows);
        bmp_destroy(raptor_data.eids);
        free(raptor_data.fd_to_ef);
        free(raptor_data.ef_to_fd);
}

static int raptor_send_frame(struct shm_du_buff * sdb,
                             uint8_t              deid)
{
        uint8_t * frame;
        size_t    frame_len;
        uint8_t * payload;
        size_t    len;

        payload = shm_du_buff_head(sdb);
        len = shm_du_buff_tail(sdb) - shm_du_buff_head(sdb);

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
        frame[2] = deid;

        memcpy(&frame[RAPTOR_HEADER], payload, len);

        if (ioctl(raptor_data.ioctl_fd, IOCTL_SEND | 1, &frame) != 1) {
                log_err("Ioctl send failed.");
                free(frame);
                return -1;
        }

        return 0;
}

static int raptor_eid_alloc(uint8_t         seid,
                            const uint8_t * hash,
                            qosspec_t       qs)
{
        struct mgmt_msg *    msg;
        struct shm_du_buff * sdb;

        if (ipcp_sdb_reserve(&sdb, sizeof(*msg) + ipcp_dir_hash_len()) < 0) {
                log_err("failed to reserve sdb for management frame.");
                return -1;
        }

        msg               = (struct mgmt_msg *) shm_du_buff_head(sdb);
        msg->code         = FLOW_REQ;
        msg->seid         = seid;
        msg->delay        = hton32(qs.delay);
        msg->bandwidth    = hton64(qs.bandwidth);
        msg->availability = qs.availability;
        msg->loss         = hton32(qs.loss);
        msg->ber          = hton32(qs.ber);
        msg->in_order     = qs.in_order;
        msg->max_gap      = hton32(qs.max_gap);

        memcpy(msg + 1, hash, ipcp_dir_hash_len());

        if (raptor_send_frame(sdb, MGMT_EID)) {
                log_err("Failed to send management frame.");
                ipcp_sdb_release(sdb);
                return -1;
        }

        ipcp_sdb_release(sdb);

        return 0;
}

static int raptor_eid_alloc_resp(uint8_t seid,
                                 uint8_t deid,
                                 int     response)
{
        struct mgmt_msg *    msg;
        struct shm_du_buff * sdb;

        if (ipcp_sdb_reserve(&sdb, sizeof(*msg)) < 0) {
                log_err("Failed to reserve sdb for management frame.");
                return -1;
        }

        msg           = (struct mgmt_msg *) shm_du_buff_head(sdb);
        msg->code     = FLOW_REPLY;
        msg->seid     = seid;
        msg->deid     = deid;
        msg->response = response;

        if (raptor_send_frame(sdb, MGMT_EID)) {
                log_err("Failed to send management frame.");
                ipcp_sdb_release(sdb);
                return -1;
        }

        ipcp_sdb_release(sdb);

        return 0;
}

static int raptor_eid_req(uint8_t         r_eid,
                          const uint8_t * dst,
                          qosspec_t       qs)
{
        struct timespec ts = {0, EVENT_WAIT_TIMEOUT * 1000};
        struct timespec abstime;
        int             fd;

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
        fd = ipcp_flow_req_arr(getpid(), dst, ipcp_dir_hash_len(), qs);
        if (fd < 0) {
                pthread_mutex_unlock(&ipcpi.alloc_lock);
                log_err("Could not get new flow from IRMd.");
                return -1;
        }

        pthread_rwlock_wrlock(&raptor_data.flows_lock);

        raptor_data.fd_to_ef[fd].r_eid = r_eid;

        ipcpi.alloc_id = fd;
        pthread_cond_broadcast(&ipcpi.alloc_cond);

        pthread_rwlock_unlock(&raptor_data.flows_lock);
        pthread_mutex_unlock(&ipcpi.alloc_lock);

        log_dbg("New flow request, fd %d, remote EID %d.", fd, r_eid);

        return 0;
}

static int raptor_eid_alloc_reply(uint8_t seid,
                                  int     deid,
                                  int     response)
{
        int ret = 0;
        int fd = -1;

        pthread_rwlock_wrlock(&raptor_data.flows_lock);

        fd = raptor_data.ef_to_fd[deid];
        if (fd < 0) {
                pthread_rwlock_unlock(& raptor_data.flows_lock);
                log_err("No flow found with that EID.");
                return -1; /* -EFLOWNOTFOUND */
        }

        if (response)
                bmp_release(raptor_data.eids, raptor_data.fd_to_ef[fd].eid);
        else
                raptor_data.fd_to_ef[fd].r_eid = seid;

        pthread_rwlock_unlock(&raptor_data.flows_lock);

        log_dbg("Flow reply, fd %d, SEID %d, DEID %d.", fd, seid, deid);

        if ((ret = ipcp_flow_alloc_reply(fd, response)) < 0)
                return -1;

        return ret;

}

static int raptor_name_query_req(const uint8_t * hash)
{
        struct mgmt_msg *    msg;
        struct shm_du_buff * sdb;

        if (!shim_data_reg_has(raptor_data.shim_data, hash))
                return 0;

        if (ipcp_sdb_reserve(&sdb, sizeof(*msg) + ipcp_dir_hash_len()) < 0) {
                log_err("Failed to reserve sdb for management frame.");
                return -1;
        }

        msg       = (struct mgmt_msg *) shm_du_buff_head(sdb);
        msg->code = NAME_QUERY_REPLY;

        memcpy(msg + 1, hash, ipcp_dir_hash_len());

        if (raptor_send_frame(sdb, MGMT_EID)) {
                log_err("Failed to send management frame.");
                ipcp_sdb_release(sdb);
                return -1;
        }

        ipcp_sdb_release(sdb);

        return 0;
}

static int raptor_name_query_reply(const uint8_t * hash)
{
        shim_data_dir_add_entry(raptor_data.shim_data, hash, 0);

        shim_data_dir_query_respond(raptor_data.shim_data, hash);

        return 0;
}

static int raptor_mgmt_frame(const uint8_t * buf,
                             size_t          len)
{
        struct mgmt_msg * msg  = (struct mgmt_msg *) buf;
        uint8_t *         hash = (uint8_t *) (msg + 1);
        qosspec_t         qs;

        switch (msg->code) {
        case FLOW_REQ:
                if (len != sizeof(*msg) + ipcp_dir_hash_len()) {
                        log_err("Corrupt message received.");
                        return -1;
                }

                qs.delay        = ntoh32(msg->delay);
                qs.bandwidth    = ntoh64(msg->bandwidth);
                qs.availability = msg->availability;
                qs.loss         = ntoh32(msg->loss);
                qs.ber          = ntoh32(msg->ber);
                qs.in_order     = msg->in_order;
                qs.max_gap      = ntoh32(msg->max_gap);

                if (shim_data_reg_has(raptor_data.shim_data, hash))
                        raptor_eid_req(msg->seid, hash, qs);
                break;
        case FLOW_REPLY:
                if (len != sizeof(*msg)) {
                        log_err("Corrupt message received.");
                        return -1;
                }

                raptor_eid_alloc_reply(msg->seid, msg->deid, msg->response);
                break;
        case NAME_QUERY_REQ:
                if (len != sizeof(*msg) + ipcp_dir_hash_len()) {
                        log_err("Corrupt message received.");
                        return -1;
                }

                raptor_name_query_req(hash);
                break;
        case NAME_QUERY_REPLY:
                if (len != sizeof(*msg) + ipcp_dir_hash_len()) {
                        log_err("Corrupt message received.");
                        return -1;
                }

                raptor_name_query_reply(hash);
                break;
        default:
                log_err("Unknown message received %d.", msg->code);
                return -1;
        }

        return 0;
}

static void * raptor_mgmt_handler(void * o)
{
        int                 ret;
        struct timespec     timeout = {(MGMT_TIMEOUT / 1000),
                                       (MGMT_TIMEOUT % 1000) * MILLION};
        struct timespec     abstime;
        struct mgmt_frame * frame;

        (void) o;

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

                raptor_mgmt_frame(frame->buf, frame->len);
                free(frame);
        }

        return NULL;
}

static void raptor_recv_frame(uint8_t * frame)
{
        uint8_t              deid;
        uint8_t *            payload;
        size_t               frame_len;
        size_t               length;
        int                  fd;
        struct mgmt_frame *  mgmt_frame;
        struct shm_du_buff * sdb;
        size_t               idx;

        sdb = (struct shm_du_buff *)((uint64_t) frame & RAPTOR_PAGE_MASK);
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

        deid    = frame[2];
        payload = &frame[RAPTOR_HEADER];
        length  = frame_len - RAPTOR_HEADER;

        shm_du_buff_head_release(sdb, RAPTOR_HEADER);
        shm_du_buff_tail_release(sdb, RAPTOR_PAGE - frame_len);

        if (deid == MGMT_EID) {
                pthread_mutex_lock(&raptor_data.mgmt_lock);

                mgmt_frame = malloc(sizeof(*mgmt_frame));
                if (mgmt_frame == NULL) {
                        pthread_mutex_unlock(&raptor_data.mgmt_lock);
                        ipcp_sdb_release(sdb);
                        return;
                }

                memcpy(mgmt_frame->buf, payload, length);
                mgmt_frame->len = length;
                list_add(&mgmt_frame->next, &raptor_data.mgmt_frames);
                pthread_cond_signal(&raptor_data.mgmt_cond);
                pthread_mutex_unlock(&raptor_data.mgmt_lock);

                ipcp_sdb_release(sdb);
        } else {
                pthread_rwlock_rdlock(&raptor_data.flows_lock);

                fd = raptor_data.ef_to_fd[deid];
                if (fd < 0) {
                        pthread_rwlock_unlock(&raptor_data.flows_lock);
                        ipcp_sdb_release(sdb);
                        return;
                }

                pthread_rwlock_unlock(&raptor_data.flows_lock);

                local_flow_write(fd, idx);
        }
}

static void * raptor_recv_done_thread(void * o)
{
        uint8_t * frames[RAPTOR_BATCH];
        int       count;
        int       i;

        (void) o;

        while (true) {
                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        break;

                count = ioctl(raptor_data.ioctl_fd,
                              IOCTL_RECV_DONE | RAPTOR_BATCH, frames);

                if (count <= 0)
                        continue;

                for (i = 0; i < count; i++)
                        raptor_recv_frame(frames[i]);
        }

        return NULL;
}

static void * raptor_send_thread(void * o)
{
        struct timespec      timeout = {0, EVENT_WAIT_TIMEOUT * 1000};
        int                  fd;
        struct shm_du_buff * sdb;
        uint8_t              deid;

        (void) o;

        while (fevent(raptor_data.np1_flows, raptor_data.fq, &timeout)) {
                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        break;

                pthread_rwlock_rdlock(&raptor_data.flows_lock);
                while ((fd = fqueue_next(raptor_data.fq)) >= 0) {
                        if (ipcp_flow_read(fd, &sdb)) {
                                log_err("Bad read from fd %d.", fd);
                                continue;
                        }

                        deid = raptor_data.fd_to_ef[fd].r_eid;

                        raptor_send_frame(sdb, deid);
                }
                pthread_rwlock_unlock(&raptor_data.flows_lock);
        }

        return NULL;
}

static void * raptor_send_done_thread(void * o)
{
        uint8_t * frames[RAPTOR_BATCH];
        int       count;
        int       i;

        (void) o;

        while (true) {
                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        break;

                count = ioctl(raptor_data.ioctl_fd,
                              IOCTL_SEND_DONE | RAPTOR_BATCH, frames);

                if (count <= 0)
                        continue;

                for (i = 0; i < count; i++)
                        free(frames[i]);
        }

        return NULL;
}

static void * raptor_recv_thread(void * o)
{
        struct shm_du_buff * sdb;
        uint8_t *            frames[RAPTOR_BATCH];
        uint8_t **           head;
        int                  needed = 0;
        int                  count;
        int                  i;

        (void) o;

        while (true) {
                if (ipcp_get_state() != IPCP_OPERATIONAL)
                        break;

                needed = ioctl(raptor_data.ioctl_fd,
                               IOCTL_RECV_NEED | RAPTOR_BATCH, NULL);

                if (needed <= 0)
                        continue;

                for (i = 0; i < needed; i++) {
                        if (ipcp_sdb_reserve(&sdb, RAPTOR_PAGE) < 0) {
                                log_err("Recv thread: reserve sdb failed.");
                                return NULL;
                        }

                        if ((uint64_t)sdb & (~RAPTOR_PAGE_MASK)) {
                                log_err("Recv thread: sdb not at offset 0.");
                                return NULL;
                        }

                        frames[i] = shm_du_buff_head(sdb);

                        if ((uint64_t)frames[i] & 0x7) {
                                log_err("Recv thread: frame not aligned.");
                                return NULL;
                        }
                }

                head = frames;

                do {
                        count = ioctl(raptor_data.ioctl_fd,
                                      IOCTL_RECV | needed, head);
                        if (count <= 0)
                                continue;

                        assert(count <= needed);

                        needed -= count;
                        head += count;

                } while (needed > 0 && ipcp_get_state() == IPCP_OPERATIONAL);
        }

        return NULL;
}

static int raptor_bootstrap(const struct ipcp_config * conf)
{
        assert(conf);
        assert(conf->type == THIS_TYPE);

        (void) conf;

        raptor_data.ioctl_fd = open("/dev/raptor", 0);
        if (raptor_data.ioctl_fd < 0) {
                log_err("Failed to open /dev/raptor.");
                goto fail_ioctl;
        }

        ipcp_set_state(IPCP_OPERATIONAL);

        if (pthread_create(&raptor_data.mgmt_handler,
                           NULL,
                           raptor_mgmt_handler,
                           NULL)) {
                ipcp_set_state(IPCP_INIT);
                goto fail_mgmt_handler;
        }

        if (pthread_create(&raptor_data.send_thread,
                           NULL,
                           raptor_send_thread,
                           NULL)) {
                ipcp_set_state(IPCP_INIT);
                goto fail_send_thread;
        }

        if (pthread_create(&raptor_data.recv_thread,
                           NULL,
                           raptor_recv_thread,
                           NULL)) {
                ipcp_set_state(IPCP_INIT);
                goto fail_recv_thread;
        }

        if (pthread_create(&raptor_data.send_done_thread,
                           NULL,
                           raptor_send_done_thread,
                           NULL)) {
                ipcp_set_state(IPCP_INIT);
                goto fail_send_done_thread;
        }

        if (pthread_create(&raptor_data.recv_done_thread,
                           NULL,
                           raptor_recv_done_thread,
                           NULL)) {
                ipcp_set_state(IPCP_INIT);
                goto fail_recv_done_thread;
        }

        log_dbg("Bootstrapped raptor IPCP with api %d.", getpid());

        return 0;

 fail_recv_done_thread:
        pthread_join(raptor_data.send_done_thread, NULL);
 fail_send_done_thread:
        pthread_join(raptor_data.recv_thread, NULL);
 fail_recv_thread:
        pthread_join(raptor_data.send_thread, NULL);
 fail_send_thread:
        pthread_join(raptor_data.mgmt_handler, NULL);
 fail_mgmt_handler:
        close(raptor_data.ioctl_fd);
 fail_ioctl:
        return -1;
}

static int raptor_reg(const uint8_t * hash)
{
        uint8_t * hash_dup;

        hash_dup = ipcp_hash_dup(hash);
        if (hash_dup == NULL) {
                log_err("Failed to duplicate hash.");
                return -ENOMEM;
        }

        if (shim_data_reg_add_entry(raptor_data.shim_data, hash_dup)) {
                log_err("Failed to add " HASH_FMT " to local registry.",
                        HASH_VAL(hash));
                free(hash_dup);
                return -1;
        }

        log_dbg("Registered " HASH_FMT ".", HASH_VAL(hash));

        return 0;
}

static int raptor_unreg(const uint8_t * hash)
{
        shim_data_reg_del_entry(raptor_data.shim_data, hash);

        return 0;
}

static int raptor_query(const uint8_t * hash)
{
        struct timespec      timeout = {(NAME_QUERY_TIMEOUT / 1000),
                                        (NAME_QUERY_TIMEOUT % 1000) * MILLION};
        struct mgmt_msg *    msg;
        struct dir_query *   query;
        int                  ret;
        struct shm_du_buff * sdb;

        if (shim_data_dir_has(raptor_data.shim_data, hash))
                return 0;

        if (ipcp_sdb_reserve(&sdb, sizeof(*msg) + ipcp_dir_hash_len()) < 0) {
                log_err("failed to reserve sdb for management frame.");
                return -1;
        }

        msg       = (struct mgmt_msg *) shm_du_buff_head(sdb);
        msg->code = NAME_QUERY_REQ;

        memcpy(msg + 1, hash, ipcp_dir_hash_len());

        query = shim_data_dir_query_create(raptor_data.shim_data, hash);
        if (query == NULL) {
                ipcp_sdb_release(sdb);
                return -1;
        }

        if (raptor_send_frame(sdb, MGMT_EID)) {
                log_err("Failed to send management frame.");
                ipcp_sdb_release(sdb);
                return -1;
        }

        ret = shim_data_dir_query_wait(query, &timeout);

        shim_data_dir_query_destroy(raptor_data.shim_data, query);

        return ret;
}

static int raptor_flow_alloc(int             fd,
                             const uint8_t * hash,
                             qosspec_t       qs)
{
        uint8_t  seid = 0;

        log_dbg("Allocating flow to " HASH_FMT ".", HASH_VAL(hash));

        assert(hash);

        if (!shim_data_dir_has(raptor_data.shim_data, hash)) {
                log_err("Destination unreachable.");
                return -1;
        }

        pthread_rwlock_wrlock(&raptor_data.flows_lock);

        seid =  bmp_allocate(raptor_data.eids);
        if (!bmp_is_id_valid(raptor_data.eids, seid)) {
                pthread_rwlock_unlock(&raptor_data.flows_lock);
                return -1;
        }

        raptor_data.fd_to_ef[fd].eid = seid;
        raptor_data.ef_to_fd[seid]   = fd;

        pthread_rwlock_unlock(&raptor_data.flows_lock);

        if (raptor_eid_alloc(seid, hash, qs) < 0) {
                pthread_rwlock_wrlock(&raptor_data.flows_lock);
                bmp_release(raptor_data.eids, raptor_data.fd_to_ef[fd].eid);
                raptor_data.fd_to_ef[fd].eid = -1;
                raptor_data.ef_to_fd[seid]   = -1;
                pthread_rwlock_unlock(&raptor_data.flows_lock);
                return -1;
        }

        fset_add(raptor_data.np1_flows, fd);

        log_dbg("Pending flow with fd %d on EID %d.", fd, seid);

        return 0;
}

static int raptor_flow_alloc_resp(int fd,
                                  int response)
{
        struct timespec ts    = {0, EVENT_WAIT_TIMEOUT * 1000};
        struct timespec abstime;
        uint8_t         seid  = 0;
        uint8_t         r_eid = 0;

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

        seid = bmp_allocate(raptor_data.eids);
        if (!bmp_is_id_valid(raptor_data.eids, seid)) {
                pthread_rwlock_unlock(&raptor_data.flows_lock);
                return -1;
        }

        raptor_data.fd_to_ef[fd].eid = seid;
        r_eid = raptor_data.fd_to_ef[fd].r_eid;
        raptor_data.ef_to_fd[seid] = fd;

        pthread_rwlock_unlock(&raptor_data.flows_lock);

        if (raptor_eid_alloc_resp(seid, r_eid, response) < 0) {
                pthread_rwlock_wrlock(&raptor_data.flows_lock);
                bmp_release(raptor_data.eids, raptor_data.fd_to_ef[fd].eid);
                pthread_rwlock_unlock(&raptor_data.flows_lock);
                return -1;
        }

        fset_add(raptor_data.np1_flows, fd);

        log_dbg("Accepted flow, fd %d, EID %d.", fd, (uint8_t)seid);

        return 0;
}

static int raptor_flow_dealloc(int fd)
{
        uint8_t eid;

        ipcp_flow_fini(fd);

        pthread_rwlock_wrlock(&raptor_data.flows_lock);

        fset_del(raptor_data.np1_flows, fd);

        eid = raptor_data.fd_to_ef[fd].eid;
        bmp_release(raptor_data.eids, eid);
        raptor_data.fd_to_ef[fd].eid = -1;
        raptor_data.fd_to_ef[fd].r_eid = -1;

        raptor_data.ef_to_fd[eid] = -1;

        pthread_rwlock_unlock(&raptor_data.flows_lock);

        flow_dealloc(fd);

        log_dbg("Flow with fd %d deallocated.", fd);

        return 0;
}

static struct ipcp_ops raptor_ops = {
        .ipcp_bootstrap       = raptor_bootstrap,
        .ipcp_enroll          = NULL,
        .ipcp_reg             = raptor_reg,
        .ipcp_unreg           = raptor_unreg,
        .ipcp_query           = raptor_query,
        .ipcp_flow_alloc      = raptor_flow_alloc,
        .ipcp_flow_join       = NULL,
        .ipcp_flow_alloc_resp = raptor_flow_alloc_resp,
        .ipcp_flow_dealloc    = raptor_flow_dealloc
};

int main(int    argc,
         char * argv[])
{
        if (ipcp_init(argc, argv, &raptor_ops) < 0) {
                log_err("Failed to init IPCP.");
                goto fail_init;
        }

        if (raptor_data_init() < 0) {
                log_err("Failed to init shim-eth-llc data.");
                goto fail_data_init;
        }

        if (ipcp_boot() < 0) {
                log_err("Failed to boot IPCP.");
                goto fail_boot;
        }

        if (ipcp_create_r(getpid(), 0)) {
                log_err("Failed to notify IRMd we are initialized.");
                ipcp_set_state(IPCP_NULL);
                goto fail_create_r;
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

 fail_create_r:
        ipcp_shutdown();
 fail_boot:
        raptor_data_fini();
 fail_data_init:
        ipcp_fini();
 fail_init:
        ipcp_create_r(getpid(), -1);
        exit(EXIT_FAILURE);
}
