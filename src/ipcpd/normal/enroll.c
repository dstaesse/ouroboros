/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Enrollment Task
 *
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

#define _POSIX_C_SOURCE 199309L

#define OUROBOROS_PREFIX "enrollment"

#include <ouroboros/endian.h>
#include <ouroboros/errno.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/errno.h>
#include <ouroboros/sockets.h>

#include "connmgr.h"
#include "enroll.h"
#include "ipcp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "enroll.pb-c.h"
typedef EnrollMsg enroll_msg_t;

#define ENROLL_AE               "Enrollment"
#define ENROLL_PROTO            "OEP" /* Ouroboros enrollment protocol */
#define ENROLL_WARN_TIME_OFFSET 20
#define ENROLL_BUF_LEN          1024

enum enroll_state {
        ENROLL_NULL = 0,
        ENROLL_INIT,
        ENROLL_RUNNING
};

struct {
        struct ipcp_config conf;
        enum enroll_state  state;
        pthread_t          listener;
} enroll;

static int send_rcv_enroll_msg(int fd)
{
        enroll_msg_t    req = ENROLL_MSG__INIT;
        enroll_msg_t *  reply;
        uint8_t         buf[ENROLL_BUF_LEN];
        ssize_t         len;
        ssize_t         delta_t;
        struct timespec t0;
        struct timespec rtt;

        req.code = ENROLL_CODE__ENROLL_REQ;

        len = enroll_msg__get_packed_size(&req);
        if (len < 0) {
                log_dbg("Failed pack request message.");
                return -1;
        }

        enroll_msg__pack(&req, buf);

        clock_gettime(CLOCK_REALTIME, &t0);

        if (flow_write(fd, buf, len)) {
                log_dbg("Failed to send request message.");
                return -1;
        }

        len = flow_read(fd, buf, ENROLL_BUF_LEN);
        if (len < 0) {
                log_dbg("No enrollment reply received.");
                return -1;
        }

        log_dbg("Received enrollment info (%zd bytes).", len);

        reply = enroll_msg__unpack(NULL, len, buf);
        if (reply == NULL) {
                log_dbg("No enrollment response.");
                return -1;
        }

        if (reply->code != ENROLL_CODE__ENROLL_BOOT) {
                log_dbg("Failed to unpack enrollment response.");
                enroll_msg__free_unpacked(reply, NULL);
                return -1;
        }

        if (!(reply->has_t_sec && reply->has_t_nsec)) {
                log_dbg("No time in response message.");
                enroll_msg__free_unpacked(reply, NULL);
                return -1;
        }

        clock_gettime(CLOCK_REALTIME, &rtt);

        delta_t = ts_diff_ms(&t0, &rtt);

        rtt.tv_sec  = reply->t_sec;
        rtt.tv_nsec = reply->t_nsec;

        if (labs(ts_diff_ms(&t0, &rtt)) - delta_t > ENROLL_WARN_TIME_OFFSET)
                log_warn("Clock offset above threshold.");

        strcpy(enroll.conf.dif_info.dif_name, reply->conf->dif_info->dif_name);
        enroll.conf.type           = reply->conf->ipcp_type;
        enroll.conf.addr_size      = reply->conf->addr_size;
        enroll.conf.fd_size        = reply->conf->fd_size;
        enroll.conf.has_ttl        = reply->conf->has_ttl;
        enroll.conf.addr_auth_type = reply->conf->addr_auth_type;
        enroll.conf.routing_type   = reply->conf->routing_type;
        enroll.conf.pff_type       = reply->conf->pff_type;
        enroll.conf.dif_info.dir_hash_algo
                = reply->conf->dif_info->dir_hash_algo;

        enroll_msg__free_unpacked(reply, NULL);

        return 0;
}

static ssize_t enroll_pack(uint8_t ** buf)
{
        enroll_msg_t      msg      = ENROLL_MSG__INIT;
        ipcp_config_msg_t config   = IPCP_CONFIG_MSG__INIT;
        dif_info_msg_t    dif_info = DIF_INFO_MSG__INIT;
        struct timespec   now;
        ssize_t           len;

        clock_gettime(CLOCK_REALTIME, &now);

        msg.code       = ENROLL_CODE__ENROLL_BOOT;
        msg.has_t_sec  = true;
        msg.t_sec      = now.tv_sec;
        msg.has_t_nsec = true;
        msg.t_nsec     = now.tv_nsec;
        msg.conf       = &config;

        config.ipcp_type          = enroll.conf.type;
        config.has_addr_size      = true;
        config.addr_size          = enroll.conf.addr_size;
        config.has_fd_size        = true;
        config.fd_size            = enroll.conf.fd_size;
        config.has_has_ttl        = true;
        config.has_ttl            = enroll.conf.has_ttl;
        config.has_addr_auth_type = true;
        config.addr_auth_type     = enroll.conf.addr_auth_type;
        config.has_routing_type   = true;
        config.routing_type       = enroll.conf.routing_type;
        config.has_pff_type       = true;
        config.pff_type           = enroll.conf.pff_type;
        config.dif_info           = &dif_info;

        dif_info.dif_name      = (char *) enroll.conf.dif_info.dif_name;
        dif_info.dir_hash_algo = enroll.conf.dif_info.dir_hash_algo;

        len = enroll_msg__get_packed_size(&msg);

        *buf = malloc(len);
        if (*buf == NULL)
                return -1;

        enroll_msg__pack(&msg, *buf);

        return len;
}

static void * enroll_handle(void * o)
{
        struct conn    conn;
        uint8_t        buf[ENROLL_BUF_LEN];
        uint8_t *      reply;
        ssize_t        len;
        enroll_msg_t * msg;

        (void) o;

        while (true) {
                if (connmgr_wait(AEID_ENROLL, &conn)) {
                        log_err("Failed to get next connection.");
                        continue;
                }

                len = flow_read(conn.flow_info.fd, buf, ENROLL_BUF_LEN);
                if (len < 0) {
                        log_err("Failed to read from flow.");
                        connmgr_dealloc(AEID_ENROLL, &conn);
                        continue;
                }

                msg = enroll_msg__unpack(NULL, len, buf);
                if (msg == NULL) {
                        log_err("Failed to unpack message.");
                        connmgr_dealloc(AEID_ENROLL, &conn);
                        continue;
                }

                if (msg->code != ENROLL_CODE__ENROLL_REQ) {
                        log_err("Wrong message type.");
                        connmgr_dealloc(AEID_ENROLL, &conn);
                        enroll_msg__free_unpacked(msg, NULL);
                        continue;
                }

                log_dbg("Enrolling a new neighbor.");

                enroll_msg__free_unpacked(msg, NULL);

                len = enroll_pack(&reply);
                if (reply == NULL) {
                        log_err("Failed to pack enrollment message.");
                        connmgr_dealloc(AEID_ENROLL, &conn);
                        continue;
                }

                log_dbg("Sending enrollment info (%zd bytes).", len);

                if (flow_write(conn.flow_info.fd, reply, len)) {
                        log_err("Failed respond to enrollment request.");
                        connmgr_dealloc(AEID_ENROLL, &conn);
                        free(reply);
                        continue;
                }

                free(reply);

                len = flow_read(conn.flow_info.fd, buf, ENROLL_BUF_LEN);
                if (len < 0) {
                        log_err("Failed to read from flow.");
                        connmgr_dealloc(AEID_ENROLL, &conn);
                        continue;
                }

                msg = enroll_msg__unpack(NULL, len, buf);
                if (msg == NULL) {
                        log_err("Failed to unpack message.");
                        connmgr_dealloc(AEID_ENROLL, &conn);
                        continue;
                }

                if (msg->code != ENROLL_CODE__ENROLL_DONE || !msg->has_result) {
                        log_err("Wrong message type.");
                        enroll_msg__free_unpacked(msg, NULL);
                        connmgr_dealloc(AEID_ENROLL, &conn);
                        continue;
                }

                if (msg->result == 0)
                        log_dbg("Neighbor enrollment successful.");
                else
                        log_dbg("Neigbor reported failed enrollment.");

                enroll_msg__free_unpacked(msg, NULL);

                connmgr_dealloc(AEID_ENROLL, &conn);
        }

        return 0;
}

int enroll_boot(struct conn * conn)
{
        log_dbg("Getting boot information.");

        if (send_rcv_enroll_msg(conn->flow_info.fd)) {
                log_err("Failed to enroll.");
                return -1;
        }

        return 0;
}

int enroll_done(struct conn * conn,
                int           result)
{
        enroll_msg_t msg = ENROLL_MSG__INIT;
        uint8_t      buf[ENROLL_BUF_LEN];
        ssize_t       len;

        msg.code       = ENROLL_CODE__ENROLL_DONE;
        msg.has_result = true;
        msg.result     = result;

        len = enroll_msg__get_packed_size(&msg);
        if (len < 0) {
                log_dbg("Failed pack request message.");
                return -1;
        }

        enroll_msg__pack(&msg, buf);

        if (flow_write(conn->flow_info.fd, buf, len)) {
                log_dbg("Failed to send acknowledgment.");
                return -1;
        }

        return 0;
}

void enroll_bootstrap(const struct ipcp_config * conf)
{
        assert(conf);

        memcpy(&enroll.conf, conf, sizeof(enroll.conf));
}

struct ipcp_config * enroll_get_conf(void)
{
        return &enroll.conf;
}

int enroll_init(void)
{
        struct conn_info info;

        memset(&info, 0, sizeof(info));

        strcpy(info.ae_name, ENROLL_AE);
        strcpy(info.protocol, ENROLL_PROTO);
        info.pref_version = 1;
        info.pref_syntax  = PROTO_GPB;
        info.addr         = 0;

        if (connmgr_ae_init(AEID_ENROLL, &info)) {
                log_err("Failed to register with connmgr.");
                return -1;
        }

        enroll.state = ENROLL_INIT;

        return 0;
}

void enroll_fini(void)
{
        if (enroll.state == ENROLL_RUNNING)
                pthread_join(enroll.listener, NULL);

        connmgr_ae_fini(AEID_ENROLL);
}

int enroll_start(void)
{
        if (pthread_create(&enroll.listener, NULL, enroll_handle, NULL))
                return -1;

        enroll.state = ENROLL_RUNNING;

        return 0;
}

void enroll_stop(void)
{
        if (enroll.state == ENROLL_RUNNING)
                pthread_cancel(enroll.listener);
}
