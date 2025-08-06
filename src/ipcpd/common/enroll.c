/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Enrollment Task
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 199309L
#endif

#define OUROBOROS_PREFIX "enrollment"

#include <ouroboros/dev.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/serdes-oep.h>
#include <ouroboros/time.h>

#include "common/connmgr.h"
#include "common/enroll.h"
#include "ipcp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#ifdef __APPLE__
#define llabs labs
#endif

#define ENROLL_COMP             "Enrollment"
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

#ifdef DEBUG_PROTO_OEP


#endif



static void * enroll_handle(void * o)
{
        struct enroll_req  req;
        struct enroll_resp resp;
        struct enroll_ack  ack;
        struct conn        conn;
        uint8_t             __buf[ENROLL_BUF_LEN];
        buffer_t           buf;
        ssize_t            len;

        (void) o;

        buf.data = __buf;
        buf.len  = sizeof(__buf);

        resp.response = 0;
        resp.conf = enroll.conf;

        while (true) {
                buffer_t msg;
                int      fd;

                if (connmgr_wait(COMPID_ENROLL, &conn)) {
                        log_err("Failed to get next connection.");
                        continue;
                }

                fd = conn.flow_info.fd;

                log_info("Incoming enrollment connection on flow %d.", fd);

                len = flow_read(fd, buf.data, buf.len);
                if (len < 0) {
                        log_err("Failed to read from flow %d.", fd);
                        goto finish_flow;
                }

                msg.data = buf.data;
                msg.len = (size_t) len;

                if (enroll_req_des(&req, msg) < 0) {
                        log_err("Failed to unpack request message.");
                        goto finish_flow;
                }

                log_info_id(req.id, "Handling incoming enrollment.");

                ack.result = -100;

                clock_gettime(CLOCK_REALTIME, &resp.t);

                memcpy(resp.id, req.id, ENROLL_ID_LEN);

                len = enroll_resp_ser(&resp, buf);
                if (len < 0) {
                        log_err_id(req.id, "Failed to pack reply.");
                        goto finish_enroll;
                }

                log_dbg_id(req.id, "Sending enrollment info (%zd bytes).", len);

                if (flow_write(conn.flow_info.fd, buf.data, len) < 0) {
                        log_err_id(req.id, "Failed te send response.");
                        goto finish_enroll;
                }

                len = flow_read(conn.flow_info.fd, buf.data, buf.len);
                if (len < 0) {
                        log_err_id(req.id, "Failed to read from flow.");
                        goto finish_enroll;
                }

                msg.data = buf.data;
                msg.len = (size_t) len;

                if (enroll_ack_des(&ack, msg) < 0) {
                        log_err_id(req.id, "Failed to unpack ack.");
                        goto finish_enroll;
                }

                if (memcmp(req.id, ack.id, ENROLL_ID_LEN) != 0)
                       log_warn_id(req.id, "Enrollment ID mismatch.");

         finish_enroll:
                switch(ack.result) {
                case 0:
                        log_info_id(req.id, "Enrollment completed.");
                        break;
                case -100:
                        log_warn_id(req.id, "Enrollment failed.");
                        break;
                default:
                        log_warn_id(req.id, "Enrollment failed at remote.");
                }
         finish_flow:
                connmgr_dealloc(COMPID_ENROLL, &conn);

                log_info("Enrollment flow %d closed.", fd);
        }

        return 0;
}

int enroll_boot(struct conn *   conn,
                const uint8_t * id)
{
        uint8_t            __buf[ENROLL_BUF_LEN];
        buffer_t           buf;
        buffer_t           msg;
        ssize_t            len;
        ssize_t            delta_t;
        struct timespec    t0;
        struct timespec    rtt;
        int                fd;
        int                ret;
        struct enroll_req  req;
        struct enroll_resp resp;

        fd = conn->flow_info.fd;

        buf.data = __buf;
        buf.len  = sizeof(__buf);

        memcpy(req.id, id, ENROLL_ID_LEN);

        len = enroll_req_ser(&req, buf);
        if (len < 0) {
                log_err_id(id, "Failed to pack request message.");
                return -1;
        }

        clock_gettime(CLOCK_REALTIME, &t0);

        if (flow_write(fd, buf.data, len) < 0) {
                log_err_id(id, "Failed to send request message.");
                return -1;
        }

        len = flow_read(fd, buf.data, buf.len);
        if (len < 0) {
                log_err_id(id, "No reply received.");
                return -1;
        }

        log_dbg_id(id, "Received configuration info (%zd bytes).", len);

        msg.data = buf.data;
        msg.len  = len;

        ret = enroll_resp_des(&resp, msg);
        if (ret < 0) {
                log_err_id(id, "Failed to unpack response message.");
                return -1;
        }

        if (memcmp(resp.id, id, ENROLL_ID_LEN) != 0) {
                log_err_id(id, "Enrollment ID mismatch.");
                return -1;
        }

        if (resp.response < 0) {
                log_warn_id(id, "Remote denied request: %d.", resp.response);
                return -1;
        }

        if (resp.conf.type != ipcp_get_type()) {
                log_err_id(id, "Wrong type in enrollment response %d (%d).",
                           resp.conf.type, ipcp_get_type());
                return -1;
        }

        enroll.conf = resp.conf;

        clock_gettime(CLOCK_REALTIME, &rtt);

        delta_t = ts_diff_ms(&t0, &rtt);

        rtt.tv_sec  = resp.t.tv_sec;
        rtt.tv_nsec = resp.t.tv_nsec;

        if (llabs(ts_diff_ms(&t0, &rtt)) - delta_t > ENROLL_WARN_TIME_OFFSET)
                log_warn_id(id, "Clock offset above threshold.");

        return 0;
}

int enroll_ack(struct conn *   conn,
               const uint8_t * id,
               const int       result)
{
        struct enroll_ack ack;
        uint8_t           __buf[ENROLL_BUF_LEN];
        buffer_t          buf;
        ssize_t           len;

        buf.data = __buf;
        buf.len  = sizeof(__buf);

        ack.result = result;

        memcpy(ack.id, id, ENROLL_ID_LEN);

        len = enroll_ack_ser(&ack, buf);
        if (len < 0) {
                log_err_id(id, "Failed to pack acknowledgement.");
                return -1;
        }

        if (flow_write(conn->flow_info.fd, buf.data, len) < 0) {
                log_err_id(id, "Failed to send acknowledgment.");
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

        strcpy(info.comp_name, ENROLL_COMP);
        strcpy(info.protocol, ENROLL_PROTO);
        info.pref_version = 1;
        info.pref_syntax  = PROTO_GPB;
        info.addr         = 0;

        if (connmgr_comp_init(COMPID_ENROLL, &info)) {
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

        connmgr_comp_fini(COMPID_ENROLL);
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
