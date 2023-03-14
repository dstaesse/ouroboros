/*
 * Ouroboros - Copyright (C) 2016 - 2023
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

#include <ouroboros/endian.h>
#include <ouroboros/errno.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/errno.h>
#include <ouroboros/serdes-oep.h>

#include "common/connmgr.h"
#include "common/enroll.h"
#include "ipcp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

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

static int send_rcv_enroll_msg(int fd)
{
        uint8_t            __buf[ENROLL_BUF_LEN];
        buffer_t           buf;
        buffer_t           msg;
        ssize_t            len;
        ssize_t            delta_t;
        struct timespec    t0;
        struct timespec    rtt;
        int                ret;
        struct enroll_resp resp;

        buf.data = __buf;
        buf.len  = sizeof(__buf);

        len = enroll_req_ser(buf);
        if (len < 0) {
                log_dbg("Failed to pack request message.");
                return -1;
        }

        clock_gettime(CLOCK_REALTIME, &t0);

        log_dbg("Sending request message.");

        if (flow_write(fd, buf.data, len) < 0) {
                log_dbg("Failed to send request message.");
                return -1;
        }

        log_dbg("Waiting for reply message.");

        len = flow_read(fd, buf.data, buf.len);
        if (len < 0) {
                log_dbg("No reply received.");
                return -1;
        }

        log_dbg("Received configuration info (%zd bytes).", len);

        msg.data = buf.data;
        msg.len  = len;

        ret = enroll_resp_des(&resp, msg);
        if (ret < 0) {
                log_dbg("Failed to unpack response message.");
                return -1;
        }

        if (resp.response < 0) {
                log_dbg("Remote denied request: %d.", resp.response);
                return -1;
        }

        if (resp.conf.type != ipcpi.type) {
                log_dbg("Wrong type in enrollment response %d (%d).",
                        resp.conf.type, ipcpi.type);
                return -1;
        }

        clock_gettime(CLOCK_REALTIME, &rtt);

        delta_t = ts_diff_ms(&t0, &rtt);

        rtt.tv_sec  = resp.t.tv_sec;
        rtt.tv_nsec = resp.t.tv_nsec;

        if (labs(ts_diff_ms(&t0, &rtt)) - delta_t > ENROLL_WARN_TIME_OFFSET)
                log_warn("Clock offset above threshold.");

        enroll.conf = resp.conf;

        return 0;
}


static void * enroll_handle(void * o)
{
        struct enroll_resp resp;
        struct conn        conn;
        uint8_t             __buf[ENROLL_BUF_LEN];
        buffer_t           buf;
        ssize_t            len;
        int                response;

        (void) o;

        buf.data = __buf;
        buf.len  = sizeof(__buf);

        resp.conf = enroll.conf;

        while (true) {
                buffer_t msg;

                if (connmgr_wait(COMPID_ENROLL, &conn)) {
                        log_err("Failed to get next connection.");
                        continue;
                }

                log_info("New enrollment connection.");

                len = flow_read(conn.flow_info.fd, buf.data, buf.len);
                if (len < 0) {
                        log_err("Failed to read from flow.");
                        connmgr_dealloc(COMPID_ENROLL, &conn);
                        continue;
                }

                log_dbg("Read request from flow (%zd bytes).", len);
                msg.data = buf.data;
                msg.len = (size_t) len;

                if (enroll_req_des(msg) < 0) {
                        log_err("Failed to unpack request message.");
                        connmgr_dealloc(COMPID_ENROLL, &conn);
                        continue;
                }

                /* TODO: authentication */

                log_dbg("Enrolling a new neighbor.");

                clock_gettime(CLOCK_REALTIME, &resp.t);

                resp.response = 0;

                len = enroll_resp_ser(&resp, buf);
                if (len < 0) {
                        log_err("Failed to pack reply.");
                        connmgr_dealloc(COMPID_ENROLL, &conn);
                        continue;
                }

                log_dbg("Sending enrollment info (%zd bytes).", len);

                if (flow_write(conn.flow_info.fd, buf.data, len) < 0) {
                        log_err("Failed respond to request.");
                        connmgr_dealloc(COMPID_ENROLL, &conn);
                        continue;
                }

                len = flow_read(conn.flow_info.fd, buf.data, buf.len);
                if (len < 0) {
                        log_err("Failed to read from flow.");
                        connmgr_dealloc(COMPID_ENROLL, &conn);
                        continue;
                }

                msg.data = buf.data;
                msg.len = (size_t) len;

                if (enroll_ack_des(&response, msg) < 0) {
                        log_err("Failed to unpack acknowledgment.");
                        connmgr_dealloc(COMPID_ENROLL, &conn);
                        continue;
                }
                if (response == 0)
                        log_info("Neighbor enrollment successful.");
                else
                        log_info("Neigbor enrolment failed at remote.");

                connmgr_dealloc(COMPID_ENROLL, &conn);

                log_info("Enrollment connection closed.");
        }

        return 0;
}

int enroll_boot(struct conn * conn)
{
        log_dbg("Starting enrollment.");

        if (send_rcv_enroll_msg(conn->flow_info.fd)) {
                log_err("Failed to enroll.");
                return -1;
        }

        log_dbg("Enrollment complete.");

        return 0;
}

int enroll_ack(struct conn * conn,
                int          result)
{
        uint8_t            __buf[ENROLL_BUF_LEN];
        buffer_t           buf;
        ssize_t            len;

        buf.data = __buf;
        buf.len  = sizeof(__buf);

        len = enroll_ack_ser(result, buf);
        if (len < 0) {
                log_err("Failed to pack acknowledgement.");
                return -1;
        }

        if (flow_write(conn->flow_info.fd, buf.data, len) < 0) {
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
