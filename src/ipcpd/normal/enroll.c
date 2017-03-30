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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */
#define OUROBOROS_PREFIX "enrollment"

#include <ouroboros/config.h>
#include <ouroboros/endian.h>
#include <ouroboros/errno.h>
#include <ouroboros/cdap.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/dev.h>
#include <ouroboros/logs.h>
#include <ouroboros/rib.h>
#include <ouroboros/errno.h>

#include "ae.h"
#include "connmgr.h"
#include "ribconfig.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

/* Symbolic, will return current time */
#define TIME_NAME               "localtime"
#define TIME_PATH               DLR TIME_NAME
#define ENROLL_WARN_TIME_OFFSET 20

struct {
        struct ae *   ae;
        struct cdap * cdap;
        pthread_t     listener;
} enroll;

static void * enroll_handle(void * o)
{
        struct cdap *    cdap;
        struct conn      conn;
        cdap_key_t       key;
        enum cdap_opcode oc;
        char *           name;
        uint8_t *        buf;
        uint8_t *        data;
        ssize_t          len;
        uint32_t         flags;

        bool boot_r     = false;
        bool members_r  = false;
        bool dif_name_r = false;

        char * boot_ro    = BOOT_PATH;
        char * members_ro = MEMBERS_PATH;
        char * dif_ro     = DIF_PATH;

        cdap = (struct cdap *) o;

        assert(cdap);

        while (true) {
                if (connmgr_wait(enroll.ae, &conn)) {
                        log_err("Failed to get next connection.");
                        continue;
                }

                if (cdap_add_flow(cdap, conn.flow_info.fd)) {
                        log_warn("Failed to add flow to CDAP.");
                        flow_dealloc(conn.flow_info.fd);
                        continue;
                }

                while (!(boot_r && members_r && dif_name_r)) {
                        key = cdap_request_wait(cdap, &oc, &name, &data,
                                                (size_t *) &len , &flags);
                        assert(key >= 0);
                        assert(name);

                        if (data != NULL) {
                                free(data);
                                log_warn("Received data with enroll request.");
                        }

                        if (oc != CDAP_READ) {
                                log_warn("Invalid request.");
                                cdap_reply_send(cdap, key, -1, NULL, 0);
                                free(name);
                                continue;
                        }

                        if (strcmp(name, boot_ro) == 0) {
                                boot_r = true;
                        } else if (strcmp(name, members_ro) == 0) {
                                members_r = true;
                        } else if (strcmp(name, dif_ro) == 0) {
                                dif_name_r = true;
                        } else if (strcmp(name, TIME_PATH) == 0) {
                                struct timespec t;
                                uint64_t buf[2];
                                clock_gettime(CLOCK_REALTIME, &t);
                                buf[0] = hton64(t.tv_sec);
                                buf[1] = hton64(t.tv_nsec);
                                cdap_reply_send(cdap, key, 0, buf, sizeof(buf));
                                free(name);
                                continue;
                        } else {
                                log_warn("Illegal read: %s.", name);
                                cdap_reply_send(cdap, key, -1, NULL, 0);
                                free(name);
                                continue;
                        }

                        len = rib_pack(name, &buf, PACK_HASH_ROOT);
                        if (len < 0) {
                                log_err("Failed to pack %s.", name);
                                cdap_reply_send(cdap, key, -1, NULL, 0);
                                free(name);
                                continue;
                        }

                        log_dbg("Packed %s (%zu bytes).", name, len);

                        free(name);

                        if (cdap_reply_send(cdap, key, 0, buf, len)) {
                                log_err("Failed to send CDAP reply.");
                                free(buf);
                                continue;
                        }

                        free(buf);
                }

                log_dbg("Sent boot info to new member.");

                cdap_del_flow(cdap, conn.flow_info.fd);
                flow_dealloc(conn.flow_info.fd);

                boot_r = members_r = dif_name_r = false;
        }

        return 0;
}

int enroll_boot(char * dst_name)
{
        struct cdap * cdap;
        cdap_key_t *  key;
        uint8_t *     data;
        size_t        len;
        struct conn   conn;

        struct timespec t0;
        struct timespec rtt;

        ssize_t delta_t;

        char * boot_ro    = BOOT_PATH;
        char * members_ro = MEMBERS_PATH;
        char * dif_ro     = DIF_PATH;

        cdap = cdap_create();
        if (cdap == NULL) {
                log_err("Failed to instantiate CDAP.");
                return -1;
        }

        if (connmgr_alloc(enroll.ae, dst_name, NULL, &conn)) {
                log_err("Failed to get connection.");
                cdap_destroy(cdap);
                return -1;
        }

        if (cdap_add_flow(cdap, conn.flow_info.fd)) {
                log_warn("Failed to add flow to CDAP.");
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        log_dbg("Getting boot information from %s.", dst_name);

        clock_gettime(CLOCK_REALTIME, &t0);

        key = cdap_request_send(cdap, CDAP_READ, TIME_PATH, NULL, 0, 0);
        if (key == NULL) {
                log_err("Failed to send CDAP request.");
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        if (cdap_reply_wait(cdap, key[0], &data, &len)) {
                log_err("Failed to get CDAP reply.");
                free(key);
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        free(key);

        clock_gettime(CLOCK_REALTIME, &rtt);

        delta_t = ts_diff_ms(&t0, &rtt);

        assert(len == 2 * sizeof (uint64_t));

        rtt.tv_sec  = ntoh64(((uint64_t *) data)[0]);
        rtt.tv_nsec = ntoh64(((uint64_t *) data)[1]);

        if (labs(ts_diff_ms(&t0, &rtt)) - delta_t > ENROLL_WARN_TIME_OFFSET)
                log_warn("Clock offset above threshold.");

        free(data);

        key = cdap_request_send(cdap, CDAP_READ, boot_ro, NULL, 0, 0);
        if (key == NULL) {
                log_err("Failed to send CDAP request.");
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        if (cdap_reply_wait(cdap, key[0], &data, &len)) {
                log_err("Failed to get CDAP reply.");
                free(key);
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        free(key);

        log_dbg("Packed information received (%zu bytes).", len);

        if (rib_unpack(data, len, UNPACK_CREATE)) {
                log_warn("Error unpacking RIB data.");
                rib_del(boot_ro);
                free(data);
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        log_dbg("Packed information inserted into RIB.");

        key = cdap_request_send(cdap, CDAP_READ, members_ro, NULL, 0, 0);
        if (key == NULL) {
                log_err("Failed to send CDAP request.");
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        if (cdap_reply_wait(cdap, key[0], &data, &len)) {
                log_err("Failed to get CDAP reply.");
                free(key);
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        free(key);

        log_dbg("Packed information received (%zu bytes).", len);

        if (rib_unpack(data, len, UNPACK_CREATE)) {
                log_warn("Error unpacking RIB data.");
                rib_del(boot_ro);
                free(data);
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        log_dbg("Packed information inserted into RIB.");

        key = cdap_request_send(cdap, CDAP_READ, dif_ro, NULL, 0, 0);
        if (key == NULL) {
                log_err("Failed to send CDAP request.");
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        if (cdap_reply_wait(cdap, key[0], &data, &len)) {
                log_err("Failed to get CDAP reply.");
                free(key);
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        free(key);

        log_dbg("Packed information received (%zu bytes).", len);

        if (rib_unpack(data, len, UNPACK_CREATE)) {
                log_warn("Error unpacking RIB data.");
                rib_del(boot_ro);
                free(data);
                cdap_destroy(cdap);
                flow_dealloc(conn.flow_info.fd);
                return -1;
        }

        log_dbg("Packed information inserted into RIB.");

        cdap_destroy(cdap);
        flow_dealloc(conn.flow_info.fd);

        return 0;
}

int enroll_init(void)
{
        struct conn_info info;

        enroll.cdap = cdap_create();
        if (enroll.cdap == NULL) {
                log_err("Failed to instantiate CDAP.");
                return -1;
        }

        memset(&info, 0, sizeof(info));

        strcpy(info.ae_name, ENROLL_AE);
        strcpy(info.protocol, CDAP_PROTO);
        info.pref_version = 1;
        info.pref_syntax  = PROTO_GPB;

        enroll.ae = connmgr_ae_create(info);
        if (enroll.ae == NULL) {
                cdap_destroy(enroll.cdap);
                return -1;
        }

        return 0;
}

void enroll_fini(void)
{
        cdap_destroy(enroll.cdap);
        connmgr_ae_destroy(enroll.ae);
}

int enroll_start(void)
{
        if (pthread_create(&enroll.listener, NULL, enroll_handle, enroll.cdap))
                return -1;

        return 0;
}

void enroll_stop(void)
{
        pthread_cancel(enroll.listener);
        pthread_join(enroll.listener, NULL);
}
