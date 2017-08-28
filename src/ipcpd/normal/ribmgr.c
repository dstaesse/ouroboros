/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * RIB manager of the IPC Process
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

#define _POSIX_C_SOURCE 200112L

#define OUROBOROS_PREFIX "rib-manager"

#include <ouroboros/logs.h>
#include <ouroboros/cdap.h>
#include <ouroboros/list.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/rib.h>

#include "ae.h"
#include "connmgr.h"
#include "ipcp.h"
#include "neighbors.h"
#include "ribconfig.h"
#include "ribmgr.h"

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define MGMT_AE          "Management"
#define RIB_SYNC_TIMEOUT 1

enum ribmgr_state {
        RIBMGR_NULL = 0,
        RIBMGR_INIT,
        RIBMGR_OPERATIONAL,
        RIBMGR_SHUTDOWN
};

struct {
        struct cdap *      cdap;

        pthread_t          reader;
        pthread_t          sync;

        struct nbs *       nbs;
        struct ae *        ae;

        struct nb_notifier nb_notifier;

        pthread_rwlock_t   state_lock;
        enum ribmgr_state  state;
} ribmgr;

static int ribmgr_neighbor_event(enum nb_event event,
                                 struct conn   conn)
{
        switch (event) {
        case NEIGHBOR_ADDED:
                cdap_add_flow(ribmgr.cdap, conn.flow_info.fd);
                break;
        case NEIGHBOR_REMOVED:
                cdap_del_flow(ribmgr.cdap, conn.flow_info.fd);
                break;
        default:
                /* Don't care about other events */
                break;
        }

        return 0;
}

static enum ribmgr_state ribmgr_get_state(void)
{
        enum ribmgr_state state;

        pthread_rwlock_rdlock(&ribmgr.state_lock);

        state = ribmgr.state;

        pthread_rwlock_unlock(&ribmgr.state_lock);

        return state;
}

static void ribmgr_set_state(enum ribmgr_state state)
{
        pthread_rwlock_wrlock(&ribmgr.state_lock);

        ribmgr.state = state;

        pthread_rwlock_unlock(&ribmgr.state_lock);
}

static void * reader(void * o)
{
        cdap_key_t       key;
        enum cdap_opcode oc;
        char *           name;
        uint8_t *        data;
        size_t           len;
        ssize_t          slen;
        uint32_t         flags;
        uint8_t *        buf;
        int              rval;

        (void) o;

        while (ribmgr_get_state() == RIBMGR_OPERATIONAL) {
                key = cdap_request_wait(ribmgr.cdap, &oc, &name, &data,
                                        (size_t *) &len , &flags);
                assert(key != -EINVAL);

                if (key == INVALID_CDAP_KEY) {
                        log_warn("Bad CDAP request.");
                        continue;
                }

                assert(name);
                assert(strlen(name));

                switch (oc) {
                case CDAP_READ:
                        assert(len == 0);
                        slen = rib_pack(name, &buf, PACK_HASH_ROOT);
                        if (slen < 0) {
                                log_err("Failed to pack %s.", name);
                                cdap_reply_send(ribmgr.cdap, key, -1, NULL, 0);
                                free(name);
                                continue;
                        }

                        log_dbg("Packed %s (%zu bytes).", name, slen);

                        free(name);

                        if (cdap_reply_send(ribmgr.cdap, key, 0, buf, slen)) {
                                log_err("Failed to send CDAP reply.");
                                free(buf);
                                continue;
                        }

                        free(buf);
                        break;
                case CDAP_WRITE:
                        assert(len);
                        assert(data);

                        rval = rib_unpack(data, len, 0);
                        switch(rval) {
                        case 0:
                                break;
                        case -EFAULT:
                                log_warn("Hash mismatch, not in sync.");
                                free(data);
                                break;
                        default:
                                log_warn("Error unpacking %s.", name);
                                cdap_reply_send(ribmgr.cdap, key, -1, NULL, 0);
                                free(name);
                                free(data);
                                continue;
                        }

                        free(name);

                        if (cdap_reply_send(ribmgr.cdap, key, 0, NULL, 0)) {
                                log_err("Failed to send CDAP reply.");
                                continue;
                        }
                        break;
                case CDAP_CREATE:
                        assert(len);
                        assert(data);

                        rval = rib_unpack(data, len, UNPACK_CREATE);
                        switch(rval) {
                        case 0:
                                break;
                        case -EFAULT:
                                log_warn("Hash mismatch, not yet in sync.");
                                free(data);
                                break;
                        default:
                                log_warn("Error unpacking %s.", name);
                                cdap_reply_send(ribmgr.cdap, key, -1, NULL, 0);
                                free(name);
                                free(data);
                                continue;
                        }

                        free(name);

                        if (cdap_reply_send(ribmgr.cdap, key, 0, NULL, 0)) {
                                log_err("Failed to send CDAP reply.");
                                continue;
                        }
                        break;
                case CDAP_DELETE:
                        assert(len == 0);
                        if (rib_del(name)) {
                                log_warn("Failed deleting %s.", name);
                                cdap_reply_send(ribmgr.cdap, key, -1, NULL, 0);
                        }

                        free(name);

                        if (cdap_reply_send(ribmgr.cdap, key, 0, NULL, 0)) {
                                log_err("Failed to send CDAP reply.");
                                continue;
                        }
                        break;
                case CDAP_START:
                case CDAP_STOP:
                        log_warn("Unsupported CDAP command.");
                        if (len)
                                free(data);
                        break;
                default:
                        log_err("Bad CDAP command.");
                        if (len)
                                free(data);
                        break;
                }
        }

        return (void *) 0;
}

char path[RIB_MAX_PATH_LEN + 1];

static void path_reset(void) {
        path[strlen(RIB_ROOT)] = '\0';
        assert(strcmp(path, RIB_ROOT) == 0);
}

static int ribmgr_sync(const char * path)
{
        uint8_t *    buf;
        ssize_t      len;
        cdap_key_t * keys;

        len = rib_pack(path, &buf, PACK_HASH_ALL);
        if (len < 0) {
                log_warn("Failed to pack %s.", path);
                return -1;
        }

        keys = cdap_request_send(ribmgr.cdap, CDAP_CREATE, path, buf, len, 0);
        if (keys != NULL) {
                cdap_key_t * key = keys;
                while (*key != INVALID_CDAP_KEY)
                        cdap_reply_wait(ribmgr.cdap, *(key++), NULL, NULL);
                free(keys);
        }

        free(buf);

        return 0;
}

/* FIXME: Temporary thread, syncs rib with neighbors every second */
static void * sync_rib(void *o)
{
        char ** children;
        ssize_t ch;

        (void) o;

        strcpy(path, RIB_ROOT);

        while (ribmgr_get_state() == RIBMGR_OPERATIONAL) {
                sleep(RIB_SYNC_TIMEOUT);

                ch = rib_children(RIB_ROOT, &children);
                if (ch <= 0)
                        continue;

                while (ch > 0) {
                        path_reset();

                        rib_path_append(path, children[--ch]);
                        free(children[ch]);

                        /* Sync fsdb */
                        if (strcmp(path, ROUTING_PATH) == 0)
                                ribmgr_sync(path);
                }

                free(children);
        }

        return (void *) 0;
}

int ribmgr_init(void)
{
        struct conn_info info;

        memset(&info, 0, sizeof(info));

        strcpy(info.ae_name, MGMT_AE);
        strcpy(info.protocol, CDAP_PROTO);
        info.pref_version = 1;
        info.pref_syntax = PROTO_GPB;
        info.addr = 0;

        ribmgr.nbs = nbs_create();
        if (ribmgr.nbs == NULL) {
                log_err("Failed to create neighbors.");
                goto fail_nbs_create;
        }

        if (connmgr_ae_init(AEID_MGMT, &info, ribmgr.nbs)) {
                log_err("Failed to register with connmgr.");
                goto fail_connmgr_ae_init;
        };

        ribmgr.cdap = cdap_create();
        if (ribmgr.cdap == NULL) {
                log_err("Failed to create CDAP instance.");
                goto fail_cdap_create;
        }

        ribmgr.nb_notifier.notify_call = ribmgr_neighbor_event;
        if (nbs_reg_notifier(ribmgr.nbs, &ribmgr.nb_notifier)) {
                log_err("Failed to register notifier.");
                goto fail_nbs_reg_notifier;
        }

        if (pthread_rwlock_init(&ribmgr.state_lock, NULL)) {
                log_err("Failed to init rwlock.");
                goto fail_rwlock_init;
        }

        ribmgr.state = RIBMGR_INIT;

        return 0;

 fail_rwlock_init:
        nbs_unreg_notifier(ribmgr.nbs, &ribmgr.nb_notifier);
 fail_nbs_reg_notifier:
        cdap_destroy(ribmgr.cdap);
 fail_cdap_create:
        connmgr_ae_fini(AEID_MGMT);
 fail_connmgr_ae_init:
        nbs_destroy(ribmgr.nbs);
 fail_nbs_create:
        return -1;
}

void ribmgr_fini(void)
{
        if (ribmgr_get_state() == RIBMGR_SHUTDOWN) {
                pthread_join(ribmgr.reader, NULL);
                pthread_join(ribmgr.sync, NULL);
        }

        nbs_unreg_notifier(ribmgr.nbs, &ribmgr.nb_notifier);
        cdap_destroy(ribmgr.cdap);
        nbs_destroy(ribmgr.nbs);

        connmgr_ae_fini(AEID_MGMT);
}

int ribmgr_start(void)
{
        ribmgr_set_state(RIBMGR_OPERATIONAL);

        if (pthread_create(&ribmgr.sync, NULL, sync_rib, NULL)) {
                ribmgr_set_state(RIBMGR_NULL);
                return -1;
        }

        if (pthread_create(&ribmgr.reader, NULL, reader, NULL)) {
                ribmgr_set_state(RIBMGR_SHUTDOWN);
                pthread_cancel(ribmgr.reader);
                return -1;
        }

        return 0;
}

void ribmgr_stop(void)
{
        if (ribmgr_get_state() == RIBMGR_OPERATIONAL) {
                ribmgr_set_state(RIBMGR_SHUTDOWN);
                pthread_cancel(ribmgr.reader);
        }
}

int ribmgr_disseminate(char *           path,
                       enum diss_target target,
                       enum diss_freq   freq,
                       size_t           delay)
{
        (void) path;
        (void) target;
        (void) freq;
        (void) delay;

        return 0;
}
