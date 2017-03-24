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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "rib-manager"

#include <ouroboros/config.h>
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
#include "gam.h"
#include "ribconfig.h"
#include "ribmgr.h"

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define RIB_SYNC_TIMEOUT 1

enum ribmgr_state {
        RIBMGR_NULL = 0,
        RIBMGR_OPERATIONAL,
        RIBMGR_SHUTDOWN
};

struct {
        struct cdap *      cdap;

        pthread_t          reader;
        pthread_t          sync;

        struct gam *       gam;
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

                        /* Only sync fsdb, members and directory */
                        if (strcmp(path, MEMBERS_PATH) == 0
                            || strcmp(path, DIR_PATH) == 0
                            || strcmp(path, ROUTING_PATH) == 0)
                                ribmgr_sync(path);
                }

                free(children);
        }

        return (void *) 0;
}

int ribmgr_init(void)
{
        enum pol_gam     pg;
        struct conn_info info;

        memset(&info, 0, sizeof(info));

        strcpy(info.ae_name, MGMT_AE);
        strcpy(info.protocol, CDAP_PROTO);
        info.pref_version = 1;
        info.pref_syntax = PROTO_GPB;

        ribmgr.nbs = nbs_create();
        if (ribmgr.nbs == NULL) {
                log_err("Failed to create neighbors.");
                return -1;
        }

        ribmgr.ae = connmgr_ae_create(info);
        if (ribmgr.ae == NULL) {
                log_err("Failed to create AE struct.");
                nbs_destroy(ribmgr.nbs);
                return -1;
        }

        if (rib_read(BOOT_PATH "/rm/gam/type", &pg, sizeof(pg))
            != sizeof(pg)) {
                log_err("Failed to read policy for ribmgr gam.");
                connmgr_ae_destroy(ribmgr.ae);
                nbs_destroy(ribmgr.nbs);
                return -1;
        }

        ribmgr.gam = gam_create(pg, ribmgr.nbs, ribmgr.ae);
        if (ribmgr.gam == NULL) {
                log_err("Failed to create gam.");
                connmgr_ae_destroy(ribmgr.ae);
                nbs_destroy(ribmgr.nbs);
                return -1;
        }

        ribmgr.cdap = cdap_create();
        if (ribmgr.cdap == NULL) {
                log_err("Failed to create CDAP instance.");
                gam_destroy(ribmgr.gam);
                connmgr_ae_destroy(ribmgr.ae);
                nbs_destroy(ribmgr.nbs);
                return -1;
        }

        ribmgr.nb_notifier.notify_call = ribmgr_neighbor_event;
        if (nbs_reg_notifier(ribmgr.nbs, &ribmgr.nb_notifier)) {
                log_err("Failed to register notifier.");
                cdap_destroy(ribmgr.cdap);
                gam_destroy(ribmgr.gam);
                connmgr_ae_destroy(ribmgr.ae);
                nbs_destroy(ribmgr.nbs);
                return -1;
        }

        pthread_rwlock_init(&ribmgr.state_lock, NULL);

        ribmgr.state = RIBMGR_OPERATIONAL;

        pthread_create(&ribmgr.sync, NULL, sync_rib, NULL);

        pthread_create(&ribmgr.reader, NULL, reader, NULL);

        return 0;
}

void ribmgr_fini(void)
{
        ribmgr_set_state(RIBMGR_SHUTDOWN);

        pthread_cancel(ribmgr.reader);

        pthread_join(ribmgr.reader, NULL);
        pthread_join(ribmgr.sync, NULL);

        nbs_unreg_notifier(ribmgr.nbs, &ribmgr.nb_notifier);
        cdap_destroy(ribmgr.cdap);
        gam_destroy(ribmgr.gam);
        connmgr_ae_destroy(ribmgr.ae);
        nbs_destroy(ribmgr.nbs);
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
