/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * OAP - Authentication, replay detection, and validation
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
 #define _POSIX_C_SOURCE 200809L
#endif

#define OUROBOROS_PREFIX "irmd/oap"

#include <ouroboros/crypt.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/logs.h>
#include <ouroboros/pthread.h>
#include <ouroboros/time.h>

#include "config.h"

#include "auth.h"
#include "hdr.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct oap_replay_entry {
        struct list_head next;
        uint64_t         timestamp;
        uint8_t          id[OAP_ID_SIZE];
};

static struct {
        struct auth_ctx * ca_ctx;
        struct {
                struct list_head list;
                pthread_mutex_t  mtx;
        } replay;
} oap_auth;

int oap_auth_init(void)
{
        oap_auth.ca_ctx = auth_create_ctx();
        if (oap_auth.ca_ctx == NULL) {
                log_err("Failed to create OAP auth context.");
                goto fail_ctx;
        }

        list_head_init(&oap_auth.replay.list);

        if (pthread_mutex_init(&oap_auth.replay.mtx, NULL)) {
                log_err("Failed to init OAP replay mutex.");
                goto fail_mtx;
        }

        return 0;

 fail_mtx:
        auth_destroy_ctx(oap_auth.ca_ctx);
 fail_ctx:
        return -1;
}

void oap_auth_fini(void)
{
        struct list_head * p;
        struct list_head * h;

        pthread_mutex_lock(&oap_auth.replay.mtx);

        list_for_each_safe(p, h, &oap_auth.replay.list) {
                struct oap_replay_entry * e;
                e = list_entry(p, struct oap_replay_entry, next);
                list_del(&e->next);
                free(e);
        }

        pthread_mutex_unlock(&oap_auth.replay.mtx);
        pthread_mutex_destroy(&oap_auth.replay.mtx);

        auth_destroy_ctx(oap_auth.ca_ctx);
}

int oap_auth_add_ca_crt(void * crt)
{
        return auth_add_crt_to_store(oap_auth.ca_ctx, crt);
}

#define TIMESYNC_SLACK 100 /* ms */
#define ID_IS_EQUAL(id1, id2) (memcmp(id1, id2, OAP_ID_SIZE) == 0)
int oap_check_hdr(const struct oap_hdr * hdr)
{
        struct list_head *        p;
        struct list_head *        h;
        struct timespec           now;
        struct oap_replay_entry * new;
        uint64_t                  stamp;
        uint64_t                  cur;
        uint8_t *                 id;
        ssize_t                   delta;

        assert(hdr != NULL);

        stamp = hdr->timestamp;
        id    = hdr->id.data;

        clock_gettime(CLOCK_REALTIME, &now);

        cur = TS_TO_UINT64(now);

        delta = (ssize_t)(cur - stamp) / MILLION;
        if (delta < -TIMESYNC_SLACK) {
                log_err_id(id, "OAP header from %zd ms into future.", -delta);
                goto fail_stamp;
        }

        if (delta > OAP_REPLAY_TIMER * 1000) {
                log_err_id(id, "OAP header too old (%zd ms).", delta);
                goto fail_stamp;
        }

        new = malloc(sizeof(*new));
        if (new == NULL) {
                log_err_id(id, "Failed to allocate memory for OAP element.");
                goto fail_stamp;
        }

        pthread_mutex_lock(&oap_auth.replay.mtx);

        list_for_each_safe(p, h, &oap_auth.replay.list) {
                struct oap_replay_entry * e;
                e = list_entry(p, struct oap_replay_entry, next);
                if (cur > e->timestamp + OAP_REPLAY_TIMER * BILLION) {
                        list_del(&e->next);
                        free(e);
                        continue;
                }

                if (e->timestamp == stamp && ID_IS_EQUAL(e->id, id)) {
                        log_warn_id(id, "OAP header already known.");
                        goto fail_replay;
                }
        }

        memcpy(new->id, id, OAP_ID_SIZE);
        new->timestamp = stamp;

        list_add_tail(&new->next, &oap_auth.replay.list);

        pthread_mutex_unlock(&oap_auth.replay.mtx);

        return 0;

 fail_replay:
        pthread_mutex_unlock(&oap_auth.replay.mtx);
        free(new);
 fail_stamp:
        return -EAUTH;
}

int oap_auth_peer(char *                 name,
                  const struct oap_hdr * local_hdr,
                  const struct oap_hdr * peer_hdr)
{
        void *     crt;
        void *     pk;
        buffer_t   sign; /* Signed region */
        uint8_t *  id = peer_hdr->id.data;

        assert(name != NULL);
        assert(local_hdr != NULL);
        assert(peer_hdr != NULL);

        if (memcmp(peer_hdr->id.data, local_hdr->id.data, OAP_ID_SIZE) != 0) {
                log_err_id(id, "OAP ID mismatch in flow allocation.");
                goto fail_check;
        }

        if (peer_hdr->crt.len == 0) {
                log_dbg_id(id, "No crt provided.");
                name[0] = '\0';
                return 0;
        }

        if (crypt_load_crt_der(peer_hdr->crt, &crt) < 0) {
                log_err_id(id, "Failed to load crt.");
                goto fail_check;
        }

        log_dbg_id(id, "Loaded peer crt.");

        if (crypt_get_pubkey_crt(crt, &pk) < 0) {
                log_err_id(id, "Failed to get pubkey from crt.");
                goto fail_crt;
        }

        log_dbg_id(id, "Got public key from crt.");

        if (auth_verify_crt(oap_auth.ca_ctx, crt) < 0) {
                log_err_id(id, "Failed to verify peer with CA store.");
                goto fail_crt;
        }

        log_dbg_id(id, "Successfully verified peer crt.");

        sign = peer_hdr->hdr;
        sign.len -= peer_hdr->sig.len;

        if (auth_verify_sig(pk, peer_hdr->md_nid, sign, peer_hdr->sig) < 0) {
                log_err_id(id, "Failed to verify signature.");
                goto fail_check_sig;
        }

        if (crypt_get_crt_name(crt, name) < 0) {
                log_warn_id(id, "Failed to extract name from certificate.");
                name[0] = '\0';
        }

        crypt_free_key(pk);
        crypt_free_crt(crt);

        log_dbg_id(id, "Successfully authenticated peer.");

        return 0;

 fail_check_sig:
        crypt_free_key(pk);
 fail_crt:
        crypt_free_crt(crt);
 fail_check:
        return -EAUTH;
}
