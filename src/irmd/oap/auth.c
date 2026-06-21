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
#include <ouroboros/logs.h>
#include <ouroboros/pthread.h>
#include <ouroboros/time.h>

#include "config.h"

#include "auth.h"
#include "hdr.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/*
 * Replay cache: three timestamp-generation hash buckets. A header's bucket
 * is gen(T) = T / OAP_REPLAY_TIMER, taken mod 3. Staleness bounds a valid T
 * to generations {G-1, G, G+1} (G is now's generation; a within-slack future
 * stamp can reach G+1), which are distinct mod 3; the aliasing generation
 * G-3 is always rejected as too old first. Each bucket is an open-addressed
 * hash set whose slots are live iff slot.gen == bucket.gen, so a stale bucket
 * clears in O(1) by bumping its gen. Overflow fails closed (reject), never
 * evicts, so a flood cannot displace a genuine entry into a replayable state.
 */
#define OAP_REPLAY_GENS 3

struct oap_replay_slot {
        uint64_t gen; /* live iff == bucket gen; 0 = never used */
        uint64_t ts;
        uint8_t  id[OAP_ID_SIZE];
};

struct oap_replay_bucket {
        uint64_t                 gen;
        size_t                   count;
        struct oap_replay_slot * slots;
};

static struct {
        struct auth_ctx * ca_ctx;
        struct {
                size_t                   mask; /* slots per bucket - 1 */
                size_t                   cap;  /* fail-closed threshold */
                struct oap_replay_bucket bucket[OAP_REPLAY_GENS];
                pthread_mutex_t          mtx;
        } replay;
} oap_auth;

/* FNV-1a over id || ts; the table mask reduces it to a slot index. */
static size_t replay_hash(const uint8_t * id,
                          uint64_t        ts)
{
        uint64_t hh = 14695981039346656037ULL;
        size_t   i;

        for (i = 0; i < OAP_ID_SIZE; i++) {
                hh ^= id[i];
                hh *= 1099511628211ULL;
        }

        for (i = 0; i < sizeof(ts); i++) {
                hh ^= (uint8_t) (ts >> (i * 8));
                hh *= 1099511628211ULL;
        }

        return (size_t) hh;
}

int oap_auth_init(void)
{
        size_t m = 1;
        int    i;

        oap_auth.ca_ctx = auth_create_ctx();
        if (oap_auth.ca_ctx == NULL) {
                log_err("Failed to create OAP auth context.");
                goto fail_ctx;
        }

        while (m < (size_t) OAP_REPLAY_MAX * 2)
                m <<= 1;

        oap_auth.replay.mask = m - 1;
        oap_auth.replay.cap  = OAP_REPLAY_MAX;

        for (i = 0; i < OAP_REPLAY_GENS; i++) {
                struct oap_replay_bucket * b = &oap_auth.replay.bucket[i];
                b->gen   = 0;
                b->count = 0;
                b->slots = calloc(m, sizeof(*b->slots));
                if (b->slots == NULL) {
                        log_err("Failed to alloc OAP replay bucket.");
                        goto fail_bucket;
                }
        }

        if (pthread_mutex_init(&oap_auth.replay.mtx, NULL)) {
                log_err("Failed to init OAP replay mutex.");
                goto fail_bucket;
        }

        return 0;

 fail_bucket:
        for (i = 0; i < OAP_REPLAY_GENS; i++)
                free(oap_auth.replay.bucket[i].slots);

        auth_destroy_ctx(oap_auth.ca_ctx);
 fail_ctx:
        return -1;
}

void oap_auth_fini(void)
{
        int i;

        pthread_mutex_lock(&oap_auth.replay.mtx);

        for (i = 0; i < OAP_REPLAY_GENS; i++) {
                free(oap_auth.replay.bucket[i].slots);
                oap_auth.replay.bucket[i].slots = NULL;
        }

        pthread_mutex_unlock(&oap_auth.replay.mtx);
        pthread_mutex_destroy(&oap_auth.replay.mtx);

        auth_destroy_ctx(oap_auth.ca_ctx);
}

int oap_auth_add_ca_crt(void * crt)
{
        return auth_add_crt_to_store(oap_auth.ca_ctx, crt);
}

int oap_auth_add_chain_crt(void * crt)
{
        return auth_add_crt_to_chain(oap_auth.ca_ctx, crt);
}

#define TIMESYNC_SLACK 100 /* ms */
#define ID_IS_EQUAL(id1, id2) (memcmp(id1, id2, OAP_ID_SIZE) == 0)
int oap_check_hdr(const struct oap_hdr * hdr)
{
        struct oap_replay_bucket * b;
        struct oap_replay_slot *   slots;
        struct timespec            now;
        uint64_t                   stamp;
        uint64_t                   cur;
        uint64_t                   gen;
        uint8_t *                  id;
        size_t                     h;
        ssize_t                    delta;
        int                        ret = 0;

        assert(hdr != NULL);

        stamp = hdr->timestamp;
        id    = hdr->id.data;

        clock_gettime(CLOCK_REALTIME, &now);

        cur = TS_TO_UINT64(now);

        delta = (ssize_t)(cur - stamp) / MILLION;
        if (delta < -TIMESYNC_SLACK) {
                log_err_id(id, "OAP header from %zd ms into future.", -delta);
                return -EAUTH;
        }

        if (delta > OAP_REPLAY_TIMER * 1000) {
                log_err_id(id, "OAP header too old (%zd ms).", delta);
                return -EAUTH;
        }

        gen = stamp / ((uint64_t) OAP_REPLAY_TIMER * BILLION);

        pthread_mutex_lock(&oap_auth.replay.mtx);

        b = &oap_auth.replay.bucket[gen % OAP_REPLAY_GENS];

        /* Rotate a stale bucket in O(1): its old-gen slots become free. */
        if (b->gen != gen) {
                b->gen   = gen;
                b->count = 0;
        }

        slots = b->slots;

        h = replay_hash(id, stamp) & oap_auth.replay.mask;
        while (slots[h].gen == gen) {
                if (slots[h].ts == stamp && ID_IS_EQUAL(slots[h].id, id)) {
                        log_warn_id(id, "OAP header already known.");
                        ret = -EREPLAY;
                        goto out;
                }

                h = (h + 1) & oap_auth.replay.mask;
        }

        /* Empty slot found; fail closed when the window is at capacity. */
        if (b->count >= oap_auth.replay.cap) {
                log_warn_id(id, "OAP replay cache full; rejecting.");
                ret = -EAUTH;
                goto out;
        }

        slots[h].gen = gen;
        slots[h].ts  = stamp;
        memcpy(slots[h].id, id, OAP_ID_SIZE);
        b->count++;
 out:
        pthread_mutex_unlock(&oap_auth.replay.mtx);

        return ret;
}

int oap_auth_peer(char *                    name,
                  const struct sec_config * cfg,
                  const struct oap_hdr *    local_hdr,
                  const struct oap_hdr *    peer_hdr)
{
        void *     crt;
        void *     pk  = NULL;
        void *     pin = NULL;
        buffer_t   sign; /* Signed region */
        uint8_t *  id = peer_hdr->id.data;
        int        ret;

        assert(name != NULL);
        assert(cfg != NULL);
        assert(local_hdr != NULL);
        assert(peer_hdr != NULL);

        if (memcmp(peer_hdr->id.data, local_hdr->id.data, OAP_ID_SIZE) != 0) {
                log_err_id(id, "OAP ID mismatch in flow allocation.");
                goto fail_check;
        }

        if (peer_hdr->crt.len == 0) {
                if (cfg->a.req) {
                        log_err_id(id, "Peer did not provide a certificate.");
                        goto fail_check;
                }
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

        if (cfg->a.cacert[0] != '\0' &&
            crypt_load_crt_file(cfg->a.cacert, &pin) < 0) {
                log_err_id(id, "Failed to load pinned CA %s.", cfg->a.cacert);
                goto fail_crt;
        }

        ret = auth_verify_crt_pin(oap_auth.ca_ctx, crt, pin);
        if (ret == -ENOENT) {
                log_err_id(id, "Peer crt not issued by pinned CA %s.",
                           cfg->a.cacert);
                goto fail_pin;
        }

        if (ret < 0) {
                log_err_id(id, "Failed to verify peer with CA store.");
                goto fail_pin;
        }

        log_dbg_id(id, "Successfully verified peer crt.");

        /* Digest pin: peer must sign with the configured digest */
        if (crypt_pk_requires_md(pk) &&
            cfg->d.nid != NID_undef && peer_hdr->md_nid != cfg->d.nid) {
                log_err_id(id, "Peer did not sign with %s.",
                           md_nid_to_str(cfg->d.nid));
                goto fail_pin;
        }

        sign = peer_hdr->hdr;
        sign.len -= peer_hdr->sig.len;

        if (auth_verify_sig(pk, peer_hdr->md_nid, sign, peer_hdr->sig) < 0) {
                log_err_id(id, "Failed to verify signature.");
                goto fail_pin;
        }

        ret = crypt_get_crt_name(crt, name);
        if (ret < 0) {
                if (ret == -ENAME)
                        log_err_id(id, "Certificate CN too long.");
                else
                        log_err_id(id, "No name in certificate.");
                goto fail_pin;
        }

        if (pin != NULL)
                crypt_free_crt(pin);
        crypt_free_key(pk);
        crypt_free_crt(crt);

        log_dbg_id(id, "Successfully authenticated peer.");

        return 0;

 fail_pin:
        if (pin != NULL)
                crypt_free_crt(pin);
 fail_crt:
        crypt_free_key(pk);
        crypt_free_crt(crt);
 fail_check:
        return -EAUTH;
}
