/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * OAP - Client-side processing
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
#include <ouroboros/random.h>

#include "config.h"

#include "auth.h"
#include "hdr.h"
#include "io.h"
#include "../oap.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Client context between oap_cli_prepare and oap_cli_complete */
struct oap_cli_ctx {
        uint8_t           __id[OAP_ID_SIZE];
        buffer_t          id;
        char              peer[NAME_SIZE + 1]; /* expected server name */
        uint8_t           kex_buf[OAP_KEX_NIDSZ + CRYPT_KEY_BUFSZ];
        uint8_t           req_hash[MAX_HASH_SIZE];
        size_t            req_hash_len;
        int               req_md_nid;
        struct sec_config scfg;
        struct oap_hdr    local_hdr;
        void *            pkp;     /* Ephemeral keypair    */
        uint8_t *         key;     /* For client-encap KEM */
};

#define OAP_CLI_CTX_INIT(s) \
        do { s->id.len = OAP_ID_SIZE; s->id.data = s->__id; } while (0)

/* Client-side credential loading, mocked in tests */

#ifdef OAP_TEST_MODE
extern int load_cli_credentials(const struct name_info * info,
                                void **                  pkp,
                                void **                  crt);
extern int load_cli_sec_config(const struct name_info * info,
                               struct sec_config *      cfg);
extern int load_server_kem_pk(const char *        name,
                              struct sec_config * cfg,
                              buffer_t *          buf);
#else

int load_cli_credentials(const struct name_info * info,
                         void **                  pkp,
                         void **                  crt)
{
        assert(info != NULL);
        assert(pkp != NULL);
        assert(crt != NULL);

        return load_credentials(info->name, &info->c, pkp, crt);
}

int load_cli_sec_config(const struct name_info * info,
                        struct sec_config *      cfg)
{
        assert(info != NULL);
        assert(cfg != NULL);

        memset(cfg, 0, sizeof(*cfg));

        /* A client authenticates the server by default, like an https client */
        cfg->a.req = OAP_CLIENT_AUTH_DEFAULT;

        return load_sec_config(info->name, info->c.sec, cfg);
}

int load_server_kem_pk(const char *        name,
                       struct sec_config * cfg,
                       buffer_t *          pk)
{
        char         path[PATH_MAX];
        const char * ext;

        assert(name != NULL);
        assert(cfg != NULL);
        assert(pk != NULL);

        ext = IS_HYBRID_KEM_NID(cfg->x.nid) ? "raw" : "pem";

        snprintf(path, sizeof(path),
                 OUROBOROS_CLI_CRT_DIR "/%s/kex.srv.pub.%s", name, ext);

        if (IS_HYBRID_KEM_NID(cfg->x.nid)) {
                if (crypt_load_pubkey_raw_file(path, cfg->x.str, pk) < 0) {
                        log_err("Failed to load %s pubkey from %s.", ext, path);
                        return -1;
                }
        } else {
                if (crypt_load_pubkey_file_to_der(path, pk) < 0) {
                        log_err("Failed to load %s pubkey from %s.", ext, path);
                        return -1;
                }
        }

        log_dbg("Loaded %s pubkey from %s (%zu bytes).", ext, path, pk->len);

        return 0;
}

#endif /* OAP_TEST_MODE */

static int do_client_kex_prepare_dhe(struct oap_cli_ctx * s)
{
        struct sec_config * scfg = &s->scfg;
        buffer_t *          kex  = &s->local_hdr.kex;
        uint8_t *           id   = s->id.data;
        ssize_t             len;

        /* Generate ephemeral keypair, send PK */
        len = kex_pkp_create(scfg, &s->pkp, kex->data);
        if (len < 0) {
                log_err_id(id, "Failed to generate DHE keypair.");
                return -ECRYPT;
        }

        kex->len = (size_t) len;
        log_dbg_id(id, "Generated ephemeral %s keys (%zd bytes).",
                   scfg->x.str, len);

        return 0;
}

static int do_client_kex_prepare_kem_encap(const char *         server_name,
                                           struct oap_cli_ctx * s)
{
        struct sec_config * scfg = &s->scfg;
        buffer_t *          kex  = &s->local_hdr.kex;
        uint8_t *           id   = s->id.data;
        buffer_t            server_pk = BUF_INIT;
        uint8_t             key_buf[SYMMKEYSZ];
        ssize_t             len;

        if (load_server_kem_pk(server_name, scfg, &server_pk) < 0) {
                log_err_id(id, "Failed to load server KEM pk.");
                return -ECRYPT;
        }

        if (IS_HYBRID_KEM_NID(scfg->x.nid)) {
                len = kex_kem_encap_raw(scfg->x.str, server_pk,
                                        kex->data + OAP_KEX_NIDSZ,
                                        scfg->k.nid, key_buf);
                len = oap_kex_tag_nid(kex->data, scfg->x.nid, len);
        } else {
                len = kex_kem_encap(server_pk, kex->data, scfg->k.nid, key_buf);
        }

        freebuf(server_pk);

        if (len < 0) {
                log_err_id(id, "Failed to encapsulate KEM.");
                return -ECRYPT;
        }

        kex->len = (size_t) len;
        log_dbg_id(id, "Client encaps: CT len=%zd.", len);

        /* Store derived key */
        s->key = crypt_secure_malloc(SYMMKEYSZ);
        if (s->key == NULL) {
                log_err_id(id, "Failed to allocate secure key.");
                return -ENOMEM;
        }
        memcpy(s->key, key_buf, SYMMKEYSZ);
        crypt_secure_clear(key_buf, SYMMKEYSZ);

        return 0;
}

static int do_client_kex_prepare_kem_decap(struct oap_cli_ctx * s)
{
        struct sec_config * scfg = &s->scfg;
        buffer_t *          kex  = &s->local_hdr.kex;
        uint8_t *           id   = s->id.data;
        ssize_t             len;

        /* Server encaps: generate keypair, send PK */
        if (IS_HYBRID_KEM_NID(scfg->x.nid)) {
                len = kex_pkp_create(scfg, &s->pkp, kex->data + OAP_KEX_NIDSZ);
                len = oap_kex_tag_nid(kex->data, scfg->x.nid, len);
        } else {
                len = kex_pkp_create(scfg, &s->pkp, kex->data);
        }

        if (len < 0) {
                log_err_id(id, "Failed to generate KEM keypair.");
                return -ECRYPT;
        }

        kex->len = (size_t) len;
        log_dbg_id(id, "Client PK for server encaps (%zd bytes).", len);

        return 0;
}

static int do_client_kex_prepare(const char *         server_name,
                                 struct oap_cli_ctx * s)
{
        struct sec_config * scfg = &s->scfg;

        if (!IS_KEX_ALGO_SET(scfg))
                return 0;

        if (IS_KEM_ALGORITHM(scfg->x.str)) {
                if (scfg->x.mode == KEM_MODE_CLIENT_ENCAP)
                        return do_client_kex_prepare_kem_encap(server_name, s);
                else
                        return do_client_kex_prepare_kem_decap(s);
        }

        return do_client_kex_prepare_dhe(s);
}

int oap_cli_prepare(void **                  ctx,
                    const struct name_info * info,
                    const char *             peer,
                    buffer_t *               req_buf,
                    buffer_t                 data,
                    bool                     rekey)
{
        struct oap_cli_ctx * s;
        void *               pkp = NULL;
        void *               crt = NULL;
        buffer_t             no_tag = BUF_INIT;
        ssize_t              ret;
        int                  enc_flags = 0;

        assert(ctx != NULL);
        assert(info != NULL);
        assert(req_buf != NULL);

        clrbuf(*req_buf);
        *ctx = NULL;

        if (peer != NULL && strlen(peer) > NAME_SIZE) {
                log_err("Peer name too long.");
                return -EINVAL;
        }

        /* Allocate ctx to carry between prepare and complete */
        s = malloc(sizeof(*s));
        if (s == NULL) {
                log_err("Failed to allocate OAP client ctx.");
                return -ENOMEM;
        }

        memset(s, 0, sizeof(*s));
        OAP_CLI_CTX_INIT(s);

        strcpy(s->peer, peer != NULL ? peer : info->name);

        /* Generate session ID */
        if (random_buffer(s->__id, OAP_ID_SIZE) < 0) {
                log_err("Failed to generate OAP session ID.");
                goto fail_id;
        }

        log_dbg_id(s->id.data, "Preparing OAP request for %s.", s->peer);

        /* Load client credentials */
        if (load_cli_credentials(info, &pkp, &crt) < 0) {
                log_err_id(s->id.data, "Failed to load credentials for %s.",
                           info->name);
                goto fail_id;
        }

        /* Load security config */
        if (load_cli_sec_config(info, &s->scfg) < 0) {
                log_err_id(s->id.data, "Failed to load security config for %s.",
                           info->name);
                goto fail_kex;
        }

        /* A re-keyed flow is encrypted; absent config must fail closed. */
        if (rekey && !IS_KEX_ALGO_SET(&s->scfg)) {
                log_err_id(s->id.data, "Refusing re-key without KEX for %s.",
                           info->name);
                goto fail_kex;
        }

        /* Re-key forces server-encap: client-encap forfeits FS/PCS. */
        if (rekey && s->scfg.x.mode == KEM_MODE_CLIENT_ENCAP) {
                s->scfg.x.mode = KEM_MODE_SERVER_ENCAP;
                log_dbg_id(s->id.data, "Re-key forcing ephemeral server KEX.");
        }

        /* Re-key omits the cert; the server verifies against its cache. */
        if (rekey && crt != NULL) {
                crypt_free_crt(crt);
                crt = NULL;
        }

        if (rekey)
                enc_flags = OAP_ENC_REKEY;

        oap_hdr_init(&s->local_hdr, s->id, s->kex_buf, data, s->scfg.c.nid);

        if (do_client_kex_prepare(s->peer, s) < 0) {
                log_err_id(s->id.data, "Failed to prepare client KEX.");
                goto fail_kex;
        }

        if (oap_hdr_encode(&s->local_hdr, pkp, crt, &s->scfg,
                           no_tag, NID_undef, NULL, enc_flags)) {
                log_err_id(s->id.data, "Failed to create OAP request header.");
                goto fail_hdr;
        }

        debug_oap_hdr_snd(&s->local_hdr);

        /* Compute and store hash of request for verification in complete */
        s->req_md_nid = s->scfg.d.nid != NID_undef ? s->scfg.d.nid : NID_sha384;
        ret = md_digest(s->req_md_nid, s->local_hdr.hdr, s->req_hash);
        if (ret < 0) {
                log_err_id(s->id.data, "Failed to hash request.");
                goto fail_hash;
        }
        s->req_hash_len = (size_t) ret;

        /* Transfer ownership of request buffer */
        *req_buf = s->local_hdr.hdr;
        clrbuf(s->local_hdr.hdr);

        /* oap_hdr_encode repoints id into hdr; restore to __id */
        s->local_hdr.id = s->id;

        crypt_free_crt(crt);
        crypt_free_key(pkp);

        *ctx = s;

        log_dbg_id(s->id.data, "OAP request prepared for %s.", info->name);

        return 0;

 fail_hash:
        oap_hdr_fini(&s->local_hdr);
 fail_hdr:
        crypt_secure_free(s->key, SYMMKEYSZ);
        crypt_free_key(s->pkp);
 fail_kex:
        crypt_free_crt(crt);
        crypt_free_key(pkp);
 fail_id:
        free(s);
        return -ECRYPT;
}

void oap_ctx_free(void * ctx)
{
        struct oap_cli_ctx * s = ctx;

        if (s == NULL)
                return;

        oap_hdr_fini(&s->local_hdr);

        if (s->pkp != NULL)
                crypt_free_key(s->pkp);

        if (s->key != NULL)
                crypt_secure_free(s->key, SYMMKEYSZ);

        memset(s, 0, sizeof(*s));
        free(s);
}

static int do_client_kex_complete_kem(struct oap_cli_ctx *   s,
                                      const struct oap_hdr * peer_hdr,
                                      struct crypt_sk *      sk)
{
        struct sec_config * scfg    = &s->scfg;
        uint8_t *           id      = s->id.data;
        uint8_t             key_buf[SYMMKEYSZ];
        buffer_t            ct;

        if (scfg->x.mode == KEM_MODE_CLIENT_ENCAP) {
                /* Key already derived during prepare */
                memcpy(sk->key, s->key, SYMMKEYSZ);
                sk->nid = scfg->c.nid;
                log_info_id(id, "Negotiated %s + %s.", scfg->x.str,
                            scfg->c.str);
                return 0;
        }

        /* KEM_MODE_SERVER_ENCAP */
        if (peer_hdr->kex.len == 0) {
                log_err_id(id, "Server did not send KEM CT.");
                return -ECRYPT;
        }

        ct.data = peer_hdr->kex.data;
        ct.len  = peer_hdr->kex.len;

        if (IS_HYBRID_KEM_NID(scfg->x.nid)) {
                if (oap_kex_strip_nid(&ct, scfg->x.nid) < 0) {
                        log_err_id(id, "KEX algo mismatch in CT.");
                        return -ECRYPT;
                }
        }

        if (kex_kem_decap(s->pkp, ct, scfg->k.nid, key_buf) < 0) {
                log_err_id(id, "Failed to decapsulate KEM.");
                return -ECRYPT;
        }

        log_dbg_id(id, "Client decapsulated server CT.");

        memcpy(sk->key, key_buf, SYMMKEYSZ);
        sk->nid = scfg->c.nid;
        crypt_secure_clear(key_buf, SYMMKEYSZ);

        log_info_id(id, "Negotiated %s + %s.", scfg->x.str, scfg->c.str);

        return 0;
}

static int do_client_kex_complete_dhe(struct oap_cli_ctx *   s,
                                      const struct oap_hdr * peer_hdr,
                                      struct crypt_sk *      sk)
{
        struct sec_config * scfg    = &s->scfg;
        uint8_t *           id      = s->id.data;
        uint8_t             key_buf[SYMMKEYSZ];

        /* DHE: derive from server's public key */
        if (peer_hdr->kex.len == 0) {
                log_err_id(id, "Server did not send DHE public key.");
                return -ECRYPT;
        }

        if (kex_dhe_derive(scfg, s->pkp, peer_hdr->kex, key_buf) < 0) {
                log_err_id(id, "Failed to derive DHE secret.");
                return -ECRYPT;
        }

        log_dbg_id(id, "DHE: derived shared secret.");

        memcpy(sk->key, key_buf, SYMMKEYSZ);
        sk->nid = scfg->c.nid;
        crypt_secure_clear(key_buf, SYMMKEYSZ);

        log_info_id(id, "Negotiated %s + %s.", scfg->x.str, scfg->c.str);

        return 0;
}


static int do_client_kex_complete(struct oap_cli_ctx *   s,
                                  const struct oap_hdr * peer_hdr,
                                  struct crypt_sk *      sk)
{
        struct sec_config * scfg = &s->scfg;
        uint8_t *           id   = s->id.data;
        int                 cipher_nid;
        int                 kdf_nid;

        if (!IS_KEX_ALGO_SET(scfg))
                return 0;

        /* Save client's configured minimums */
        cipher_nid = scfg->c.nid;
        kdf_nid    = scfg->k.nid;

        /* Accept server's cipher choice */
        if (peer_hdr->cipher_str == NULL) {
                log_err_id(id, "Server did not provide cipher.");
                return -ECRYPT;
        }

        SET_KEX_CIPHER(scfg, peer_hdr->cipher_str);

        if (crypt_cipher_rank(scfg->c.nid) < 0) {
                log_err_id(id, "Server cipher '%s' not supported.",
                           peer_hdr->cipher_str);
                return -ENOTSUP;
        }

        /* Verify server cipher >= client's minimum */
        if (crypt_cipher_rank(scfg->c.nid) < crypt_cipher_rank(cipher_nid)) {
                log_err_id(id, "Server cipher %s too weak.",
                           peer_hdr->cipher_str);
                return -ECRYPT;
        }

        log_dbg_id(id, "Accepted server cipher %s.",
                   peer_hdr->cipher_str);

        /* Accept server's KDF for non-client-encap modes */
        if (scfg->x.mode != KEM_MODE_CLIENT_ENCAP
            && peer_hdr->kdf_nid != NID_undef) {
                if (crypt_kdf_rank(peer_hdr->kdf_nid)
                    < crypt_kdf_rank(kdf_nid)) {
                        log_err_id(id, "Server KDF too weak.");
                        return -ECRYPT;
                }
                SET_KEX_KDF_NID(scfg, peer_hdr->kdf_nid);
                log_dbg_id(id, "Accepted server KDF %s.",
                           md_nid_to_str(scfg->k.nid));
        }

        /* Derive shared secret */
        if (IS_KEM_ALGORITHM(scfg->x.str))
                return do_client_kex_complete_kem(s, peer_hdr, sk);

        return do_client_kex_complete_dhe(s, peer_hdr, sk);
}

int oap_cli_complete(void *            ctx,
                     buffer_t          rsp_buf,
                     buffer_t *        data,
                     struct crypt_sk * sk,
                     const buffer_t *  cached_crt,
                     buffer_t *        peer_crt)
{
        struct oap_cli_ctx * s = ctx;
        struct oap_hdr       peer_hdr;
        char                 peer[NAME_SIZE + 1];
        uint8_t              kc_buf[MAX_HASH_SIZE];
        uint8_t              resp_hash_buf[MAX_HASH_SIZE];
        uint8_t              hs_key[SYMMKEYSZ];
        buffer_t             req_hash  = BUF_INIT;
        buffer_t             resp_hash = BUF_INIT;
        uint8_t *            id;
        int                  rc;

        assert(ctx != NULL);
        assert(data != NULL);
        assert(sk != NULL);

        sk->nid = NID_undef;

        clrbuf(*data);

        memset(&peer_hdr, 0, sizeof(peer_hdr));

        id = s->id.data;

        log_dbg_id(id, "Completing OAP for %s.", s->peer);

        /* Decode response header using client's md_nid for hash length */
        if (oap_hdr_decode(&peer_hdr, rsp_buf, s->req_md_nid, false) < 0) {
                log_err_id(id, "Failed to decode OAP response header.");
                goto fail_oap;
        }

        debug_oap_hdr_rcv(&peer_hdr);

        /* Verify response ID matches request */
        if (memcmp(peer_hdr.id.data, id, OAP_ID_SIZE) != 0) {
                log_err_id(id, "OAP response ID mismatch.");
                goto fail_oap;
        }

        /* Complete key exchange first; the sealed identity needs the secret */
        if (do_client_kex_complete(s, &peer_hdr, sk) < 0) {
                log_err_id(id, "Failed to complete key exchange.");
                goto fail_oap;
        }

        req_hash.data = s->req_hash;
        req_hash.len  = s->req_hash_len;

        /* Decrypt the sealed server identity (data+cert+sig) before auth */
        if (sk->nid != NID_undef && peer_hdr.sealed.data != NULL) {
                if (oap_derive_hs_key(sk, req_hash, hs_key) < 0) {
                        log_err_id(id, "Failed to derive handshake key.");
                        goto fail_oap;
                }

                rc = oap_hdr_unseal(&peer_hdr, hs_key);

                crypt_secure_clear(hs_key, SYMMKEYSZ);

                if (rc < 0) {
                        log_err_id(id, "Failed to unseal server identity.");
                        goto fail_oap;
                }
        }

        /* Authenticate server (cert + signature now in cleartext) */
        if (oap_auth_peer(peer, &s->scfg, &s->local_hdr, &peer_hdr,
                          cached_crt) < 0) {
                log_err_id(id, "Failed to authenticate server.");
                goto fail_oap;
        }

        /* Surface the peer cert so the caller can cache it for re-key. */
        if (peer_crt != NULL && peer_hdr.crt.len > 0) {
                peer_crt->data = malloc(peer_hdr.crt.len);
                if (peer_crt->data == NULL)
                        goto fail_oap;

                memcpy(peer_crt->data, peer_hdr.crt.data, peer_hdr.crt.len);
                peer_crt->len = peer_hdr.crt.len;
        }

        /* Response must carry a transcript tag of the expected length */
        if (peer_hdr.rsp_tag.len != s->req_hash_len) {
                log_err_id(id, "Response transcript tag mismatch.");
                goto fail_oap;
        }

        /* Verify peer certificate name matches expected destination */
        if (peer_hdr.crt.len > 0 && strcmp(peer, s->peer) != 0) {
                log_err_id(id, "Peer crt for '%s' does not match '%s'.",
                         peer, s->peer);
                goto fail_oap;
        }

        if (sk->nid != NID_undef) {
                /* Encrypted: bind the key and verify key confirmation */
                resp_hash.data = resp_hash_buf;

                if (oap_resp_hash(s->req_md_nid, peer_hdr.kex,
                                  peer_hdr.data, peer_hdr.crt,
                                  &resp_hash) < 0) {
                        log_err_id(id, "Failed to hash response.");
                        goto fail_oap;
                }

                if (oap_bind_session_key(sk, req_hash, resp_hash,
                                         s->scfg.k.nid) < 0) {
                        log_err_id(id, "Failed to bind session key.");
                        goto fail_oap;
                }

                if (oap_key_confirm_tag(sk, req_hash, resp_hash, kc_buf,
                                        s->req_hash_len) < 0) {
                        log_err_id(id, "Failed to confirm session key.");
                        goto fail_oap;
                }

                if (crypt_ct_cmp(peer_hdr.rsp_tag.data, kc_buf,
                                 s->req_hash_len) != 0) {
                        log_err_id(id, "Key confirmation mismatch.");
                        goto fail_oap;
                }
        } else {
                /* Cleartext path is config-driven, never a wire downgrade */
                assert(!IS_KEX_ALGO_SET(&s->scfg));
                /* Unencrypted: verify request-echo integrity */
                if (crypt_ct_cmp(peer_hdr.rsp_tag.data, s->req_hash,
                                 s->req_hash_len) != 0) {
                        log_err_id(id, "Response tag mismatch.");
                        goto fail_oap;
                }
        }

        /* Copy piggybacked data from server response */
        if (oap_hdr_copy_data(&peer_hdr, data) < 0) {
                log_err_id(id, "Failed to copy server data.");
                goto fail_oap;
        }

        log_info_id(id, "OAP completed for %s.", s->peer);

        freebuf(peer_hdr.sealed_pt);

        oap_ctx_free(s);

        return 0;

 fail_oap:
        freebuf(peer_hdr.sealed_pt);
        oap_ctx_free(s);
        return -ECRYPT;
}
