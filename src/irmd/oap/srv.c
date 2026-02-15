/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * OAP - Server-side processing
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

#include "config.h"

#include "auth.h"
#include "hdr.h"
#include "io.h"
#include "oap.h"

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef OAP_TEST_MODE
extern int load_srv_credentials(const struct name_info * info,
                                void **                  pkp,
                                void **                  crt);
extern int load_srv_kex_config(const struct name_info * info,
                               struct sec_config *      cfg);
extern int load_server_kem_keypair(const char * name,
                                   bool         raw_fmt,
                                   void **      pkp);
#else

int load_srv_credentials(const struct name_info * info,
                         void **                  pkp,
                         void **                  crt)
{
        assert(info != NULL);
        assert(pkp != NULL);
        assert(crt != NULL);

        return load_credentials(info->name, &info->s, pkp, crt);
}

int load_srv_kex_config(const struct name_info * info,
                        struct sec_config *      cfg)
{
        assert(info != NULL);
        assert(cfg != NULL);

        return load_kex_config(info->name, info->s.enc, cfg);
}

int load_server_kem_keypair(const char * name,
                            bool         raw_fmt,
                            void **      pkp)
{
        char         path[PATH_MAX];
        const char * ext;

        assert(name != NULL);
        assert(pkp != NULL);

        ext = raw_fmt ? "raw" : "pem";

        snprintf(path, sizeof(path),
                 OUROBOROS_SRV_CRT_DIR "/%s/kex.key.%s", name, ext);

        if (raw_fmt) {
                if (crypt_load_privkey_raw_file(path, pkp) < 0) {
                        log_err("Failed to load %s keypair from %s.",
                                ext, path);
                        return -ECRYPT;
                }
        } else {
                if (crypt_load_privkey_file(path, pkp) < 0) {
                        log_err("Failed to load %s keypair from %s.",
                                ext, path);
                        return -ECRYPT;
                }
        }

        log_dbg("Loaded server KEM keypair from %s.", path);
        return 0;
}

#endif /* OAP_TEST_MODE */

static int get_algo_from_peer_key(const struct oap_hdr * peer_hdr,
                                  char *                 algo_buf)
{
        uint8_t * id = peer_hdr->id.data;
        int       ret;

        if (OAP_KEX_IS_RAW_FMT(peer_hdr)) {
                ret = kex_get_algo_from_pk_raw(peer_hdr->kex, algo_buf);
                if (ret < 0) {
                        log_err_id(id, "Failed to get algo from raw key.");
                        return -ECRYPT;
                }
        } else {
                ret = kex_get_algo_from_pk_der(peer_hdr->kex, algo_buf);
                if (ret < 0) {
                        log_err_id(id, "Failed to get algo from DER key.");
                        return -ECRYPT;
                }
        }

        return 0;
}

static int negotiate_cipher(const struct oap_hdr * peer_hdr,
                            struct sec_config *    kcfg)
{
        uint8_t * id = peer_hdr->id.data;
        int       cli_nid;
        int       cli_rank;
        int       srv_rank;

        /* Cipher: select the strongest of client and server */
        cli_nid = peer_hdr->cipher_str != NULL
                ? (int) crypt_str_to_nid(peer_hdr->cipher_str)
                : NID_undef;

        if (cli_nid != NID_undef
            && crypt_cipher_rank(cli_nid) < 0) {
                log_err_id(id, "Unsupported cipher '%s'.",
                           peer_hdr->cipher_str);
                return -ENOTSUP;
        }

        cli_rank = crypt_cipher_rank(cli_nid);
        srv_rank = crypt_cipher_rank(kcfg->c.nid);

        if (cli_rank > srv_rank) {
                SET_KEX_CIPHER_NID(kcfg, cli_nid);
                log_dbg_id(id, "Selected client cipher %s.",
                           kcfg->c.str);
        } else if (srv_rank > 0) {
                log_dbg_id(id, "Selected server cipher %s.",
                           kcfg->c.str);
        } else {
                log_err_id(id, "Encryption requested, no cipher.");
                return -ECRYPT;
        }

        /* KDF: select the strongest of client and server */
        if (peer_hdr->kdf_nid != NID_undef
            && crypt_kdf_rank(peer_hdr->kdf_nid) < 0) {
                log_err_id(id, "Unsupported KDF NID %d.",
                           peer_hdr->kdf_nid);
                return -ENOTSUP;
        }

        cli_rank = crypt_kdf_rank(peer_hdr->kdf_nid);
        srv_rank = crypt_kdf_rank(kcfg->k.nid);

        /*
         * For client-encap KEM, the KDF is baked into
         * the ciphertext. The server must use the client's
         * KDF and can only verify the minimum.
         */
        if (OAP_KEX_ROLE(peer_hdr) == KEM_MODE_CLIENT_ENCAP) {
                if (srv_rank > cli_rank) {
                        log_err_id(id, "Client KDF too weak.");
                        return -ECRYPT;
                }
                SET_KEX_KDF_NID(kcfg, peer_hdr->kdf_nid);
        } else if (cli_rank > srv_rank) {
                SET_KEX_KDF_NID(kcfg, peer_hdr->kdf_nid);
                log_dbg_id(id, "Selected client KDF %s.",
                           md_nid_to_str(kcfg->k.nid));
        } else if (srv_rank > 0) {
                log_dbg_id(id, "Selected server KDF %s.",
                           md_nid_to_str(kcfg->k.nid));
        }

        if (IS_KEX_ALGO_SET(kcfg))
                log_info_id(id, "Negotiated %s + %s.",
                            kcfg->x.str, kcfg->c.str);
        else
                log_info_id(id, "No key exchange.");

        return 0;
}

static int do_server_kem_decap(const struct name_info * info,
                               const struct oap_hdr *   peer_hdr,
                               struct sec_config *      kcfg,
                               struct crypt_sk *        sk)
{
        buffer_t  ct;
        void *    server_pkp = NULL;
        int       ret;
        uint8_t * id = peer_hdr->id.data;

        ret = load_server_kem_keypair(info->name,
                                      peer_hdr->kex_flags.fmt,
                                      &server_pkp);
        if (ret < 0)
                return ret;

        ct.data = peer_hdr->kex.data;
        ct.len  = peer_hdr->kex.len;

        ret = kex_kem_decap(server_pkp, ct, kcfg->k.nid, sk->key);

        crypt_free_key(server_pkp);

        if (ret < 0) {
                log_err_id(id, "Failed to decapsulate KEM.");
                return -ECRYPT;
        }

        log_dbg_id(id, "Client encaps: decapsulated CT.");

        return 0;
}

static int do_server_kem_encap(const struct oap_hdr * peer_hdr,
                               struct sec_config *    kcfg,
                               buffer_t *             kex,
                               struct crypt_sk *      sk)
{
        buffer_t  client_pk;
        ssize_t   ct_len;
        uint8_t * id = peer_hdr->id.data;

        client_pk.data = peer_hdr->kex.data;
        client_pk.len  = peer_hdr->kex.len;

        if (IS_HYBRID_KEM(kcfg->x.str))
                ct_len = kex_kem_encap_raw(client_pk, kex->data,
                                           kcfg->k.nid, sk->key);
        else
                ct_len = kex_kem_encap(client_pk, kex->data,
                                       kcfg->k.nid, sk->key);

        if (ct_len < 0) {
                log_err_id(id, "Failed to encapsulate KEM.");
                return -ECRYPT;
        }

        kex->len = (size_t) ct_len;

        log_dbg_id(id, "Server encaps: generated CT, len=%zd.", ct_len);

        return 0;
}

static int do_server_kex_kem(const struct name_info * info,
                             struct oap_hdr *         peer_hdr,
                             struct sec_config *      kcfg,
                             buffer_t *               kex,
                             struct crypt_sk *        sk)
{
        int ret;

        kcfg->x.mode = peer_hdr->kex_flags.role;

        if (kcfg->x.mode == KEM_MODE_CLIENT_ENCAP) {
                ret = do_server_kem_decap(info, peer_hdr, kcfg, sk);
                kex->len = 0;
        } else {
                ret = do_server_kem_encap(peer_hdr, kcfg, kex, sk);
        }

        return ret;
}

static int do_server_kex_dhe(const struct oap_hdr * peer_hdr,
                             struct sec_config *    kcfg,
                             buffer_t *             kex,
                             struct crypt_sk *      sk)
{
        ssize_t   key_len;
        void *    epkp;
        int       ret;
        uint8_t * id = peer_hdr->id.data;

        key_len = kex_pkp_create(kcfg, &epkp, kex->data);
        if (key_len < 0) {
                log_err_id(id, "Failed to generate key pair.");
                return -ECRYPT;
        }

        kex->len = (size_t) key_len;

        log_dbg_id(id, "Generated %s ephemeral keys.", kcfg->x.str);

        ret = kex_dhe_derive(kcfg, epkp, peer_hdr->kex, sk->key);
        if (ret < 0) {
                log_err_id(id, "Failed to derive secret.");
                kex_pkp_destroy(epkp);
                return -ECRYPT;
        }

        kex_pkp_destroy(epkp);

        return 0;
}

int do_server_kex(const struct name_info * info,
                  struct oap_hdr *         peer_hdr,
                  struct sec_config *      kcfg,
                  buffer_t *               kex,
                  struct crypt_sk *        sk)
{
        char      algo_buf[KEX_ALGO_BUFSZ];
        int       srv_kex_nid;
        uint8_t * id;

        id = peer_hdr->id.data;

        /* No KEX data from client */
        if (peer_hdr->kex.len == 0) {
                if (IS_KEX_ALGO_SET(kcfg)) {
                        log_warn_id(id, "KEX requested without info.");
                        return -ECRYPT;
                }
                return 0;
        }

        if (negotiate_cipher(peer_hdr, kcfg) < 0)
                return -ECRYPT;

        /* Save server's configured KEX before overwriting */
        srv_kex_nid = kcfg->x.nid;

        if (OAP_KEX_ROLE(peer_hdr) != KEM_MODE_CLIENT_ENCAP) {
                /* Server encapsulation or DHE: extract algo from DER PK */
                if (get_algo_from_peer_key(peer_hdr, algo_buf) < 0)
                        return -ECRYPT;

                SET_KEX_ALGO(kcfg, algo_buf);

                /* Reject if client KEX is weaker than server's */
                if (crypt_kex_rank(kcfg->x.nid)
                    < crypt_kex_rank(srv_kex_nid)) {
                        log_err_id(id, "Client KEX %s too weak.",
                                   kcfg->x.str);
                        return -ECRYPT;
                }
        }

        /* Dispatch based on algorithm type */
        if (IS_KEM_ALGORITHM(kcfg->x.str))
                return do_server_kex_kem(info, peer_hdr, kcfg, kex, sk);
        else
                return do_server_kex_dhe(peer_hdr, kcfg, kex, sk);
}

int oap_srv_process(const struct name_info * info,
                    buffer_t                 req_buf,
                    buffer_t *               rsp_buf,
                    buffer_t *               data,
                    struct crypt_sk *        sk)
{
        struct oap_hdr        peer_hdr;
        struct oap_hdr        local_hdr;
        struct sec_config     kcfg;
        uint8_t               kex_buf[MSGBUFSZ];
        uint8_t               hash_buf[MAX_HASH_SIZE];
        buffer_t              req_hash = BUF_INIT;
        ssize_t               hash_ret;
        char                  cli_name[NAME_SIZE + 1]; /* TODO */
        uint8_t *             id;
        void *                pkp = NULL;
        void *                crt = NULL;
        int                   req_md_nid;

        assert(info != NULL);
        assert(rsp_buf != NULL);
        assert(data != NULL);
        assert(sk != NULL);

        sk->nid = NID_undef;

        memset(&peer_hdr, 0, sizeof(peer_hdr));
        memset(&local_hdr, 0, sizeof(local_hdr));
        clrbuf(*rsp_buf);

        log_dbg("Processing OAP request for %s.", info->name);

        if (load_srv_credentials(info, &pkp, &crt) < 0) {
                log_err("Failed to load security keys for %s.", info->name);
                goto fail_cred;
        }

        if (load_srv_kex_config(info, &kcfg) < 0) {
                log_err("Failed to load KEX config for %s.", info->name);
                goto fail_kex;
        }

        /* Decode incoming header (NID_undef = request, no hash) */
        if (oap_hdr_decode(&peer_hdr, req_buf, NID_undef) < 0) {
                log_err("Failed to decode OAP header.");
                goto fail_auth;
        }

        debug_oap_hdr_rcv(&peer_hdr);

        id = peer_hdr.id.data; /* Logging */

        if (oap_check_hdr(&peer_hdr) < 0) {
                log_err_id(id, "OAP header failed replay check.");
                goto fail_auth;
        }

        oap_hdr_init(&local_hdr, peer_hdr.id, kex_buf, *data, NID_undef);

        if (oap_auth_peer(cli_name, &local_hdr, &peer_hdr) < 0) {
                log_err_id(id, "Failed to authenticate client.");
                goto fail_auth;
        }

        if (do_server_kex(info, &peer_hdr, &kcfg, &local_hdr.kex, sk) < 0)
                goto fail_kex;

        sk->nid = kcfg.c.nid;

        /* Build response header with hash of client request */
        local_hdr.nid = sk->nid;

        /* Use client's md_nid, defaulting to SHA-384 for PQC */
        req_md_nid = peer_hdr.md_nid != NID_undef ?
                     peer_hdr.md_nid : NID_sha384;

        /* Compute request hash using client's md_nid */
        hash_ret = md_digest(req_md_nid, req_buf, hash_buf);
        if (hash_ret < 0) {
                log_err_id(id, "Failed to hash request.");
                goto fail_auth;
        }
        req_hash.data = hash_buf;
        req_hash.len = (size_t) hash_ret;

        if (oap_hdr_encode(&local_hdr, pkp, crt, &kcfg,
                           req_hash, req_md_nid) < 0) {
                log_err_id(id, "Failed to create OAP response header.");
                goto fail_auth;
        }

        debug_oap_hdr_snd(&local_hdr);

        if (oap_hdr_copy_data(&peer_hdr, data) < 0) {
                log_err_id(id, "Failed to copy client data.");
                goto fail_data;
        }

        /* Transfer ownership of response buffer */
        *rsp_buf = local_hdr.hdr;

        log_info_id(id, "OAP request processed for %s.", info->name);

        crypt_free_crt(crt);
        crypt_free_key(pkp);

        return 0;

 fail_data:
        oap_hdr_fini(&local_hdr);
 fail_auth:
        crypt_free_crt(crt);
        crypt_free_key(pkp);
 fail_cred:
        return -EAUTH;

 fail_kex:
        crypt_free_crt(crt);
        crypt_free_key(pkp);
        return -ECRYPT;
}
