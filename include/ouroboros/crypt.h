/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Cryptography
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_LIB_CRYPT_H
#define OUROBOROS_LIB_CRYPT_H

#include <ouroboros/shm_du_buff.h>
#include <ouroboros/utils.h>

#include <assert.h>

#define IVSZ             16
#define SYMMKEYSZ        32
#define MAX_HASH_SIZE    64 /* SHA-512/BLAKE2b max */
#define KEX_ALGO_BUFSZ   32
#define KEX_CIPHER_BUFSZ 32
#define MSGBUFSZ         2048

/* Cipher NIDs (match OpenSSL values) */
#define NID_undef              0
#define NID_aes_128_gcm        895
#define NID_aes_192_gcm        898
#define NID_aes_256_gcm        901
#define NID_aes_128_ctr        904
#define NID_aes_192_ctr        905
#define NID_aes_256_ctr        906
#define NID_chacha20_poly1305  1018

/* KDF NIDs (match OpenSSL values) */
#define NID_hkdf               1036
#define NID_sha256             672
#define NID_sha384             673
#define NID_sha512             674
#define NID_sha3_256           1096
#define NID_sha3_384           1097
#define NID_sha3_512           1098
#define NID_blake2b512         1056
#define NID_blake2s256         1057

/* KEX algorithm NIDs (match OpenSSL values) */
#define NID_X9_62_prime256v1   415
#define NID_secp384r1          715
#define NID_secp521r1          716
#define NID_X25519             1034
#define NID_X448               1035
#define NID_ffdhe2048          1126
#define NID_ffdhe3072          1127
#define NID_ffdhe4096          1128
#define NID_MLKEM512           1454
#define NID_MLKEM768           1455
#define NID_MLKEM1024          1456
#define NID_X25519MLKEM768     2053 /* !! not in OpenSSL   */
#define NID_X448MLKEM1024      2054 /* !! not in OpenSSL   */

#define IS_KEM_ALGORITHM(algo) \
        (strstr(algo, "ML-KEM") != NULL || strstr(algo, "MLKEM") != NULL)

#define IS_HYBRID_KEM(algo) \
        ((strstr(algo, "X25519") != NULL || strstr(algo, "X448") != NULL) && \
         strstr(algo, "MLKEM") != NULL)

#define X25519MLKEM768_PKSZ   1216  /* 32 + 1184 */
#define X25519MLKEM768_CTSZ   1120  /* 32 + 1088 */
#define X25519MLKEM768_SKSZ   2432  /* 32 + 2400 */
#define X448MLKEM1024_PKSZ    1624  /* 56 + 1568 */
#define X448MLKEM1024_SKSZ    3224  /* 56 + 3168 */

#define KEM_MODE_SERVER_ENCAP 0     /* Server encapsulates (default) */
#define KEM_MODE_CLIENT_ENCAP 1     /* Client encapsulates           */
#define IS_KEX_ALGO_SET(cfg)   ((cfg)->x.nid != NID_undef)
#define IS_KEX_CIPHER_SET(cfg) ((cfg)->c.nid != NID_undef)


struct crypt_sk {
        int       nid;
        uint8_t * key;
};

struct sec_config {
        struct {
                const char * str;
                int          nid;
                int          mode;
        } x; /* key exchange */
        struct {
                const char * str;
                int          nid;
        } k; /* kdf */
        struct {
                const char * str;
                int          nid;
        } c; /* cipher */
        struct {
                const char * str;
                int          nid;
        } d; /* digest */
};

/* Helper macros to set sec_config fields consistently */
#define SET_KEX_ALGO(cfg, algo_str) do {                           \
        (cfg)->x.nid = kex_str_to_nid(algo_str);                   \
        (cfg)->x.str = kex_nid_to_str((cfg)->x.nid);               \
        assert((cfg)->x.nid != NID_undef || (cfg)->x.str == NULL); \
} while (0)

#define SET_KEX_ALGO_NID(cfg, nid_val) do {                        \
        (cfg)->x.nid = (nid_val);                                  \
        (cfg)->x.str = kex_nid_to_str((cfg)->x.nid);               \
        assert((cfg)->x.nid != NID_undef || (cfg)->x.str == NULL); \
} while (0)

#define SET_KEX_KEM_MODE(cfg, mode_val) do {                       \
        (cfg)->x.mode = (mode_val);                                \
} while (0)

#define SET_KEX_KDF(cfg, kdf_str) do {                             \
        (cfg)->k.nid = md_str_to_nid(kdf_str);                     \
        (cfg)->k.str = md_nid_to_str((cfg)->k.nid);                \
        assert((cfg)->k.nid != NID_undef || (cfg)->k.str == NULL); \
} while (0)

#define SET_KEX_KDF_NID(cfg, nid_val) do {                         \
        (cfg)->k.nid = (nid_val);                                  \
        (cfg)->k.str = md_nid_to_str((cfg)->k.nid);                \
        assert((cfg)->k.nid != NID_undef || (cfg)->k.str == NULL); \
} while (0)

#define SET_KEX_CIPHER(cfg, cipher_str) do {                       \
        (cfg)->c.nid = crypt_str_to_nid(cipher_str);               \
        (cfg)->c.str = crypt_nid_to_str((cfg)->c.nid);             \
        assert((cfg)->c.nid != NID_undef || (cfg)->c.str == NULL); \
} while (0)

#define SET_KEX_CIPHER_NID(cfg, nid_val) do {                      \
        (cfg)->c.nid = (nid_val);                                  \
        (cfg)->c.str = crypt_nid_to_str((cfg)->c.nid);             \
        assert((cfg)->c.nid != NID_undef || (cfg)->c.str == NULL); \
} while (0)

#define SET_KEX_DIGEST(cfg, digest_str) do {                       \
        (cfg)->d.nid = md_str_to_nid(digest_str);                  \
        (cfg)->d.str = md_nid_to_str((cfg)->d.nid);                \
        assert((cfg)->d.nid != NID_undef || (cfg)->d.str == NULL); \
} while (0)

#define SET_KEX_DIGEST_NID(cfg, nid_val) do {                      \
        (cfg)->d.nid = (nid_val);                                  \
        (cfg)->d.str = md_nid_to_str((cfg)->d.nid);                \
        assert((cfg)->d.nid != NID_undef || (cfg)->d.str == NULL); \
} while (0)

#define CLEAR_KEX_ALGO(cfg) do {                                   \
        (cfg)->x.nid = NID_undef;                                  \
        (cfg)->x.str = NULL;                                       \
} while (0)

#define CLEAR_KEX_KDF(cfg) do {                                    \
        (cfg)->k.nid = NID_undef;                                  \
        (cfg)->k.str = NULL;                                       \
} while (0)

#define CLEAR_KEX_CIPHER(cfg) do {                                 \
        (cfg)->c.nid = NID_undef;                                  \
        (cfg)->c.str = NULL;                                       \
} while (0)

#define CLEAR_KEX_DIGEST(cfg) do {                                 \
        (cfg)->d.nid = NID_undef;                                  \
        (cfg)->d.str = NULL;                                       \
} while (0)

struct auth_ctx;
struct crypt_ctx;

struct auth_ctx *  auth_create_ctx(void);

void               auth_destroy_ctx(struct auth_ctx * ctx);

int                auth_add_crt_to_store(struct auth_ctx * ctx,
                                         void *            crt);

int                auth_verify_crt(struct auth_ctx * ctx,
                                   void *            crt);

int                auth_sign(void *     pkp,
                             int        md_nid,
                             buffer_t   msg,
                             buffer_t * sig);

int                auth_verify_sig(void *   pk,
                                   int      md_nid,
                                   buffer_t msg,
                                   buffer_t sig);

int                load_sec_config_file(struct sec_config * cfg,
                                        const char *        path);

int                kex_pkp_create(struct sec_config * cfg,
                                  void **             pkp,
                                  uint8_t *           pk);

void               kex_pkp_destroy(void * pkp);

int                kex_dhe_derive(struct sec_config * cfg,
                                  void *              pkp,
                                  buffer_t            pk,
                                  uint8_t *           s);

ssize_t            kex_kem_encap(buffer_t  pk,
                                 uint8_t * ct,
                                 int       kdf_nid,
                                 uint8_t * s);

ssize_t            kex_kem_encap_raw(buffer_t  pk,
                                     uint8_t * ct,
                                     int       kdf_nid,
                                     uint8_t * s);

int                kex_kem_decap(void *    pkp,
                                 buffer_t  ct,
                                 int       kdf_nid,
                                 uint8_t * s);

int                kex_get_algo_from_pk_der(buffer_t pk,
                                            char *   algo);

int                kex_get_algo_from_pk_raw(buffer_t pk,
                                            char *   algo);

int                kex_validate_algo(const char * algo);

int                kex_validate_nid(int nid);

const char *       kex_nid_to_str(uint16_t nid);

uint16_t           kex_str_to_nid(const char * algo);

struct crypt_ctx * crypt_create_ctx(struct crypt_sk * sk);

void               crypt_destroy_ctx(struct crypt_ctx * ctx);

int                crypt_validate_nid(int nid);

const char *       crypt_nid_to_str(uint16_t nid);

uint16_t           crypt_str_to_nid(const char * cipher);

int                md_validate_nid(int nid);

const char *       md_nid_to_str(uint16_t nid);

uint16_t           md_str_to_nid(const char * kdf);

ssize_t            md_digest(int        md_nid,
                             buffer_t   in,
                             uint8_t *  out);

ssize_t            md_len(int md_nid);

int                crypt_encrypt(struct crypt_ctx * ctx,
                                 buffer_t           in,
                                 buffer_t *         out);

int                crypt_decrypt(struct crypt_ctx * ctx,
                                 buffer_t           in,
                                 buffer_t *         out);

int                crypt_load_crt_file(const char * path,
                                       void **      crt);

int                crypt_load_crt_str(const char * str,
                                      void **      crt);

int                crypt_load_crt_der(buffer_t buf,
                                      void **  crt);

int                crypt_get_pubkey_crt(void *  crt,
                                        void ** pk);

void               crypt_free_crt(void * crt);

int                crypt_load_privkey_file(const char * path,
                                           void **      key);

int                crypt_load_privkey_str(const char * str,
                                          void **      key);

int                crypt_load_pubkey_str(const char * str,
                                         void **      key);

int                crypt_load_pubkey_file(const char * path,
                                          void **      key);

int                crypt_load_pubkey_file_to_der(const char * path,
                                                 buffer_t *   buf);

int                crypt_load_pubkey_raw_file(const char * path,
                                              buffer_t *   buf);

int                crypt_load_privkey_raw_file(const char * path,
                                               void **      key);

int                crypt_cmp_key(const void * key1,
                                 const void * key2);

void               crypt_free_key(void * key);

int                crypt_crt_str(const void * crt,
                                 char *       buf);

int                crypt_crt_der(const void * crt,
                                 buffer_t *   buf);

int                crypt_check_crt_name(void *       crt,
                                        const char * name);

int                crypt_get_crt_name(void * crt,
                                     char * name);

/* Secure memory allocation for sensitive data (keys, secrets) */
int                crypt_secure_malloc_init(size_t max);

void               crypt_secure_malloc_fini(void);

void *             crypt_secure_malloc(size_t size);

void               crypt_secure_free(void *  ptr,
                                     size_t  size);

#endif /* OUROBOROS_LIB_CRYPT_H */
