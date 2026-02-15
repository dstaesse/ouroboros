/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * OAP - File I/O for credentials and configuration
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

#include "io.h"

#include <assert.h>
#include <string.h>
#include <sys/stat.h>

/*
 * Shared credential and configuration loading helpers
 */

#ifndef OAP_TEST_MODE

static bool file_exists(const char * path)
{
        struct stat s;

        if (stat(path, &s) < 0 && errno == ENOENT) {
                log_dbg("File %s does not exist.", path);
                return false;
        }

        return true;
}

int load_credentials(const char *                  name,
                     const struct name_sec_paths * paths,
                     void **                       pkp,
                     void **                       crt)
{
        assert(paths != NULL);
        assert(pkp != NULL);
        assert(crt != NULL);

        *pkp = NULL;
        *crt = NULL;

        if (!file_exists(paths->crt) || !file_exists(paths->key)) {
                log_info("No authentication certificates for %s.", name);
                return 0;
        }

        if (crypt_load_crt_file(paths->crt, crt) < 0) {
                log_err("Failed to load %s for %s.", paths->crt, name);
                goto fail_crt;
        }

        if (crypt_load_privkey_file(paths->key, pkp) < 0) {
                log_err("Failed to load %s for %s.", paths->key, name);
                goto fail_key;
        }

        log_info("Loaded authentication certificates for %s.", name);

        return 0;

 fail_key:
        crypt_free_crt(*crt);
        *crt = NULL;
 fail_crt:
        return -EAUTH;
}

int load_kex_config(const char *        name,
                    const char *        path,
                    struct sec_config * cfg)
{
        assert(name != NULL);
        assert(cfg != NULL);

        memset(cfg, 0, sizeof(*cfg));

        /* Load encryption config */
        if (!file_exists(path))
                log_dbg("No encryption %s for %s.", path, name);

        if (load_sec_config_file(cfg, path) < 0) {
                log_warn("Failed to load %s for %s.", path, name);
                return -1;
        }

        if (!IS_KEX_ALGO_SET(cfg)) {
                log_info("Key exchange not configured for %s.", name);
                return 0;
        }
#ifndef HAVE_OPENSSL_PQC
        if (IS_KEM_ALGORITHM(cfg->x.str)) {
                log_err("PQC not available, can't use %s for %s.",
                        cfg->x.str, name);
                return -ENOTSUP;
        }
#endif
        if (cfg->c.nid == NID_undef) {
                log_err("Invalid cipher for %s.", name);
                return -ECRYPT;
        }

        log_info("Encryption enabled for %s.", name);

        return 0;
}

#endif /* OAP_TEST_MODE */
