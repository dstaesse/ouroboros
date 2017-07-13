/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * DIF directory
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

#define OUROBOROS_PREFIX "directory"

#include <ouroboros/config.h>
#include <ouroboros/endian.h>
#include <ouroboros/errno.h>
#include <ouroboros/logs.h>
#include <ouroboros/rib.h>
#include <ouroboros/utils.h>

#include "dir.h"
#include "dht.h"
#include "ipcp.h"
#include "ribconfig.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <inttypes.h>

#define KAD_B (hash_len(ipcpi.dir_hash_algo) * CHAR_BIT)
#define ENROL_RETR 6
#define ENROL_INTV 1

struct dht * dht;

static uint64_t find_peer_addr(void)
{
        ssize_t  i;
        char ** members;
        ssize_t n_members;
        size_t  reset;
        char    path[RIB_MAX_PATH_LEN + 1];

        strcpy(path, MEMBERS_PATH);

        reset = strlen(path);

        n_members = rib_children(path, &members);
        if (n_members == 1) {
                freepp(ssize_t, members, n_members);
                return 0;
        }

        for (i = 0; i < n_members; ++i) {
                uint64_t addr;
                rib_path_append(path, members[i]);
                if (rib_read(path, &addr, sizeof(addr)) != sizeof(addr)) {
                        log_err("Failed to read address from RIB.");
                        freepp(ssize_t, members, n_members);
                        return ipcpi.dt_addr;
                }

                if (addr != ipcpi.dt_addr) {
                        freepp(ssize_t, members, n_members);
                        return addr;
                }

                path[reset] = '\0';
        }

        freepp(ssize_t, members, n_members);

        return 0;
}

int dir_init()
{
        uint64_t addr;

        dht = dht_create(ipcpi.dt_addr);
        if (dht == NULL)
                return -ENOMEM;

        addr = find_peer_addr();
        if (addr == ipcpi.dt_addr) {
                log_err("Failed to get peer address.");
                dht_destroy(dht);
                return -EPERM;
        }

        if (addr != 0) {
                size_t retr = 0;
                log_dbg("Enrolling directory with peer %" PRIu64 ".", addr);
                /* NOTE: we could try other members if dht_enroll times out. */
                while (dht_enroll(dht, addr)) {
                        if (retr++ == ENROL_RETR) {
                                dht_destroy(dht);
                                return -EPERM;
                        }

                        log_dbg("Directory enrollment failed, retrying...");
                        sleep(ENROL_INTV);
                }

                return 0;
        }

        log_dbg("Bootstrapping DHT.");

        /* TODO: get parameters for bootstrap from IRM tool. */
        if (dht_bootstrap(dht, KAD_B, 86400)) {
                dht_destroy(dht);
                return -ENOMEM;
        }

        return 0;
}

void dir_fini(void)
{
        dht_destroy(dht);
}

int dir_reg(const uint8_t * hash)
{
        return dht_reg(dht, hash);
}

int dir_unreg(const uint8_t * hash)
{
        return dht_unreg(dht, hash);
}

uint64_t dir_query(const uint8_t * hash)
{
        return dht_query(dht, hash);
}
