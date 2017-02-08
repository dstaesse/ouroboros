/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Policy for flat addresses in a distributed way
 *
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#define OUROBOROS_PREFIX "flat-addr-auth"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/errno.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/rib.h>

#include "ipcp.h"

#include <time.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <assert.h>

#define NAME_LEN 8
#define REC_DIF_SIZE 10000

/* convert 32 bit addr to a hex string */
static void addr_name(char *   name,
                      uint32_t addr)
{
        sprintf(name, "%8x", (uint32_t) (addr));
}

#define freepp(type, ptr, len)                          \
        do {                                            \
                if (len == 0)                           \
                        break;                          \
                while (len > 0)                         \
                        free(((type **) ptr)[--len]);   \
                free(ptr);                              \
        } while (0);

static int addr_taken(char *  name,
                      char ** members,
                      size_t  len)
{
        size_t i;
        char path[RIB_MAX_PATH_LEN + 1];

        size_t reset;
        strcpy(path, "/" MEMBERS_NAME);

        reset = strlen(path);

        for (i = 0; i < len; ++i) {
                ssize_t j;
                ssize_t c;
                char ** addrs;
                rib_path_append(path, members[i]);
                c = rib_children(path, &addrs);
                for (j = 0; j < c; ++j)
                        if (strcmp(addrs[j], name) == 0) {
                                freepp(char, addrs, c);
                                return 1;
                        }
                freepp(char, addrs, c);
                path[reset] = '\0';
        }

        return 0;
}

#define INVALID_ADDRESS 0

uint64_t flat_address(void)
{
        struct timespec t;

        char path[RIB_MAX_PATH_LEN];
        char name[NAME_LEN + 1];
        uint32_t addr;
        uint8_t addr_size;

        char ** members;
        ssize_t n_members;

        strcpy(path, "/" MEMBERS_NAME);

        if (!rib_has(path)) {
                log_err("Could not read members from RIB.");
                return INVALID_ADDRESS;
        }

        if (rib_read("/" BOOT_NAME "/dt/const/addr_size",
                     &addr_size, sizeof(addr_size)) != sizeof(addr_size)) {
                log_err("Failed to read address size.");
                return INVALID_ADDRESS;
        }

        if (addr_size != 4) {
                log_err("Flat address policy mandates 4 byte addresses.");
                return INVALID_ADDRESS;
        }

        n_members = rib_children(path, &members);
        if (n_members > REC_DIF_SIZE)
                log_warn("DIF exceeding recommended size for flat addresses.");

        rib_path_append(path, ipcpi.name);

        if (!rib_has(path)) {
                log_err("This ipcp is not a member.");
                freepp(char, members, n_members);
                return INVALID_ADDRESS;
        }

        clock_gettime(CLOCK_REALTIME, &t);
        srand(t.tv_nsec);

        assert(n_members > 0);

        do {
                addr = (rand() % (RAND_MAX - 1) + 1) & 0xFFFFFFFF;
                addr_name(name, addr);
        } while (addr_taken(name, members, n_members));

        freepp(char, members, n_members);

        if (rib_add(path, name)) {
                log_err("Failed to add address to RIB.");
                return INVALID_ADDRESS;
        }

        if (rib_write(path, &addr, sizeof(addr))) {
                log_err("Failed to write address in RIB.");
                return INVALID_ADDRESS;
        }

        return addr;
}
