/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The Common Application Connection Establishment Phase
 *
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OUROBOROS_CACEP_H
#define OUROBOROS_CACEP_H

#include <ouroboros/irm_config.h>

enum proto_concrete_syntax {
        PROTO_GPB = 0,
        PROTO_ASN_1,
        PROTO_FIXED
};

struct cacep_info {
        struct {
                char *                     protocol;
                uint32_t                   pref_version;
                enum proto_concrete_syntax pref_syntax;
        }        proto;
        char *   name;
        uint64_t addr;
        void *   data;
};

int                 cacep_info_init(struct cacep_info * info);

void                cacep_info_fini(struct cacep_info * info);

struct cacep_info * cacep_auth(int                       fd,
                               enum pol_cacep            pc,
                               const struct cacep_info * info);

struct cacep_info * cacep_auth_wait(int                       fd,
                                    enum pol_cacep            pc,
                                    const struct cacep_info * info);

#endif /* OUROBOROS_CACEP_H */
