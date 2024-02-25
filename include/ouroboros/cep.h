/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The Ouroboros Connection Establishment Protocol
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

#ifndef OUROBOROS_CEP_H
#define OUROBOROS_CEP_H

#include <ouroboros/cdefs.h>
#include <ouroboros/proto.h>

#include <stdint.h>

#define OCEP_BUF_STRLEN 128

struct conn_info {
        char                       comp_name[OCEP_BUF_STRLEN + 1];
        char                       protocol[OCEP_BUF_STRLEN + 1];
        uint32_t                   pref_version;
        enum proto_concrete_syntax pref_syntax;
        struct proto_field         fixed_conc_syntax[PROTO_MAX_FIELDS];
        size_t                     num_fields;
        uint64_t                   addr;
};

__BEGIN_DECLS

int cep_snd(int                      fd,
            const struct conn_info * in);

int cep_rcv(int                fd,
            struct conn_info * out);

__END_DECLS

#endif /* OUROBOROS_CEP_H */
