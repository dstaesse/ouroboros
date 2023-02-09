/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Protocol syntax definitions
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

#ifndef OUROBOROS_PROTO_H
#define OUROBOROS_PROTO_H

#include <sys/types.h>

#define PROTO_FIELD_ABSENT   -1
#define PROTO_FIELD_VARIABLE  0
#define PROTO_MAX_FIELDS      128

enum proto_concrete_syntax {
        PROTO_GPB = 0,
        PROTO_ASN_1,
        PROTO_FIXED
};

struct proto_field {
        size_t  fid; /* an ID for the protocol field */
        ssize_t len; /* 0 variable, -1 not present   */
};

#endif /* OUROBOROS_PROTO_H */
