/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * CACEP - Read/Write Protocol info
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

#include "cacep_proto.h"

enum proto_concrete_syntax code_to_syntax(int code)
{
        switch(code) {
        case PROTO_CONCRETE_SYNTAX_CODE__GPB:
                return PROTO_GPB;
        case PROTO_CONCRETE_SYNTAX_CODE__ASN_1:
                return PROTO_ASN_1;
        case PROTO_CONCRETE_SYNTAX_CODE__FIXED:
                return PROTO_FIXED;
        default:
                return -1;
        }
}

int syntax_to_code(enum proto_concrete_syntax stx)
{
        switch(stx) {
        case PROTO_GPB:
                return PROTO_CONCRETE_SYNTAX_CODE__GPB;
        case PROTO_ASN_1:
                return PROTO_CONCRETE_SYNTAX_CODE__ASN_1;
        case PROTO_FIXED:
                return PROTO_CONCRETE_SYNTAX_CODE__FIXED;
        default:
                return -1;
        }
}
