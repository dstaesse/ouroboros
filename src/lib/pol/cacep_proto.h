/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * CACEP - Convert syntax to msg code and back
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

#ifndef OUROBOROS_LIB_CACEP_CDAP_H
#define OUROBOROS_LIB_CACEP_CDAP_H

#include <ouroboros/cacep.h>
#include <ouroboros/irm_config.h>

#include "cacep_proto.pb-c.h"

enum proto_concrete_syntax code_to_syntax(int code);

int                        syntax_to_code(enum proto_concrete_syntax stx);

#endif /* OUROBOROS_LIB_CACEP_CDAP_H */
