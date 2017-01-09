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

#include <stdint.h>
#include <unistd.h>

struct cacep;

struct cacep_info {
        char *   name;
        uint64_t addr;
};

struct cacep *      cacep_create(int      fd,
                                 char *   name,
                                 uint64_t address);

int                 cacep_destroy(struct cacep * instance);

struct cacep_info * cacep_auth(struct cacep * instance);

struct cacep_info * cacep_auth_wait(struct cacep * instance);

#endif /* OUROBOROS_CACEP_H */
