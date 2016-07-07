/*
 * Ouroboros - Copyright (C) 2016
 *
 * Lockfile for ouroboros system
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#ifndef OUROBOROS_LOCKFILE_H
#define OUROBOROS_LOCKFILE_H

#include <sys/types.h>

struct lockfile;

struct lockfile * lockfile_create();
struct lockfile * lockfile_open();
void              lockfile_close(struct lockfile * lf);
void              lockfile_destroy(struct lockfile * lf);

pid_t             lockfile_owner(struct lockfile * lf);

#endif
