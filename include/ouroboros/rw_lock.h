/*
 * Ouroboros - Copyright (C) 2016
 *
 * Read/Write locks
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

#ifndef OUROBOROS_RWLOCK_H
#define OUROBOROS_RWLOCK_H

#include <ouroboros/config.h>
#include <pthread.h>

typedef struct rw_lock {
        pthread_mutex_t lock;
        pthread_mutex_t i_lock;
        int             i;
} rw_lock_t;

int  rw_lock_init(rw_lock_t * lock);
void rw_lock_destroy(rw_lock_t * lock);
int  rw_lock_rdlock(rw_lock_t * lock);
int  rw_lock_wrlock(rw_lock_t * lock);
int  rw_lock_unlock(rw_lock_t * lock);

#endif /* OUROBOROS_RWLOCK_H */
