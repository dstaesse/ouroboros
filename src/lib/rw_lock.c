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

#include <ouroboros/rw_lock.h>

int rw_lock_init(rw_lock_t * lock)
{
        if (lock == NULL)
                return -1;

        pthread_mutex_init(&lock->lock, NULL);
        pthread_mutex_init(&lock->i_lock, NULL);
        lock->i = 0;

        return 0;
}

void rw_lock_destroy(rw_lock_t * lock)
{
        if (lock == NULL)
                return;

        pthread_mutex_destroy(&lock->lock);
        pthread_mutex_destroy(&lock->i_lock);
        lock->i = -1;
}

int rw_lock_rdlock(rw_lock_t * lock)
{
        int ret = 0;

        if (lock == NULL)
                return -1;

        pthread_mutex_lock(&lock->i_lock);

        if (lock->i < 0) {
                pthread_mutex_unlock(&lock->i_lock);
                return -1;
        }

        if (lock->i == 0)
                ret = pthread_mutex_lock(&lock->lock);

        ++(lock->i);

        pthread_mutex_unlock(&lock->i_lock);

        return ret;
}

int rw_lock_wrlock(rw_lock_t * lock)
{
        int ret = 0;

        if (lock == NULL)
                return -1;

        pthread_mutex_lock(&lock->i_lock);

        if (lock->i < 0) {
                pthread_mutex_unlock(&lock->i_lock);
                return -1;
        }

        pthread_mutex_unlock(&lock->i_lock);

        while (1) {
                pthread_mutex_lock(&lock->i_lock);

                if (lock->i == 0) {
                        ++(lock->i);
                        ret = pthread_mutex_lock(&lock->lock);
                        pthread_mutex_unlock(&lock->i_lock);
                        break;
                }

                pthread_mutex_unlock(&lock->i_lock);

                sched_yield();
        }

        return ret;
}

int rw_lock_unlock(rw_lock_t * lock)
{
        int ret = 0;

        if (lock == NULL)
                return -1;

        pthread_mutex_lock(&lock->i_lock);

        if (lock->i < 0) {
                pthread_mutex_unlock(&lock->i_lock);
                return -1;
        }

        --(lock->i);

        if (lock->i == 0)
                ret = pthread_mutex_unlock(&lock->lock);

        pthread_mutex_unlock(&lock->i_lock);

        return ret;
}
