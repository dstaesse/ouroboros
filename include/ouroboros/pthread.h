/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Useful cleanup functions for pthreads
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

#ifndef OUROBOROS_PTHREAD_H
#define OUROBOROS_PTHREAD_H

#include <pthread.h>

/* various cleanup functions for pthread_cleanup_push */
static void __attribute__((unused)) __cleanup_rwlock_unlock(void * rwlock)
{
        pthread_rwlock_unlock((pthread_rwlock_t *) rwlock);
}

static void __attribute__((unused)) __cleanup_mutex_unlock(void * mutex)
{
        pthread_mutex_unlock((pthread_mutex_t *) mutex);
}

#endif /* OUROBOROS_PTHREAD_H */
