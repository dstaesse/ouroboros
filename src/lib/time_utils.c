/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Time utilities
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#include <ouroboros/config.h>
#include <ouroboros/time_utils.h>
#include <stddef.h>

/* functions for timespecs */

/* add intv to t and store it in res*/
int ts_add(const struct timespec * t,
           const struct timespec * intv,
           struct timespec *       res)
{
        time_t nanos = 0;

        if (t == NULL || intv == NULL || res == NULL)
                return -1;

        nanos = t->tv_nsec + intv->tv_nsec;

        res->tv_sec = t->tv_sec + intv->tv_sec;
        while (nanos >= BILLION) {
                nanos -= BILLION;
                ++(res->tv_sec);
        }

        res->tv_nsec = nanos;

        return 0;
}

/* subtract intv from t and stores it in res */
int ts_diff(const struct timespec * t,
            const struct timespec * intv,
            struct timespec *       res)
{
        time_t nanos = 0;

        if (t == NULL || intv == NULL || res == NULL)
                return -1;

        nanos = t->tv_nsec - intv->tv_nsec;

        res->tv_sec = t->tv_sec - intv->tv_sec;
        while (nanos < 0) {
                nanos += BILLION;
                --(res->tv_sec);
        }
        res->tv_nsec = nanos;

        return 0;
}

/* functions for timevals */

/* add intv to t and store it in res*/
int tv_add(const struct timeval * t,
           const struct timeval * intv,
           struct timeval *       res)
{
        time_t micros = 0;

        if (t == NULL || intv == NULL || res == NULL)
                return -1;

        micros = t->tv_usec + intv->tv_usec;

        res->tv_sec = t->tv_sec + intv->tv_sec;
        while (micros >= MILLION) {
                micros -= MILLION;
                ++(res->tv_sec);
        }
        res->tv_usec = micros;

        return 0;
}

/* subtract intv from t and stores it in res */
int tv_diff(const struct timeval * t,
            const struct timeval * intv,
            struct timeval       * res)
{
        time_t micros = 0;

        if (t == NULL || intv == NULL || res == NULL)
                return -1;

        micros = t->tv_usec - intv->tv_usec;

        res->tv_sec = t->tv_sec - intv->tv_sec;
        while (micros < 0) {
                micros += MILLION;
                --(res->tv_sec);
        }
        res->tv_usec = micros;

        return 0;
}

int tv_to_ts(const struct timeval * src,
             struct timespec *      dst)
{
        if (src == NULL || dst == NULL)
                return -1;

        dst->tv_sec  = src->tv_sec;
        dst->tv_nsec = src->tv_usec * 1000L;

        return 0;
}

/* copying a timespec into a timeval (loss of resolution) */
int ts_to_tv(const struct timespec * src,
             struct timeval *        dst)
{
        if (src == NULL || dst == NULL)
                return -1;

        dst->tv_sec  = src->tv_sec;
        dst->tv_usec = src->tv_nsec / 1000L;

        return 0;
}
