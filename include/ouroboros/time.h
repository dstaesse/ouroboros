/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Time utilities
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

#ifndef OUROBOROS_LIB_TIME_H
#define OUROBOROS_LIB_TIME_H

#ifdef MILLION
#undef MILLION
#endif

#ifdef BILLION
#undef BILLION
#endif

#define MILLION  1000000LL
#define BILLION  1000000000LL

#include <time.h>
#include <sys/time.h>
#include <sys/types.h>

#define TIMESPEC_INIT_S(s)   {(s), 0}
#define TIMESPEC_INIT_MS(ms) {(ms) / 1000, ((ms) % 1000) * MILLION}
#define TIMESPEC_INIT_US(us) {(us) / MILLION, ((us) % MILLION) * 1000}
#define TIMESPEC_INIT_NS(ns) {(ns) / BILLION, ((ns) % BILLION)}

#define TS_TO_UINT64(ts)                                                \
        ((uint64_t)(ts).tv_sec * BILLION + (uint64_t)(ts).tv_nsec)

#define TIMEVAL_INIT_S(s)   {(s), 0}
#define TIMEVAL_INIT_MS(ms) {(ms) / 1000, ((ms) % 1000) * 1000}
#define TIMEVAL_INIT_US(us) {(us) / MILLION, ((us) % MILLION)}

/* functions for timespecs */
#define ts_diff_ns(tx, t0) (((tx)->tv_sec - (t0)->tv_sec) * BILLION     \
                            + ((tx)->tv_nsec - (t0)->tv_nsec))
#define ts_diff_us(tx, t0) (((tx)->tv_sec - (t0)->tv_sec) * MILLION     \
                            + ((tx)->tv_nsec - (t0)->tv_nsec) / 1000L)
#define ts_diff_ms(tx, t0) (((tx)->tv_sec - (t0)->tv_sec) * 1000L       \
                            + ((tx)->tv_nsec - (t0)->tv_nsec) / MILLION)

/* functions for timevals are the same */
#define tv_diff_us(tx, t0) (((tx)->tv_sec - (t0)->tv_sec) * MILLION     \
                            + ((tx)->tv_usec - (t0)->tv_usec))
#define tv_diff_ms(tx, t0) (((tx)->tv_sec - (t0)->tv_sec) * 1000L       \
                            + ((tx)->tv_usec - (t0)->tv_usec) / 1000L)

/* functions for timespecs */

#define ts_add(t, intv, res)                                    \
        do {                                                    \
                time_t nanos = 0;                               \
                nanos = (t)->tv_nsec + (intv)->tv_nsec;         \
                (res)->tv_sec = (t)->tv_sec + (intv)->tv_sec;   \
                while (nanos >= BILLION) {                      \
                        nanos -= BILLION;                       \
                        ++((res)->tv_sec);                      \
                }                                               \
                (res)->tv_nsec = nanos;                         \
        } while (0);

#define ts_diff(t, intv, res)                                   \
        do {                                                    \
                time_t nanos = 0;                               \
                nanos = (t)->tv_nsec - (intv)->tv_nsec;         \
                (res)->tv_sec = (t)->tv_sec - (intv)->tv_sec;   \
                while (nanos < 0) {                             \
                        nanos += BILLION;                       \
                        --((res)->tv_sec);                      \
                }                                               \
                (res)->tv_nsec = nanos;                         \
        } while (0);

/* functions for timevals */

#define tv_add(t, intv, res)                                    \
        do {                                                    \
                time_t micros = 0;                              \
                micros = (t)->tv_usec + (intv)->tv_usec;        \
                (res)->tv_sec = (t)->tv_sec + (intv)->tv_sec;   \
                while (micros >= MILLION) {                     \
                        micros -= MILLION;                      \
                        ++((res)->tv_sec);                      \
                }                                               \
                (res)->tv_usec = micros;                        \
        } while (0);

#define tv_diff(t, intv, res)                                   \
        do {                                                    \
                time_t micros = 0;                              \
                micros = (t)->tv_usec - (intv)->tv_usec;        \
                (res)->tv_sec = (t)->tv_sec - (intv)->tv_sec;   \
                while (micros < 0) {                            \
                        micros += MILLION;                      \
                        --((res)->tv_sec);                      \
                }                                               \
                (res)->tv_usec = micros;                        \
        } while (0);


/* copying a timeval into a timespec */
#define tv_to_ts(tv, ts)                                \
        do {                                            \
                (ts)->tv_sec  = (tv)->tv_sec;           \
                (ts)->tv_nsec = (tv)->tv_usec * 1000L;  \
        } while (0);

/* copying a timespec into a timeval (loss of resolution) */
#define ts_to_tv(ts, tv)                                \
        do {                                            \
                (tv)->tv_sec  = (ts)->tv_sec;           \
                (tv)->tv_usec = (ts)->tv_nsec / 1000L;  \
        } while (0);

#endif /* OUROBOROS_LIB_TIME_H */
