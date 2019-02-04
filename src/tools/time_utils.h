/*
 * Ouroboros - Copyright (C) 2016 - 2019
 *
 * Time utilities
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following
 * disclaimer in the documentation and/or other materials provided
 * with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived
 * from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */
#ifndef OUROBOROS_TOOLS_TIME_UTILS_H
#define OUROBOROS_TOOLS_TIME_UTILS_H

#ifdef MILLION
#undef MILLION
#endif

#ifdef BILLION
#undef BILLION
#endif

#define MILLION  1000000L
#define BILLION  1000000000L

#include <time.h>
#include <sys/time.h>

/* functions for timespecs */
#define ts_diff_ns(t0, tx) (((tx)->tv_sec - (t0)->tv_sec) * BILLION     \
                            + ((tx)->tv_nsec - (t0)->tv_nsec))
#define ts_diff_us(t0, tx) (((tx)->tv_sec - (t0)->tv_sec) * MILLION     \
                            + ((tx)->tv_nsec - (t0)->tv_nsec) / 1000L)
#define ts_diff_ms(t0, tx) (((tx)->tv_sec - (t0)->tv_sec) * 1000L       \
                            + ((tx)->tv_nsec - (t0)->tv_nsec) / MILLION)

/* functions for timevals are the same */
#define tv_diff_us(t0, tx) (((tx)->tv_sec - (t0)->tv_sec) * MILLION     \
                            + ((tx)->tv_usec - (t0)->tv_usec) / 1000L)
#define tv_diff_ms(t0, tx) (((tx)->tv_sec - (t0)->tv_sec) * 1000L       \
                            + ((tx)->tv_usec - (t0)->tv_usec) / MILLION)

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
                nanos = (t)->tv_usec + (intv)->tv_usec;         \
                (res)->tv_sec = (t)->tv_sec + (intv)->tv_sec;   \
                while (micros >= MILLION) {                     \
                        micros -= MILLION;                      \
                        ++((res)->tv_sec);                      \
                }                                               \
                (res)->tv_nsec = nanos;                         \
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

#endif /* OUROBOROS_TOOLS_TIME_UTILS_H */
