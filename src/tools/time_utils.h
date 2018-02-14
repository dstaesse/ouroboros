/*
 * Ouroboros - Copyright (C) 2016 - 2018
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
#include <limits.h> /* LONG_MAX */

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
int ts_add(const struct timespec * t,
           const struct timespec * intv,
           struct timespec *       res);

int ts_diff(const struct timespec * t,
            const struct timespec * intv,
            struct timespec *       res);

/* functions for timevals */
int tv_add(const struct timeval * t,
           const struct timeval * intv,
           struct timeval *       res);

int tv_diff(const struct timeval * t,
            const struct timeval * intv,
            struct timeval *       res);

/* copying a timeval into a timespec */
int tv_to_ts(const struct timeval * src,
             struct timespec *      dst);

/* copying a timespec into a timeval (loss of resolution) */
int ts_to_tv(const struct timespec * src,
             struct timeval *        dst);

#endif /* OUROBOROS_TOOLS_TIME_UTILS_H */
