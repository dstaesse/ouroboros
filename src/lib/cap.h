/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Link capacity estimation
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_LIB_CAP_H
#define OUROBOROS_LIB_CAP_H

#include <stddef.h>
#include <stdint.h>

#define CAP_ALIGN 64

struct cap_est {
        uint64_t c_pkt;  /* total packets enqueued (relaxed)  */
        uint64_t c_byt;  /* total bytes enqueued (relaxed)    */
        uint64_t c_idl;  /* times ring seen empty (relaxed)   */

        uint64_t t_gate; /* last window close (ns)            */
        uint64_t t_last; /* last update, to spot a gap (ns)   */
        uint8_t  busy;   /* close in progress (try-lock)      */

        uint64_t t0;     /* window start (ns), 0 = no window  */
        uint64_t q0;     /* ring occupancy at window start    */
        uint64_t pkt0;   /* c_pkt snapshot at window start    */
        uint64_t byt0;   /* c_byt snapshot at window start    */
        uint64_t idl0;   /* c_idl snapshot at window start    */
        uint64_t rate;   /* filtered drain rate (bytes/s)     */

        uint64_t est;    /* published estimate (bytes/s)      */
} __attribute__((aligned(CAP_ALIGN)));

void     cap_clear(struct cap_est * e);

void     cap_update(struct cap_est * e,
                    size_t           qlen,
                    size_t           len);

void     cap_update_at(struct cap_est * e,
                       size_t           qlen,
                       size_t           len,
                       uint64_t         now);

uint64_t cap_rate(const struct cap_est * e);

#endif /* OUROBOROS_LIB_CAP_H */
