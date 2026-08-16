/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Quality of Service specification
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

#ifndef OUROBOROS_QOS_H
#define OUROBOROS_QOS_H

#include <stdint.h>
#include <stdbool.h>

#define DEFAULT_PEER_TIMEOUT 120000

/* qos_spec.service: framing / reliability class. */
enum qos_service {
        SVC_RAW     = 0, /* No FRCT; best-effort raw messages            */
        SVC_MESSAGE = 1, /* FRCT, ordered messages, optional reliability */
        SVC_STREAM  = 2, /* FRCT, reliable ordered byte stream           */
};

typedef struct qos_spec {
        uint8_t  service;       /* enum qos_service; gates FRCT (>0).         */
        uint32_t delay;         /* In ms.                                     */
        uint64_t bandwidth;     /* In bits/s.                                 */
        uint8_t  availability;  /* Class of 9s.                               */
        uint32_t loss;          /* Packet loss.                               */
        uint32_t ber;           /* Bit error rate, errors per billion bits.   */
        uint32_t max_gap;       /* In ms.                                     */
        uint32_t timeout;       /* Peer timeout time, in ms, 0 = no timeout.  */
} qosspec_t;

/* "_safe" = integrity check (ber=0). "rt" = latency over reliability. */

static const qosspec_t qos_raw = {
        .service      = SVC_RAW,
        .delay        = UINT32_MAX,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = 1,
        .ber          = 1,
        .max_gap      = UINT32_MAX,
        .timeout      = 0
};

static const qosspec_t qos_raw_safe = {
        .service      = SVC_RAW,
        .delay        = UINT32_MAX,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = 1,
        .ber          = 0,
        .max_gap      = UINT32_MAX,
        .timeout      = 0
};

static const qosspec_t qos_rt = {
        .service      = SVC_MESSAGE,
        .delay        = 100,
        .bandwidth    = UINT64_MAX,
        .availability = 3,
        .loss         = 1,
        .ber          = 1,
        .max_gap      = 100,
        .timeout      = DEFAULT_PEER_TIMEOUT
};

static const qosspec_t qos_rt_safe = {
        .service      = SVC_MESSAGE,
        .delay        = 100,
        .bandwidth    = UINT64_MAX,
        .availability = 3,
        .loss         = 1,
        .ber          = 0,
        .max_gap      = 100,
        .timeout      = DEFAULT_PEER_TIMEOUT
};

static const qosspec_t qos_msg = {
        .service      = SVC_MESSAGE,
        .delay        = 1000,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = 0,
        .ber          = 0,
        .max_gap      = 2000,
        .timeout      = DEFAULT_PEER_TIMEOUT
};

static const qosspec_t qos_stream = {
        .service      = SVC_STREAM,
        .delay        = 1000,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = 0,
        .ber          = 0,
        .max_gap      = 2000,
        .timeout      = DEFAULT_PEER_TIMEOUT
};

#endif /* OUROBOROS_QOS_H */
