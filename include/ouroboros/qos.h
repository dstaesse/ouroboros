/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Quality of Service specification
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_QOS_H
#define OUROBOROS_QOS_H

#include <stdint.h>
#include <stdbool.h>

typedef struct qos_spec {
        uint32_t delay;         /* In ms */
        uint64_t bandwidth;     /* In bits/s */
        uint8_t  availability;  /* Class of 9s */
        uint32_t loss;          /* Packet loss */
        uint32_t ber;           /* Bit error rate, errors per billion bits */
        uint8_t  in_order;      /* In-order delivery, enables FRCT */
        uint32_t max_gap;       /* In ms */
        uint16_t cypher_s;      /* Cypher strength, 0 = no encryption */
} qosspec_t;

static const qosspec_t qos_raw = {
        .delay        = UINT32_MAX,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = 1,
        .ber          = 1,
        .in_order     = 0,
        .max_gap      = UINT32_MAX,
        .cypher_s     = 0
};

static const qosspec_t qos_raw_no_errors = {
        .delay        = UINT32_MAX,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = 1,
        .ber          = 0,
        .in_order     = 0,
        .max_gap      = UINT32_MAX,
        .cypher_s     = 0
};

static const qosspec_t qos_raw_crypt = {
        .delay        = UINT32_MAX,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = 1,
        .ber          = 0,
        .in_order     = 0,
        .max_gap      = UINT32_MAX,
        .cypher_s     = 256
};

static const qosspec_t qos_best_effort = {
        .delay        = UINT32_MAX,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = 1,
        .ber          = 0,
        .in_order     = 1,
        .max_gap      = UINT32_MAX,
        .cypher_s     = 0
};

static const qosspec_t qos_best_effort_crypt = {
        .delay        = UINT32_MAX,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = 1,
        .ber          = 0,
        .in_order     = 1,
        .max_gap      = UINT32_MAX,
        .cypher_s     = 256
};

static const qosspec_t qos_video   = {
        .delay        = 100,
        .bandwidth    = UINT64_MAX,
        .availability = 3,
        .loss         = 1,
        .ber          = 0,
        .in_order     = 1,
        .max_gap      = 100,
        .cypher_s     = 0
};

static const qosspec_t qos_video_crypt   = {
        .delay        = 100,
        .bandwidth    = UINT64_MAX,
        .availability = 3,
        .loss         = 1,
        .ber          = 0,
        .in_order     = 1,
        .max_gap      = 100,
        .cypher_s     = 256
};

static const qosspec_t qos_voice = {
        .delay        = 50,
        .bandwidth    = 100000,
        .availability = 5,
        .loss         = 1,
        .ber          = 0,
        .in_order     = 1,
        .max_gap      = 50,
        .cypher_s     = 0
};

static const qosspec_t qos_voice_crypt = {
        .delay        = 50,
        .bandwidth    = 100000,
        .availability = 5,
        .loss         = 1,
        .ber          = 0,
        .in_order     = 1,
        .max_gap      = 50,
        .cypher_s     = 256
};

static const qosspec_t qos_data = {
        .delay        = 1000,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = 0,
        .ber          = 0,
        .in_order     = 1,
        .max_gap      = 2000,
        .cypher_s     = 0
};

static const qosspec_t qos_data_crypt = {
        .delay        = 1000,
        .bandwidth    = 0,
        .availability = 0,
        .loss         = 0,
        .ber          = 0,
        .in_order     = 1,
        .max_gap      = 2000,
        .cypher_s     = 256
};

#endif /* OUROBOROS_QOS_H */
