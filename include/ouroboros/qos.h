/*
 * Ouroboros - Copyright (C) 2016 - 2018
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
        uint32_t delay;                /* In ms */
        uint64_t bandwidth;            /* In bits/s */
        uint8_t  availability;         /* Class of 9s */
        uint32_t loss;                 /* Packet loss */
        uint8_t  in_order;             /* In-order delivery, enables FRCT */
        uint32_t maximum_interruption; /* In ms */
} qosspec_t;

qosspec_t qos_raw;
qosspec_t qos_best_effort;
qosspec_t qos_video;
qosspec_t qos_voice;
qosspec_t qos_data;

__BEGIN_DECLS

int qosspec_init(qosspec_t * qs);

int qosspec_fini(qosspec_t * qs);

__END_DECLS

#endif /* OUROBOROS_QOS_H */
