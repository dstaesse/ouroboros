/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Quality of Service cube specifications
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

#include <ouroboros/qos.h>
#include <ouroboros/errno.h>

#include <stdint.h>
#include <stddef.h>

qosspec_t qos_raw = {
        .delay                = UINT32_MAX,
        .bandwidth            = UINT64_MAX,
        .availability         = 0,
        .in_order             = 0,
        .maximum_interruption = UINT32_MAX
};

qosspec_t qos_best_effort = {
        .delay                = UINT32_MAX,
        .bandwidth            = UINT64_MAX,
        .availability         = 0,
        .in_order             = 1,
        .maximum_interruption = UINT32_MAX
};

qosspec_t qos_video = {
        .delay                = 100,
        .bandwidth            = UINT64_MAX,
        .availability         = 3,
        .in_order             = 1,
        .maximum_interruption = 100
};

qosspec_t qos_voice = {
        .delay                = 10,
        .bandwidth            = 100000,
        .availability         = 5,
        .in_order             = 1,
        .maximum_interruption = 50
};

int qosspec_init(qosspec_t * qs)
{
        if (qs == NULL)
                return -EINVAL;

        qs->delay = UINT32_MAX;
        qs->bandwidth = UINT64_MAX;
        qs->availability = 0;
        qs->maximum_interruption = UINT32_MAX;

        return 0;
}

int qosspec_fini(qosspec_t * qs)
{
        if (qs == NULL)
                return -EINVAL;

        qs = NULL;

        return 0;
}
