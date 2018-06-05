/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Quality of Service cube
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

#include <ouroboros/qoscube.h>

#include <string.h>

static struct qos_spec qos_raw = {
        .delay                = UINT32_MAX,
        .bandwidth            = UINT64_MAX,
        .availability         = 0,
        .in_order             = 0,
        .maximum_interruption = UINT32_MAX
};

static struct qos_spec qos_best_effort = {
        .delay                = UINT32_MAX,
        .bandwidth            = UINT64_MAX,
        .availability         = 0,
        .in_order             = 1,
        .maximum_interruption = UINT32_MAX
};

static struct qos_spec qos_video = {
        .delay                = 100,
        .bandwidth            = UINT64_MAX,
        .availability         = 3,
        .in_order             = 1,
        .maximum_interruption = 100
};

static struct qos_spec qos_voice = {
        .delay                = 10,
        .bandwidth            = 100000,
        .availability         = 5,
        .in_order             = 1,
        .maximum_interruption = 50
};

qoscube_t qos_spec_to_cube(qosspec_t qs)
{
        if (qs.delay <= qos_voice.delay &&
            qs.bandwidth <= qos_voice.bandwidth &&
            qs.availability >= qos_voice.availability &&
            qs.maximum_interruption <= qos_voice.maximum_interruption)
                return QOS_CUBE_VOICE;
        else if (qs.delay <= qos_video.delay &&
                 qs.bandwidth <= qos_video.bandwidth &&
                 qs.availability >= qos_video.availability &&
                 qs.maximum_interruption <= qos_video.maximum_interruption)
                return QOS_CUBE_VIDEO;
        else if (qs.in_order == 1)
                return QOS_CUBE_BE;
        else
                return QOS_CUBE_RAW;
}

qosspec_t qos_cube_to_spec(qoscube_t qc)
{
        switch (qc) {
        case QOS_CUBE_VOICE:
                return qos_voice;
        case QOS_CUBE_VIDEO:
                return qos_video;
        case QOS_CUBE_BE:
                return qos_best_effort;
        default:
                return qos_raw;
        }
}
