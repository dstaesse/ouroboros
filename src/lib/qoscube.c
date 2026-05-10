/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Quality of Service cube
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

#include <ouroboros/qos.h>
#include <ouroboros/qoscube.h>

#include <string.h>



qoscube_t qos_spec_to_cube(qosspec_t qs)
{
        if (qs.delay <= 50 && qs.bandwidth <= 100000
            && qs.availability >= 5 && qs.max_gap <= 50)
                return QOS_CUBE_VOICE;
        else if (qs.delay <= 100 && qs.availability >= 3
                 && qs.max_gap <= 100)
                return QOS_CUBE_VIDEO;
        else
                return QOS_CUBE_BE;
}
