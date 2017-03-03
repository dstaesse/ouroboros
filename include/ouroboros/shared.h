/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Shared definitions between IRMd and IPCPs
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OUROBOROS_SHARED_H
#define OUROBOROS_SHARED_H

/* FIXME: To be decided which QoS cubes we support */
typedef enum qos_cube {
        QOS_CUBE_FRC = 0,
        QOS_CUBE_BE,
        QOS_CUBE_VIDEO,
        QOS_CUBE_MAX
} qoscube_t;

#endif /* OUROBOROS_SHARED_H */
