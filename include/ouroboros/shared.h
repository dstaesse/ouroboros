/*
 * Ouroboros - Copyright (C) 2016
 *
 * Shared definitions between IRMd and IPCPs
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef OUROBOROS_SHARED_H
#define OUROBOROS_SHARED_H

/* FIXME: To be decided which QoS cubes we support */
enum qos_cube {
        QOS_CUBE_BE = 0,
        QOS_CUBE_VIDEO,
        QOS_MAX
};

#endif /* OUROBOROS_SHARED_H */
