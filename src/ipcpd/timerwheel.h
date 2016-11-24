/*
 * Ouroboros - Copyright (C) 2016
 *
 * Ring buffer for incoming SDUs
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#ifndef OUROBOROS_IPCPD_TIMERWHEEL_H
#define OUROBOROS_IPCPD_TIMERWHEEL_H

struct timerwheel;

struct timerwheel * timerwheel_create(unsigned int resolution,
                                      unsigned int max_delay);

void                timerwheel_destroy(struct timerwheel * tw);

int                 timerwheel_add(struct timerwheel * tw,
                                   void (* func)(void *),
                                   void *       arg,
                                   size_t       arg_len,
                                   unsigned int delay); /* ms */

#endif /* OUROBOROS_IPCPD_TIMERWHEEL_H */
