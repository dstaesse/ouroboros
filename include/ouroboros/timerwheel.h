/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Ring buffer for incoming SDUs
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

#ifndef OUROBOROS_LIB_TIMERWHEEL_H
#define OUROBOROS_LIB_TIMERWHEEL_H

struct timerwheel;

struct timerwheel * timerwheel_create(time_t resolution,
                                      time_t max_delay);

void                timerwheel_destroy(struct timerwheel * tw);

struct tw_f *       timerwheel_start(struct timerwheel * tw,
                                     void (* func)(void *),
                                     void *              arg,
                                     time_t              delay); /* ms */

int                 timerwheel_restart(struct timerwheel * tw,
                                       struct tw_f *       f,
                                       time_t              delay); /* ms */

void                timerwheel_stop(struct timerwheel * tw,
                                    struct tw_f *       f);

void                timerwheel_move(struct timerwheel * tw);

#endif /* OUROBOROS_LIB_TIMERWHEEL_H */
