/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Notifier event system using callbacks
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

#ifndef OUROBOROS_LIB_NOTIFIER_H
#define OUROBOROS_LIB_NOTIFIER_H

typedef void (* notifier_fn_t)(int          event,
                               const void * o);

int  notifier_init(void);

void notifier_fini(void);

void notifier_event(int          event,
                    const void * o);

int  notifier_reg(notifier_fn_t callback);

void notifier_unreg(notifier_fn_t callback);

#endif /* OUROBOROS_LIB_NOTIFIER_H */
