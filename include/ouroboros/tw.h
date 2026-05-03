/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Generic deadline-ordered callback queue (timing wheel)
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

#ifndef OUROBOROS_TW_H
#define OUROBOROS_TW_H

#include <ouroboros/cdefs.h>
#include <ouroboros/list.h>

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef void (*tw_fire_fn_t)(void * arg);

struct tw_entry {
        struct list_head next;
        uint64_t         deadline_ns;
        tw_fire_fn_t     fire;
        void *           arg;
        size_t           lvl;
};

__BEGIN_DECLS

int  tw_init(void);

void tw_fini(void);

void tw_init_entry(struct tw_entry * e);

/*
 * Schedule e to fire at deadline_ns. If e is already posted,
 * the previous schedule is cancelled and replaced.
 */
void tw_post(struct tw_entry * e,
             uint64_t          deadline_ns,
             tw_fire_fn_t      fire,
             void *            arg);

void tw_cancel(struct tw_entry * e);

/*
 * Advance the wheel and fire due callbacks. Callbacks run with the wheel
 * unlocked and may call tw_post / tw_cancel on any entry, including the one
 * currently firing. Concurrent tw_move from a second thread is a no-op.
 */
void tw_move(void);

/*
 * Write the absolute deadline of the earliest pending entry to *out.
 * Empty wheel is signalled by out->tv_nsec == -1.
 */
void tw_next_expiry(struct timespec * out);

__END_DECLS

#endif /* OUROBOROS_TW_H */
