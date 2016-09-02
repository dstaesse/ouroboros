/*
 * Ouroboros - Copyright (C) 2016
 *
 * Ring buffer for application processes
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#ifndef OUROBOROS_SHM_AP_RBUFF_H
#define OUROBOROS_SHM_AP_RBUFF_H

#include <sys/types.h>
#include <sys/time.h>
#include <stdbool.h>

struct shm_ap_rbuff;

struct rb_entry {
        ssize_t index;
        int     port_id;
};

/* recv SDUs from N + 1 */
struct shm_ap_rbuff * shm_ap_rbuff_create_n();

/* recv SDUs from N - 1 */
struct shm_ap_rbuff * shm_ap_rbuff_create_s();

/* write SDUs to N - 1 */
struct shm_ap_rbuff * shm_ap_rbuff_open_n(pid_t api);

/* write SDUs to N + 1 */
struct shm_ap_rbuff * shm_ap_rbuff_open_s(pid_t api);

void                  shm_ap_rbuff_close(struct shm_ap_rbuff * rb);

void                  shm_ap_rbuff_destroy(struct shm_ap_rbuff * rb);

int                   shm_ap_rbuff_write(struct shm_ap_rbuff * rb,
                                         struct rb_entry *     e);

struct rb_entry *     shm_ap_rbuff_read(struct shm_ap_rbuff * rb);

int                   shm_ap_rbuff_peek_idx(struct shm_ap_rbuff * rb);

int                   shm_ap_rbuff_peek_b(struct shm_ap_rbuff * rb,
                                          const struct timespec * timeout);

ssize_t               shm_ap_rbuff_read_port(struct shm_ap_rbuff * rb,
                                             int                   port_id);

ssize_t               shm_ap_rbuff_read_port_b(struct shm_ap_rbuff *   rb,
                                               int                     port_id,
                                               const struct timespec * timeout);

void                  shm_ap_rbuff_reset(struct shm_ap_rbuff * rb);
#endif /* OUROBOROS_SHM_AP_RBUFF_H */
