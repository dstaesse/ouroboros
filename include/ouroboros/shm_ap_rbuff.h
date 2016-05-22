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

#ifndef SHM_AP_RBUFF
#define SHM_AP_RBUFF_PREFIX "ouroboros_rb_"
#endif

#ifndef SHM_RBUFF_SIZE
#define SHM_RBUFF_SIZE (1 << 12)
#endif

#include <sys/types.h>

struct shm_ap_rbuff;

struct rb_entry {
        ssize_t index;
        int     port_id;
};

struct shm_ap_rbuff * shm_ap_rbuff_create();
struct shm_ap_rbuff * shm_ap_rbuff_open();
void                  shm_ap_rbuff_close(struct shm_ap_rbuff * rb);
void                  shm_ap_rbuff_destroy(struct shm_ap_rbuff * rb);
int                   shm_ap_rbuff_write(struct shm_ap_rbuff * rb,
                                         struct rb_entry * e);
struct rb_entry *     shm_ap_rbuff_read(struct shm_ap_rbuff * rb);
ssize_t               shm_ap_rbuff_read_port(struct shm_ap_rbuff * rb,
                                             int port_id);

#endif /* OUROBOROS_SHM_AP_RBUFF_H */
