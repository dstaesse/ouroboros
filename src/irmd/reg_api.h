/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager - Registered Application Instances
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


#ifndef OUROBOROS_IRMD_REG_API_H
#define OUROBOROS_IRMD_REG_API_H

#include <ouroboros/list.h>
#include <sys/types.h>
#include <pthread.h>

enum api_state {
        REG_I_NULL = 0,
        REG_I_INIT,
        REG_I_SLEEP,
        REG_I_WAKE,
        REG_I_DESTROY
};

struct reg_api {
        struct list_head next;
        pid_t            api;

        /* the api will block on this */
        enum api_state   state;
        pthread_cond_t   state_cond;
        pthread_mutex_t  state_lock;
};

struct reg_api * reg_api_create(pid_t pid);
void             reg_api_destroy(struct reg_api * i);
int              reg_api_sleep(struct reg_api * i);
void             reg_api_wake(struct reg_api * i);

#endif /* OUROBOROS_IRMD_REG_API_H */
