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

#include <ouroboros/config.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/errno.h>

#include "reg_api.h"

#include <stdlib.h>
#include <stdbool.h>
#include <time.h>

struct reg_api * reg_api_create(pid_t api)
{
        struct reg_api * i;
        i = malloc(sizeof(*i));
        if (i == NULL)
                return NULL;

        i->api   = api;
        i->state = REG_I_INIT;

        pthread_mutex_init(&i->state_lock, NULL);
        pthread_cond_init(&i->state_cond, NULL);

        INIT_LIST_HEAD(&i->next);

        return i;
}

void reg_api_destroy(struct reg_api * i)
{
        if (i == NULL)
                return;

        pthread_mutex_lock(&i->state_lock);

        if (i->state == REG_I_INIT)
                i->state = REG_I_NULL;

        if (i->state != REG_I_NULL)
                i->state = REG_I_DESTROY;

        pthread_cond_signal(&i->state_cond);

        while (i->state != REG_I_NULL)
                pthread_cond_wait(&i->state_cond, &i->state_lock);

        pthread_mutex_unlock(&i->state_lock);

        pthread_cond_destroy(&i->state_cond);
        pthread_mutex_destroy(&i->state_lock);

        free(i);
}

int reg_api_sleep(struct reg_api * i)
{
        struct timespec timeout = {(IRMD_ACCEPT_TIMEOUT / 1000),
                                   (IRMD_ACCEPT_TIMEOUT % 1000) * MILLION};
        struct timespec now;
        struct timespec dl;

        int ret = 0;

        if (i == NULL)
                return -EINVAL;

        clock_gettime(CLOCK_REALTIME, &now);

        ts_add(&now, &timeout, &dl);

        pthread_mutex_lock(&i->state_lock);
        if (i->state != REG_I_INIT) {
                pthread_mutex_unlock(&i->state_lock);
                return -EINVAL;
        }

        i->state = REG_I_SLEEP;

        while (i->state == REG_I_SLEEP) {
                if ((ret = -pthread_cond_timedwait(&i->state_cond,
                                                   &i->state_lock,
                                                   &dl)) == -ETIMEDOUT) {
                        i->state = REG_I_INIT;
                        break;
                } else {
                        i->state = REG_I_NULL;
                        pthread_cond_broadcast(&i->state_cond);
                }
        }

        pthread_mutex_unlock(&i->state_lock);

        return ret;
}

void reg_api_wake(struct reg_api * i)
{
        pthread_mutex_lock(&i->state_lock);

        if (i->state == REG_I_NULL) {
                pthread_mutex_unlock(&i->state_lock);
                return;
        }

        i->state = REG_I_WAKE;

        pthread_cond_broadcast(&i->state_cond);

        while (i->state == REG_I_WAKE)
                pthread_cond_wait(&i->state_cond, &i->state_lock);

        pthread_mutex_unlock(&i->state_lock);
}
