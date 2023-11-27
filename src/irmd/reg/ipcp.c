/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * The IPC Resource Manager - Registry - IPCPs
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#include <ouroboros/errno.h>
#include <ouroboros/hash.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/pthread.h>
#include <ouroboros/time_utils.h>

#include "ipcp.h"

#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

struct reg_ipcp * reg_ipcp_create(const struct ipcp_info * info)
{
        struct reg_ipcp *  ipcp;
        pthread_condattr_t cattr;

        ipcp = malloc(sizeof(*ipcp));
        if (ipcp == NULL)
                goto fail_malloc;

        if (pthread_mutex_init(&ipcp->mtx, NULL))
                goto fail_mutex;

        if (pthread_condattr_init(&cattr))
                goto fail_cattr;
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&ipcp->cond, &cattr))
                goto fail_cond;

        memcpy(&ipcp->info, info, sizeof(*info));

        pthread_condattr_destroy(&cattr);

        ipcp->layer = NULL;
        ipcp->state = IPCP_BOOT;

        list_head_init(&ipcp->next);

        return ipcp;

 fail_cond:
        pthread_condattr_destroy(&cattr);
 fail_cattr:
        pthread_mutex_destroy(&ipcp->mtx);
 fail_mutex:
        free(ipcp);
 fail_malloc:
        return NULL;
}

void reg_ipcp_destroy(struct reg_ipcp * ipcp)
{
        assert(ipcp);

        pthread_mutex_lock(&ipcp->mtx);

        while (ipcp->state == IPCP_BOOT)
                pthread_cond_wait(&ipcp->cond, &ipcp->mtx);

        free(ipcp->layer);

        pthread_mutex_unlock(&ipcp->mtx);

        pthread_cond_destroy(&ipcp->cond);
        pthread_mutex_destroy(&ipcp->mtx);

        free(ipcp);
}

void reg_ipcp_set_state(struct reg_ipcp * ipcp,
                        enum ipcp_state   state)
{
        pthread_mutex_lock(&ipcp->mtx);

        ipcp->state = state;
        pthread_cond_broadcast(&ipcp->cond);

        pthread_mutex_unlock(&ipcp->mtx);
}

int reg_ipcp_wait_boot(struct reg_ipcp * ipcp)
{
        int             ret = 0;
        struct timespec dl;
        struct timespec to = {SOCKET_TIMEOUT / 1000,
                              (SOCKET_TIMEOUT % 1000) * MILLION};

        clock_gettime(PTHREAD_COND_CLOCK, &dl);
        ts_add(&dl, &to, &dl);

        pthread_mutex_lock(&ipcp->mtx);

        while (ipcp->state == IPCP_BOOT && ret != ETIMEDOUT)
                ret = pthread_cond_timedwait(&ipcp->cond, &ipcp->mtx, &dl);

        if (ret == ETIMEDOUT) {
                kill(ipcp->pid, SIGTERM);
                ipcp->state = IPCP_NULL;
                pthread_cond_signal(&ipcp->cond);
        }

        if (ipcp->state != IPCP_LIVE) {
                pthread_mutex_unlock(&ipcp->mtx);
                return -1;
        }

        pthread_mutex_unlock(&ipcp->mtx);

        return 0;
}
