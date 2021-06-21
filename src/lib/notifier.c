/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Notifier event system using callbacks
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

#define _POSIX_C_SOURCE 200112L

#include <ouroboros/errno.h>
#include <ouroboros/notifier.h>
#include <ouroboros/list.h>
#include <ouroboros/utils.h>
#include <ouroboros/pthread.h>

#include <stdlib.h>

struct listener {
        struct list_head next;
        notifier_fn_t    callback;
        void *           obj;
};

struct {
        struct list_head listeners;
        pthread_rwlock_t lock;
} notifier;

int notifier_init(void)
{
        if (pthread_rwlock_init(&notifier.lock, NULL))
                return -1;

        list_head_init(&notifier.listeners);

        return 0;
}

void notifier_fini(void)
{
        struct list_head * p;
        struct list_head * h;

        pthread_rwlock_wrlock(&notifier.lock);

        list_for_each_safe(p, h, &notifier.listeners) {
                struct listener * l = list_entry(p, struct listener, next);
                list_del(&l->next);
                free(l);
        }

        pthread_rwlock_unlock(&notifier.lock);

        pthread_rwlock_destroy(&notifier.lock);
}

void notifier_event(int          event,
                    const void * o)
{
        struct list_head * p;

        pthread_rwlock_rdlock(&notifier.lock);

        pthread_cleanup_push(__cleanup_rwlock_unlock, &notifier.lock)

        list_for_each(p, &notifier.listeners) {
                struct listener * l = list_entry(p, struct listener, next);
                l->callback(l->obj, event, o);
        }

        pthread_cleanup_pop(true);
}

int notifier_reg(notifier_fn_t callback,
                 void *        obj)
{
        struct listener *  l;
        struct list_head * p;

        pthread_rwlock_wrlock(&notifier.lock);

        list_for_each(p, &notifier.listeners) {
                struct listener * l = list_entry(p, struct listener, next);
                if (l->callback == callback) {
                        pthread_rwlock_unlock(&notifier.lock);
                        return -EPERM;
                }
        }

        l = malloc(sizeof(*l));
        if (l == NULL) {
                pthread_rwlock_unlock(&notifier.lock);
                return -ENOMEM;
        }

        l->callback = callback;
        l->obj      = obj;

        list_add_tail(&l->next, &notifier.listeners);

        pthread_rwlock_unlock(&notifier.lock);

        return 0;
}

void notifier_unreg(notifier_fn_t callback)
{
        struct list_head * p;
        struct list_head * h;

        pthread_rwlock_wrlock(&notifier.lock);

        list_for_each_safe(p, h, &notifier.listeners) {
                struct listener * l = list_entry(p, struct listener, next);
                if (l->callback == callback) {
                        list_del(&l->next);
                        free(l);
                        break;
                }
        }

        pthread_rwlock_unlock(&notifier.lock);
}
