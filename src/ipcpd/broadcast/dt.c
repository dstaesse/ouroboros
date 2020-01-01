/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Forward loop for broadcast
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
#define _POSIX_C_SOURCE 200112L
#endif

#include "config.h"

#define BROADCAST_MTU    1400 /* FIXME: avoid packet copy. */

#define DT               "dt"
#define OUROBOROS_PREFIX DT

#include <ouroboros/endian.h>
#include <ouroboros/dev.h>
#include <ouroboros/errno.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/list.h>
#include <ouroboros/logs.h>
#include <ouroboros/notifier.h>
#include <ouroboros/utils.h>

#include "comp.h"
#include "connmgr.h"
#include "dt.h"
#include "ipcp.h"

#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>

struct nb {
        struct list_head next;

        int              fd;
};

struct {
        struct list_head  nbs;
        size_t            nbs_len;
        pthread_rwlock_t  nbs_lock;

        fset_t *          set;

        pthread_t         reader;
        pthread_t         listener;
} fwd;

static int dt_add_nb(int fd)
{
        struct list_head * p;
        struct nb *        nb;

        pthread_rwlock_wrlock(&fwd.nbs_lock);

        list_for_each(p, &fwd.nbs) {
                struct nb * el = list_entry(p, struct nb, next);
                if (el->fd == fd) {
                        log_dbg("Already know neighbor.");
                        pthread_rwlock_unlock(&fwd.nbs_lock);
                        return -EPERM;
                }
        }

        nb = malloc(sizeof(*nb));
        if (nb == NULL) {
                pthread_rwlock_unlock(&fwd.nbs_lock);
                return -ENOMEM;
        }

        nb->fd = fd;

        list_add_tail(&nb->next, p);

        ++fwd.nbs_len;

        log_dbg("Neighbor %d added.", fd);

        pthread_rwlock_unlock(&fwd.nbs_lock);

        return 0;
}

static int dt_del_nb(int fd)
{
        struct list_head * p;
        struct list_head * h;

        pthread_rwlock_wrlock(&fwd.nbs_lock);

        list_for_each_safe(p, h, &fwd.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                if (nb->fd == fd) {
                        list_del(&nb->next);
                        --fwd.nbs_len;
                        pthread_rwlock_unlock(&fwd.nbs_lock);
                        log_dbg("Neighbor %d deleted.", nb->fd);
                        free(nb);
                        return 0;
                }
        }

        pthread_rwlock_unlock(&fwd.nbs_lock);

        return -EPERM;
}

static void * dt_conn_handle(void * o)
{
        struct conn conn;

        (void) o;

        while (true) {
                if (connmgr_wait(COMPID_DT, &conn)) {
                        log_err("Failed to get next DT connection.");
                        continue;
                }

                /* NOTE: connection acceptance policy could be here. */

                notifier_event(NOTIFY_DT_CONN_ADD, &conn);
        }

        return 0;
}


static void dt_packet(uint8_t * buf,
                      size_t    len,
                      int       in_fd)
{
        struct list_head * p;

        pthread_rwlock_rdlock(&fwd.nbs_lock);

        pthread_cleanup_push((void (*))(void *) pthread_rwlock_unlock,
                             &fwd.nbs_lock);

        list_for_each(p, &fwd.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                if (nb->fd != in_fd)
                        flow_write(nb->fd, buf, len); /* FIXME: avoid copy. */
        }

        pthread_cleanup_pop(true);
}

static void * dt_reader(void * o)
{
        fqueue_t *   fq;
        int          ret;
        uint8_t      buf[BROADCAST_MTU];
        int          fd;
        ssize_t      len;

        (void) o;

        fq = fqueue_create();
        if (fq == NULL)
                return (void *) -1;

        pthread_cleanup_push((void (*) (void *)) fqueue_destroy,
                             (void *) fq);

        while (true) {
                ret = fevent(fwd.set, fq, NULL);
                if (ret < 0) {
                        log_warn("Event error: %d.", ret);
                        continue;
                }

                while ((fd = fqueue_next(fq)) >= 0) {
                        if (fqueue_type(fq) != FLOW_PKT)
                                continue;

                        /* FIXME: avoid copy. */
                        len = flow_read(fd, buf, BROADCAST_MTU);
                        if (len < 0)
                                continue;

                        dt_packet(buf, len, fd);
                }
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

static void handle_event(void *       self,
                         int          event,
                         const void * o)
{
        /* FIXME: Apply correct QoS on graph */
        struct conn *      c;

        (void) self;

        c = (struct conn *) o;

        switch (event) {
        case NOTIFY_DT_CONN_ADD:
                if (dt_add_nb(c->flow_info.fd))
                        log_dbg("Failed to add neighbor.");
                fset_add(fwd.set, c->flow_info.fd);
                break;
        case NOTIFY_DT_CONN_DEL:
                if (dt_del_nb(c->flow_info.fd))
                        log_dbg("Failed to delete neighbor.");
                fset_del(fwd.set, c->flow_info.fd);
                break;
        default:
                break;
        }
}

int dt_init(void)
{
        struct conn_info info;

        memset(&info, 0, sizeof(info));

        strcpy(info.comp_name, DT);
        strcpy(info.comp_name, DT_COMP);

        list_head_init(&fwd.nbs);

        if (notifier_reg(handle_event, NULL))
                goto fail_notifier_reg;

        if (pthread_rwlock_init(&fwd.nbs_lock, NULL))
                goto fail_lock_init;

        fwd.set = fset_create();
        if (fwd.set == NULL)
                goto fail_fset_create;

        if (pthread_create(&fwd.reader, NULL, dt_reader, NULL))
                goto fail_pthread_create_reader;

        if (pthread_create(&fwd.listener, NULL, dt_conn_handle, NULL))
                goto fail_pthread_create_listener;

        if (connmgr_comp_init(COMPID_DT, &info))
                goto fail_connmgr_comp_init;

        fwd.nbs_len = 0;

        return 0;

 fail_connmgr_comp_init:
        pthread_cancel(fwd.listener);
        pthread_join(fwd.listener, NULL);
 fail_pthread_create_listener:
        pthread_cancel(fwd.reader);
        pthread_join(fwd.reader, NULL);
 fail_pthread_create_reader:
        fset_destroy(fwd.set);
 fail_fset_create:
        pthread_rwlock_destroy(&fwd.nbs_lock);
 fail_lock_init:
        notifier_unreg(handle_event);
 fail_notifier_reg:
        return -1;
}

void dt_fini(void)
{
        struct list_head * p;
        struct list_head * h;

        notifier_unreg(handle_event);

        pthread_cancel(fwd.reader);
        pthread_cancel(fwd.listener);

        pthread_join(fwd.reader, NULL);
        pthread_join(fwd.listener, NULL);

        fset_destroy(fwd.set);

        pthread_rwlock_wrlock(&fwd.nbs_lock);

        list_for_each_safe(p, h, &fwd.nbs) {
                struct nb * n = list_entry(p, struct nb, next);
                list_del(&n->next);
                free(n);
        }

        pthread_rwlock_unlock(&fwd.nbs_lock);

        pthread_rwlock_destroy(&fwd.nbs_lock);
}
