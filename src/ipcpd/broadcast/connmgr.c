/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Handles connections between components
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

#define OUROBOROS_PREFIX "connection-manager"

#include <ouroboros/dev.h>
#include <ouroboros/cacep.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/logs.h>
#include <ouroboros/notifier.h>

#include "comp.h"
#include "connmgr.h"
#include "enroll.h"
#include "ipcp.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

enum connmgr_state {
        CONNMGR_NULL = 0,
        CONNMGR_INIT,
        CONNMGR_RUNNING
};

struct conn_el {
        struct list_head next;
        struct conn      conn;
};

struct comp {
        struct conn_info info;

        struct list_head conns;
        struct list_head pending;

        pthread_cond_t   cond;
        pthread_mutex_t  lock;
};

struct {
        struct comp        comps[COMPID_MAX];
        enum connmgr_state state;

        pthread_t          acceptor;
} connmgr;

static int get_id_by_name(const char * name)
{
        enum comp_id i;

        for (i = 0; i < COMPID_MAX; ++i)
                if (strcmp(name, connmgr.comps[i].info.comp_name) == 0)
                        return i;

        return -1;
}

static int get_conn_by_fd(int           fd,
                          enum comp_id  id,
                          struct conn * conn)
{
        struct list_head * p;

        pthread_mutex_lock(&connmgr.comps[id].lock);

        list_for_each(p, &connmgr.comps[id].conns) {
                struct conn_el * c =
                        list_entry(p, struct conn_el, next);
                if (c->conn.flow_info.fd == fd) {
                        *conn = c->conn;
                        pthread_mutex_unlock(&connmgr.comps[id].lock);
                        return 0;
                }
        }

        pthread_mutex_unlock(&connmgr.comps[id].lock);

        return -1;
}

static int add_comp_conn(enum comp_id       id,
                         int                fd,
                         qosspec_t          qs,
                         struct conn_info * rcv_info)
{
        struct conn_el * el;

        el = malloc(sizeof(*el));
        if (el == NULL) {
                log_err("Not enough memory.");
                return -1;
        }

        el->conn.conn_info    = *rcv_info;
        el->conn.flow_info.fd = fd;
        el->conn.flow_info.qs = qs;

        pthread_mutex_lock(&connmgr.comps[id].lock);

        list_add(&el->next, &connmgr.comps[id].pending);
        pthread_cond_signal(&connmgr.comps[id].cond);

        pthread_mutex_unlock(&connmgr.comps[id].lock);

        return 0;
}

static void * flow_acceptor(void * o)
{
        int               fd;
        qosspec_t         qs;
        struct conn_info  rcv_info;
        struct conn_info  fail_info;

        (void) o;

        memset(&fail_info, 0, sizeof(fail_info));

        while (true) {
                int id;

                fd = flow_accept(&qs, NULL);
                if (fd < 0) {
                        if (fd != -EIRMD)
                                log_warn("Flow accept failed: %d", fd);
                        continue;
                }

                if (cacep_rcv(fd, &rcv_info)) {
                        log_dbg("Error establishing application connection.");
                        flow_dealloc(fd);
                        continue;
                }

                id = get_id_by_name(rcv_info.comp_name);
                if (id < 0) {
                        log_dbg("Connection request for unknown component %s.",
                                rcv_info.comp_name);
                        cacep_snd(fd, &fail_info);
                        flow_dealloc(fd);
                        continue;
                }

                assert(id < COMPID_MAX);

                if (cacep_snd(fd, &connmgr.comps[id].info)) {
                        log_dbg("Failed to respond to request.");
                        flow_dealloc(fd);
                        continue;
                }

                if (add_comp_conn(id, fd, qs, &rcv_info)) {
                        log_dbg("Failed to add new connection.");
                        flow_dealloc(fd);
                        continue;
                }
        }

        return (void *) 0;
}

static void handle_event(void *       self,
                         int          event,
                         const void * o)
{
        struct conn conn;

        (void) self;

        if (!(event == NOTIFY_DT_FLOW_UP ||
              event == NOTIFY_DT_FLOW_DOWN ||
              event == NOTIFY_DT_FLOW_DEALLOC))
                return;

        if (get_conn_by_fd(*((int *) o), COMPID_DT, &conn))
                return;

        switch (event) {
        case NOTIFY_DT_FLOW_UP:
                notifier_event(NOTIFY_DT_CONN_UP, &conn);
                break;
        case NOTIFY_DT_FLOW_DOWN:
                notifier_event(NOTIFY_DT_CONN_DOWN, &conn);
                break;
        case NOTIFY_DT_FLOW_DEALLOC:
                notifier_event(NOTIFY_DT_CONN_DEL, &conn);
                break;
        default:
                break;
        }
}

int connmgr_init(void)
{
        connmgr.state = CONNMGR_INIT;

        if (notifier_reg(handle_event, NULL))
                return -1;

        return 0;
}

void connmgr_fini(void)
{
        int i;

        notifier_unreg(handle_event);

        if (connmgr.state == CONNMGR_RUNNING)
                pthread_join(connmgr.acceptor, NULL);

        for (i = 0; i < COMPID_MAX; ++i)
                connmgr_comp_fini(i);
}

int connmgr_start(void)
{
        if (pthread_create(&connmgr.acceptor, NULL, flow_acceptor, NULL))
                return -1;

        connmgr.state = CONNMGR_RUNNING;

        return 0;
}

void connmgr_stop(void)
{
        if (connmgr.state == CONNMGR_RUNNING)
                pthread_cancel(connmgr.acceptor);
}

int connmgr_comp_init(enum comp_id             id,
                      const struct conn_info * info)
{
        struct comp * comp;

        assert(id >= 0 && id < COMPID_MAX);

        comp = connmgr.comps + id;

        if (pthread_mutex_init(&comp->lock, NULL))
                return -1;

        if (pthread_cond_init(&comp->cond, NULL)) {
                pthread_mutex_destroy(&comp->lock);
                return -1;
        }

        list_head_init(&comp->conns);
        list_head_init(&comp->pending);

        memcpy(&connmgr.comps[id].info, info, sizeof(connmgr.comps[id].info));

        return 0;
}

void connmgr_comp_fini(enum comp_id id)
{
        struct list_head * p;
        struct list_head * h;
        struct comp *      comp;

        assert(id >= 0 && id < COMPID_MAX);

        if (strlen(connmgr.comps[id].info.comp_name) == 0)
                return;

        comp = connmgr.comps + id;

        pthread_mutex_lock(&comp->lock);

        list_for_each_safe(p, h, &comp->conns) {
                struct conn_el * e = list_entry(p, struct conn_el, next);
                list_del(&e->next);
                free(e);
        }

        list_for_each_safe(p, h, &comp->pending) {
                struct conn_el * e = list_entry(p, struct conn_el, next);
                list_del(&e->next);
                free(e);
        }

        pthread_mutex_unlock(&comp->lock);

        pthread_cond_destroy(&comp->cond);
        pthread_mutex_destroy(&comp->lock);

        memset(&connmgr.comps[id].info, 0, sizeof(connmgr.comps[id].info));
}

int connmgr_ipcp_connect(const char * dst,
                         const char * component,
                         qosspec_t    qs)
{
        struct conn_el * ce;
        int              id;

        assert(dst);
        assert(component);

        ce = malloc(sizeof(*ce));
        if (ce == NULL) {
                log_dbg("Out of memory.");
                return -1;
        }

        id = get_id_by_name(component);
        if (id < 0) {
                log_dbg("No such component: %s", component);
                free(ce);
                return -1;
        }

        if (connmgr_alloc(id, dst, &qs, &ce->conn)) {
                free(ce);
                return -1;
        }

        if (strlen(dst) > DST_MAX_STRLEN) {
                log_warn("Truncating dst length for connection.");
                memcpy(ce->conn.flow_info.dst, dst, DST_MAX_STRLEN);
                ce->conn.flow_info.dst[DST_MAX_STRLEN] = '\0';
        } else {
                strcpy(ce->conn.flow_info.dst, dst);
        }

        pthread_mutex_lock(&connmgr.comps[id].lock);

        list_add(&ce->next, &connmgr.comps[id].conns);

        pthread_mutex_unlock(&connmgr.comps[id].lock);

        return 0;
}

int connmgr_ipcp_disconnect(const char * dst,
                            const char * component)
{
        struct list_head * p;
        struct list_head * h;
        int                id;

        assert(dst);
        assert(component);

        id = get_id_by_name(component);
        if (id < 0)
                return -1;

        pthread_mutex_lock(&connmgr.comps[id].lock);

        list_for_each_safe(p,h, &connmgr.comps[id].conns) {
                struct conn_el * el = list_entry(p, struct conn_el, next);
                if (strcmp(el->conn.flow_info.dst, dst) == 0) {
                        int ret;
                        pthread_mutex_unlock(&connmgr.comps[id].lock);
                        list_del(&el->next);
                        ret = connmgr_dealloc(id, &el->conn);
                        free(el);
                        return ret;
                }
        }

        pthread_mutex_unlock(&connmgr.comps[id].lock);

        return 0;
}

int connmgr_alloc(enum comp_id  id,
                  const char *  dst,
                  qosspec_t *   qs,
                  struct conn * conn)
{
        assert(id >= 0 && id < COMPID_MAX);
        assert(dst);

        conn->flow_info.fd = flow_alloc(dst, qs, NULL);
        if (conn->flow_info.fd < 0) {
                log_dbg("Failed to allocate flow to %s.", dst);
                return -1;
        }

        if (qs != NULL)
                conn->flow_info.qs = *qs;
        else
                memset(&conn->flow_info.qs, 0, sizeof(conn->flow_info.qs));

        log_dbg("Sending cacep info for protocol %s to fd %d.",
                connmgr.comps[id].info.protocol, conn->flow_info.fd);

        if (cacep_snd(conn->flow_info.fd, &connmgr.comps[id].info)) {
                log_dbg("Failed to create application connection.");
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (cacep_rcv(conn->flow_info.fd, &conn->conn_info)) {
                log_dbg("Failed to connect to application.");
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (strcmp(connmgr.comps[id].info.protocol, conn->conn_info.protocol)) {
                log_dbg("Unknown protocol (requested %s, got %s).",
                        connmgr.comps[id].info.protocol,
                        conn->conn_info.protocol);
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (connmgr.comps[id].info.pref_version !=
            conn->conn_info.pref_version) {
                log_dbg("Unknown protocol version.");
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (connmgr.comps[id].info.pref_syntax != conn->conn_info.pref_syntax) {
                log_dbg("Unknown protocol syntax.");
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        switch (id) {
        case COMPID_DT:
                notifier_event(NOTIFY_DT_CONN_ADD, conn);
                break;
        default:
                break;
        }

        return 0;
}

int connmgr_dealloc(enum comp_id  id,
                    struct conn * conn)
{
        switch (id) {
        case COMPID_DT:
                notifier_event(NOTIFY_DT_CONN_DEL, conn);
                break;
        default:
                break;
        }

        return flow_dealloc(conn->flow_info.fd);
}


int connmgr_wait(enum comp_id  id,
                 struct conn * conn)
{
        struct conn_el * el;
        struct comp *    comp;

        assert(id >= 0 && id < COMPID_MAX);
        assert(conn);

        comp = connmgr.comps + id;

        pthread_mutex_lock(&comp->lock);

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) &comp->lock);

        while (list_is_empty(&comp->pending))
                pthread_cond_wait(&comp->cond, &comp->lock);

        pthread_cleanup_pop(false);

        el = list_first_entry((&comp->pending), struct conn_el, next);
        if (el == NULL) {
                pthread_mutex_unlock(&comp->lock);
                return -1;
        }

        *conn = el->conn;

        list_del(&el->next);
        list_add(&el->next, &connmgr.comps[id].conns);

        pthread_mutex_unlock(&comp->lock);

        return 0;
}
