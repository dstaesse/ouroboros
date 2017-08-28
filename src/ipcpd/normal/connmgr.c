/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Handles AE connections
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

#define _POSIX_C_SOURCE 200112L

#define OUROBOROS_PREFIX "Connection manager"

#include <ouroboros/dev.h>
#include <ouroboros/cacep.h>
#include <ouroboros/cdap.h>
#include <ouroboros/errno.h>
#include <ouroboros/list.h>
#include <ouroboros/logs.h>

#include "ae.h"
#include "connmgr.h"
#include "enroll.h"
#include "ipcp.h"
#include "ribmgr.h"

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

struct ae {
        struct nbs *     nbs;
        struct conn_info info;

        struct list_head conns;
        struct list_head pending;

        pthread_cond_t   cond;
        pthread_mutex_t  lock;
};

struct {
        struct ae          aes[AEID_MAX];
        enum connmgr_state state;

        pthread_t          acceptor;
} connmgr;

static int get_id_by_name(const char * name)
{
        enum ae_id i;

        for (i = 0; i < AEID_MAX; ++i)
                if (strcmp(name, connmgr.aes[i].info.ae_name) == 0)
                        return i;

        return -1;
}

static int add_ae_conn(enum ae_id         id,
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

        pthread_mutex_lock(&connmgr.aes[id].lock);

        list_add(&el->next, &connmgr.aes[id].pending);
        pthread_cond_signal(&connmgr.aes[id].cond);

        pthread_mutex_unlock(&connmgr.aes[id].lock);

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

                id = get_id_by_name(rcv_info.ae_name);
                if (id < 0) {
                        log_dbg("Connection request for unknown AE %s.",
                                rcv_info.ae_name);
                        cacep_snd(fd, &fail_info);
                        flow_dealloc(fd);
                        continue;
                }

                assert(id < AEID_MAX);

                if (cacep_snd(fd, &connmgr.aes[id].info)) {
                        log_dbg("Failed to respond to request.");
                        flow_dealloc(fd);
                        continue;
                }

                if (add_ae_conn(id, fd, qs, &rcv_info)) {
                        log_dbg("Failed to add new connection.");
                        flow_dealloc(fd);
                        continue;
                }
        }

        return (void *) 0;
}

int connmgr_init(void)
{
        connmgr.state = CONNMGR_INIT;

        return 0;
}

void connmgr_fini(void)
{
        int i;

        if (connmgr.state == CONNMGR_RUNNING)
                pthread_join(connmgr.acceptor, NULL);

        for (i = 0; i < AEID_MAX; ++i)
                connmgr_ae_fini(i);
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

int connmgr_ae_init(enum ae_id               id,
                    const struct conn_info * info,
                    struct nbs *             nbs)
{
        struct ae * ae;

        assert(id >= 0 && id < AEID_MAX);

        ae = connmgr.aes + id;

        if (pthread_mutex_init(&ae->lock, NULL)) {
                return -1;
        }

        if (pthread_cond_init(&ae->cond, NULL)) {
                pthread_mutex_destroy(&ae->lock);
                return -1;
        }

        list_head_init(&ae->conns);
        list_head_init(&ae->pending);

        memcpy(&connmgr.aes[id].info, info, sizeof(connmgr.aes[id].info));

        connmgr.aes[id].nbs = nbs;

        return 0;
}

void connmgr_ae_fini(enum ae_id id)
{
        struct list_head * p;
        struct list_head * h;
        struct ae *        ae;

        assert(id >= 0 && id < AEID_MAX);

        if (strlen(connmgr.aes[id].info.ae_name) == 0)
                return;

        ae = connmgr.aes + id;

        pthread_mutex_lock(&ae->lock);

        list_for_each_safe(p, h, &ae->conns) {
                struct conn_el * e = list_entry(p, struct conn_el, next);
                list_del(&e->next);
                free(e);
        }

        list_for_each_safe(p, h, &ae->pending) {
                struct conn_el * e = list_entry(p, struct conn_el, next);
                list_del(&e->next);
                free(e);
        }

        pthread_mutex_unlock(&ae->lock);

        pthread_cond_destroy(&ae->cond);
        pthread_mutex_destroy(&ae->lock);

        memset(&connmgr.aes[id].info, 0, sizeof(connmgr.aes[id].info));

        connmgr.aes[id].nbs = NULL;
}

int connmgr_ipcp_connect(const char * dst,
                         const char * component)
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

        /* FIXME: get the correct qos for the component. */
        if (connmgr_alloc(id, dst, NULL, &ce->conn)) {
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

        pthread_mutex_lock(&connmgr.aes[id].lock);

        list_add(&ce->next, &connmgr.aes[id].conns);

        pthread_mutex_unlock(&connmgr.aes[id].lock);

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

        pthread_mutex_lock(&connmgr.aes[id].lock);

        list_for_each_safe(p,h, &connmgr.aes[id].conns) {
                struct conn_el * el = list_entry(p, struct conn_el, next);
                if (strcmp(el->conn.flow_info.dst, dst) == 0) {
                        int ret;
                        pthread_mutex_unlock(&connmgr.aes[id].lock);
                        list_del(&el->next);
                        ret = connmgr_dealloc(id, &el->conn);
                        free(el);
                        return ret;
                }
        }

        pthread_mutex_unlock(&connmgr.aes[id].lock);

        return 0;
}

int connmgr_alloc(enum ae_id    id,
                  const char *  dst,
                  qosspec_t *   qs,
                  struct conn * conn)
{
        assert(id >= 0 && id < AEID_MAX);
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
                connmgr.aes[id].info.protocol, conn->flow_info.fd);

        if (cacep_snd(conn->flow_info.fd, &connmgr.aes[id].info)) {
                log_dbg("Failed to create application connection.");
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (cacep_rcv(conn->flow_info.fd, &conn->conn_info)) {
                log_dbg("Failed to connect to application.");
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (strcmp(connmgr.aes[id].info.protocol, conn->conn_info.protocol)) {
                log_dbg("Unknown protocol (requested %s, got %s).",
                        connmgr.aes[id].info.protocol,
                        conn->conn_info.protocol);
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (connmgr.aes[id].info.pref_version != conn->conn_info.pref_version) {
                log_dbg("Unknown protocol version.");
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (connmgr.aes[id].info.pref_syntax != conn->conn_info.pref_syntax) {
                log_dbg("Unknown protocol syntax.");
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (connmgr.aes[id].nbs != NULL)
                nbs_add(connmgr.aes[id].nbs, *conn);

        return 0;
}

int connmgr_dealloc(enum ae_id    id,
                    struct conn * conn)
{
        if (connmgr.aes[id].nbs != NULL)
                nbs_del(connmgr.aes[id].nbs, conn->flow_info.fd);

        return flow_dealloc(conn->flow_info.fd);
}


int connmgr_wait(enum ae_id    id,
                 struct conn * conn)
{
        struct conn_el * el;
        struct ae *      ae;

        assert(id >= 0 && id < AEID_MAX);
        assert(conn);

        ae = connmgr.aes + id;

        pthread_mutex_lock(&ae->lock);

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) &ae->lock);

        while (list_is_empty(&ae->pending))
                pthread_cond_wait(&ae->cond, &ae->lock);

        pthread_cleanup_pop(false);

        el = list_first_entry((&ae->pending), struct conn_el, next);
        if (el == NULL) {
                pthread_mutex_unlock(&ae->lock);
                return -1;
        }

        *conn = el->conn;

        list_del(&el->next);
        free(el);

        pthread_mutex_unlock(&ae->lock);

        return 0;
}
