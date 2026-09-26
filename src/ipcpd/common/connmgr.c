/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Handles connections between components
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

#define OUROBOROS_PREFIX "connection-manager"

#include <ouroboros/cep.h>
#include <ouroboros/dev.h>
#include <ouroboros/errno.h>
#include <ouroboros/fccntl.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/list.h>
#include <ouroboros/logs.h>
#include <ouroboros/notifier.h>
#include <ouroboros/pthread.h>
#include <ouroboros/qos.h>
#include <ouroboros/tpm.h>

#include "connmgr.h"
#include "ipcp.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#define CONNMGR_ETH_PROBE_TIMEO    20  /* ms, one query attempt   */
#define CONNMGR_ETH_RETRY_TIMEO  1500  /* ms, the remaining tries */
#define CONNMGR_DHT_TIMEO        1000  /* ms, bounded lower-layer */

struct conn_el {
        struct list_head next;
        struct conn      conn;
};

/* An accepted flow waiting for a handler to run OCEP on it. */
struct fd_el {
        struct list_head next;
        int              fd;
        qosspec_t        qs;
};

struct comp {
        struct conn_info info;

        struct list_head conns;
        struct list_head pending;

        pthread_cond_t   cond;
        pthread_mutex_t  mtx;
};

struct {
        struct comp      comps[COMPID_MAX];

        struct list_head inbox;
        pthread_cond_t   cond;
        pthread_mutex_t  mtx;
        struct tpm *     tpm;

        pthread_t        acceptor;
} connmgr;

static bool is_eth_query(const struct poa_addr * addr)
{
        static const uint8_t zero[POA_MAC_SIZE] = { 0 };

        if (addr->type != POA_ETH)
                return false;

        return memcmp(addr->eth.dst.mac, zero, POA_MAC_SIZE) == 0;
}

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

        pthread_mutex_lock(&connmgr.comps[id].mtx);

        list_for_each(p, &connmgr.comps[id].conns) {
                struct conn_el * c = list_entry(p, struct conn_el, next);

                if (c->conn.flow_info.fd == fd) {
                        *conn = c->conn;

                        pthread_mutex_unlock(&connmgr.comps[id].mtx);
                        return 0;
                }
        }

        pthread_mutex_unlock(&connmgr.comps[id].mtx);

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

        pthread_mutex_lock(&connmgr.comps[id].mtx);

        list_add(&el->next, &connmgr.comps[id].pending);
        pthread_cond_signal(&connmgr.comps[id].cond);

        pthread_mutex_unlock(&connmgr.comps[id].mtx);

        return 0;
}

/* qs is also an in-parameter, and flow_accept writes it back. */
static void handle_flow(int       fd,
                        qosspec_t qs)
{
        struct conn_info rcv_info;
        struct conn_info fail_info;
        struct timespec  timeo = TIMESPEC_INIT_MS(CONNMGR_RCV_TIMEOUT);
        int              id;
        int              err;

        memset(&fail_info, 0, sizeof(fail_info));

        log_info("Handling incoming flow %d.", fd);

        fccntl(fd, FLOWSRCVTIMEO, &timeo);

        err = cep_rcv(fd, &rcv_info);
        if (err < 0) {
                log_err("Error receiving OCEP info: %d.", err);
                flow_dealloc(fd);
                return;
        }

        log_info("Request to connect to %s.", rcv_info.comp_name);

        id = get_id_by_name(rcv_info.comp_name);
        if (id < 0) {
                log_err("Connection request for unknown component %s.",
                        rcv_info.comp_name);
                cep_snd(fd, &fail_info);
                flow_dealloc(fd);
                return;
        }

        err = cep_snd(fd, &connmgr.comps[id].info);
        if (err < 0) {
                log_err("Failed responding to OCEP request: %d.", err);
                flow_dealloc(fd);
                return;
        }

        fccntl(fd, FLOWSRCVTIMEO, NULL);

        err = add_comp_conn(id, fd, qs, &rcv_info);
        if (err < 0) {
                log_err("Failed to add new connection: %d.", err);
                flow_dealloc(fd);
                return;
        }

        log_info("Finished handling incoming flow %d for %s.",
                 fd, rcv_info.comp_name);
}

/* A handler is idle only while it waits on the inbox. */
static void * flow_handler(void * o)
{
        struct fd_el * el;

        (void) o;

        while (true) {
                pthread_mutex_lock(&connmgr.mtx);

                pthread_cleanup_push(__cleanup_mutex_unlock, &connmgr.mtx);

                while (list_is_empty(&connmgr.inbox))
                        pthread_cond_wait(&connmgr.cond, &connmgr.mtx);

                el = list_first_entry(&connmgr.inbox, struct fd_el, next);

                list_del(&el->next);

                tpm_begin_work(connmgr.tpm);

                pthread_cleanup_pop(true);

                handle_flow(el->fd, el->qs);

                free(el);

                tpm_end_work(connmgr.tpm);
        }

        return (void *) 0;
}

static int inbox_push(int       fd,
                      qosspec_t qs)
{
        struct fd_el * el;

        el = malloc(sizeof(*el));
        if (el == NULL)
                return -ENOMEM;

        el->fd = fd;
        el->qs = qs;

        list_head_init(&el->next);

        pthread_mutex_lock(&connmgr.mtx);

        list_add_tail(&el->next, &connmgr.inbox);
        pthread_cond_signal(&connmgr.cond);

        pthread_mutex_unlock(&connmgr.mtx);

        return 0;
}

static void inbox_flush(void)
{
        struct list_head * p;
        struct list_head * h;

        pthread_mutex_lock(&connmgr.mtx);

        list_for_each_safe(p, h, &connmgr.inbox) {
                struct fd_el * el = list_entry(p, struct fd_el, next);

                list_del(&el->next);
                flow_dealloc(el->fd);
                free(el);
        }

        pthread_mutex_unlock(&connmgr.mtx);
}

static void * flow_acceptor(void * o)
{
        int fd;

        (void) o;

        while (true) {
                qosspec_t qs = qos_raw;

                fd = flow_accept(&qs, NULL);
                if (fd < 0) {
                        if (fd != -EIRMD)
                                log_err("Flow accept failed: %d", fd);
                        continue;
                }

                if (inbox_push(fd, qs) < 0) {
                        log_err("Failed to queue incoming flow %d.", fd);
                        flow_dealloc(fd);
                }
        }

        return (void *) 0;
}

static bool is_dt_flow_event(int event)
{
        switch (event) {
        case NOTIFY_DT_FLOW_UP:
                /* FALLTHRU */
        case NOTIFY_DT_FLOW_DOWN:
                /* FALLTHRU */
        case NOTIFY_DT_FLOW_DEALLOC:
                return true;
        default:
                return false;
        }
}

static void handle_event(void *       self,
                         int          event,
                         const void * o)
{
        struct conn conn;

        (void) self;

        if (!is_dt_flow_event(event))
                return;

        if (get_conn_by_fd(*((int *) o), COMPID_DT, &conn) < 0)
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
        list_head_init(&connmgr.inbox);

        if (pthread_mutex_init(&connmgr.mtx, NULL) != 0) {
                log_err("Failed to initialize mutex: %s.", strerror(errno));
                goto fail_mtx;
        }

        if (pthread_cond_init(&connmgr.cond, NULL) != 0) {
                log_err("Failed to initialize condvar: %s.", strerror(errno));
                goto fail_cond;
        }

        connmgr.tpm = tpm_create(CONNMGR_MIN_THREADS, CONNMGR_ADD_THREADS,
                                 CONNMGR_MAX_THREADS, flow_handler, NULL);

        if (connmgr.tpm == NULL) {
                log_err("Failed to create thread pool.");
                goto fail_tpm;
        }

        if (notifier_reg(handle_event, NULL) < 0) {
                log_err("Failed to register notifier.");
                goto fail_notifier;
        }

        return 0;

 fail_notifier:
        tpm_destroy(connmgr.tpm);
 fail_tpm:
        pthread_cond_destroy(&connmgr.cond);
 fail_cond:
        pthread_mutex_destroy(&connmgr.mtx);
 fail_mtx:
        return -1;
}

void connmgr_fini(void)
{
        int i;

        for (i = 0; i < COMPID_MAX; ++i)
                connmgr_comp_fini(i);

        notifier_unreg(handle_event);

        tpm_destroy(connmgr.tpm);

        pthread_cond_destroy(&connmgr.cond);
        pthread_mutex_destroy(&connmgr.mtx);
}

int connmgr_start(void)
{
        if (tpm_start(connmgr.tpm) < 0) {
                log_err("Failed to start thread pool.");
                goto fail_tpm;
        }

        if (pthread_create(&connmgr.acceptor, NULL, flow_acceptor, NULL) != 0) {
                log_err("Failed to create pthread: %s.", strerror(errno));
                goto fail_acceptor;
        }

        return 0;

 fail_acceptor:
        tpm_stop(connmgr.tpm);
 fail_tpm:
        return -1;
}

void connmgr_stop(void)
{
        pthread_cancel(connmgr.acceptor);
        pthread_join(connmgr.acceptor, NULL);

        tpm_stop(connmgr.tpm);

        inbox_flush();
}

int connmgr_comp_init(enum comp_id             id,
                      const struct conn_info * info)
{
        struct comp * comp;

        assert(id >= 0 && id < COMPID_MAX);

        comp = connmgr.comps + id;
        if (pthread_mutex_init(&comp->mtx, NULL) != 0) {
                log_err("Failed to initialize mutex: %s.", strerror(errno));
                goto fail_mutex;
        }

        if (pthread_cond_init(&comp->cond, NULL) != 0) {
                log_err("Failed to initialize condvar: %s.", strerror(errno));
                goto fail_cond;
        }

        list_head_init(&comp->conns);
        list_head_init(&comp->pending);

        memcpy(&connmgr.comps[id].info, info, sizeof(connmgr.comps[id].info));

        return 0;

 fail_cond:
        pthread_mutex_destroy(&comp->mtx);
 fail_mutex:
        return -1;
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

        pthread_mutex_lock(&comp->mtx);

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

        pthread_mutex_unlock(&comp->mtx);

        pthread_cond_destroy(&comp->cond);
        pthread_mutex_destroy(&comp->mtx);

        memset(&connmgr.comps[id].info, 0, sizeof(connmgr.comps[id].info));
}

int connmgr_ipcp_connect(const char *            dst,
                         const char *            component,
                         qosspec_t               qs,
                         const struct poa_addr * addr)
{
        struct conn_el * ce;
        int              id;
        int              ret;

        assert(dst);
        assert(component);

        if (qs.service == SVC_STREAM) {
                log_err("No stream service on component flows.");
                return -ENOTSUP;
        }

        ce = malloc(sizeof(*ce));
        if (ce == NULL) {
                log_err("Out of memory.");
                goto fail_malloc;
        }

        id = get_id_by_name(component);
        if (id < 0) {
                log_err("No such component: %s", component);
                goto fail_id;
        }

        pthread_cleanup_push(free, ce);

        ret = connmgr_alloc(id, dst, &qs, addr, &ce->conn);

        pthread_cleanup_pop(false);

        if (ret < 0) {
                log_err("Failed to allocate flow.");
                goto fail_id;
        }

        if (strlen(dst) > DST_MAX_STRLEN) {
                log_warn("Truncating dst length for connection.");
                memcpy(ce->conn.flow_info.dst, dst, DST_MAX_STRLEN);

                ce->conn.flow_info.dst[DST_MAX_STRLEN] = '\0';
        } else {
                strcpy(ce->conn.flow_info.dst, dst);
        }

        pthread_mutex_lock(&connmgr.comps[id].mtx);

        list_add(&ce->next, &connmgr.comps[id].conns);

        pthread_mutex_unlock(&connmgr.comps[id].mtx);

        return 0;

 fail_id:
        free(ce);
 fail_malloc:
        return -1;
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
        if (id < 0) {
                log_err("No such component: %s.", component);
                return -1;
        }

        pthread_mutex_lock(&connmgr.comps[id].mtx);

        list_for_each_safe(p, h, &connmgr.comps[id].conns) {
                struct conn_el * el = list_entry(p, struct conn_el, next);

                if (strcmp(el->conn.flow_info.dst, dst) == 0) {
                        int ret;

                        list_del(&el->next);
                        pthread_mutex_unlock(&connmgr.comps[id].mtx);

                        ret = connmgr_dealloc(id, &el->conn);

                        free(el);

                        return ret;
                }
        }

        pthread_mutex_unlock(&connmgr.comps[id].mtx);

        return 0;
}

/*
 * Try a cheap PoA query first, then a bounded try over the layer
 * below, then the query again; the last try is unbounded.
 */
static int alloc_any(const char * dst,
                     qosspec_t *  qs)
{
        struct timespec probe = TIMESPEC_INIT_MS(CONNMGR_ETH_PROBE_TIMEO);
        struct timespec retry = TIMESPEC_INIT_MS(CONNMGR_ETH_RETRY_TIMEO);
        struct timespec below = TIMESPEC_INIT_MS(CONNMGR_DHT_TIMEO);
        struct poa_addr addr;
        int             fd;

        if (poa_query(dst, &probe, &addr) == 0) {
                fd = poa_flow_alloc(dst, &addr, qs, NULL);
                if (fd >= 0)
                        return fd;
        }

        fd = flow_alloc(dst, qs, &below);
        if (fd >= 0)
                return fd;

        if (poa_query(dst, &retry, &addr) == 0) {
                fd = poa_flow_alloc(dst, &addr, qs, NULL);
                if (fd >= 0)
                        return fd;
        }

        return flow_alloc(dst, qs, NULL);
}

/* A literal peer address bypasses the layer below. */
int connmgr_alloc(enum comp_id            id,
                  const char *            dst,
                  qosspec_t *             qs,
                  const struct poa_addr * addr,
                  struct conn *           conn)
{
        struct comp *   comp;
        int             fd;
        struct timespec timeo = TIMESPEC_INIT_MS(CONNMGR_RCV_TIMEOUT);

        assert(id >= 0 && id < COMPID_MAX);
        assert(dst);

        comp = connmgr.comps + id;

        if (addr != NULL)
                fd = poa_flow_alloc(dst, addr, qs, NULL);
        else
                fd = alloc_any(dst, qs);

        if (fd == -EPERM && addr != NULL) {
                log_err("No PoA attached to reach %s.", dst);
                goto fail_alloc;
        }

        if (fd == -EINVAL && addr != NULL) {
                log_err("More than one PoA could reach %s", dst);
                goto fail_alloc;
        }

        if (fd == -ETIMEDOUT && addr != NULL && is_eth_query(addr)) {
                log_err("No answer to name query for %s.", dst);
                goto fail_alloc;
        }

        if (fd < 0) {
                log_err("Failed to allocate flow to %s.", dst);
                goto fail_alloc;
        }

        conn->flow_info.fd = fd;

        if (qs != NULL)
                conn->flow_info.qs = *qs;
        else
                memset(&conn->flow_info.qs, 0, sizeof(conn->flow_info.qs));

        log_dbg("Sending OCEP info for protocol %s to fd %d.",
                comp->info.protocol, conn->flow_info.fd);

        fccntl(fd, FLOWSRCVTIMEO, &timeo);

        if (cep_snd(fd, &comp->info) < 0) {
                log_err("Failed to send OCEP info.");
                goto fail_cep;
        }

        if (cep_rcv(fd, &conn->conn_info) < 0) {
                log_err("Failed to receive OCEP info.");
                goto fail_cep;
        }

        if (strcmp(comp->info.protocol, conn->conn_info.protocol) != 0) {
                log_err("Unknown protocol (requested %s, got %s).",
                        comp->info.protocol, conn->conn_info.protocol);
                goto fail_cep;
        }

        if (comp->info.pref_version != conn->conn_info.pref_version) {
                log_err("Unknown protocol version %d.",
                        conn->conn_info.pref_version);
                goto fail_cep;
        }

        if (comp->info.pref_syntax != conn->conn_info.pref_syntax) {
                log_err("Unknown protocol syntax.");
                goto fail_cep;
        }

        switch (id) {
        case COMPID_DT:
                notifier_event(NOTIFY_DT_CONN_ADD, conn);
                break;
        case COMPID_MGMT:
                notifier_event(NOTIFY_MGMT_CONN_ADD, conn);
                break;
        default:
                break;
        }

        return 0;

 fail_cep:
        flow_dealloc(conn->flow_info.fd);
 fail_alloc:
        return -1;
}

int connmgr_dealloc(enum comp_id  id,
                    struct conn * conn)
{
        switch (id) {
        case COMPID_DT:
                notifier_event(NOTIFY_DT_CONN_DEL, conn);
                break;
#if defined(BUILD_IPCP_UNICAST)
        case COMPID_MGMT:
                notifier_event(NOTIFY_MGMT_CONN_DEL, conn);
                break;
#endif
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

        pthread_mutex_lock(&comp->mtx);

        pthread_cleanup_push(__cleanup_mutex_unlock, &comp->mtx);

        while (list_is_empty(&comp->pending))
                pthread_cond_wait(&comp->cond, &comp->mtx);

        pthread_cleanup_pop(false);

        el = list_first_entry((&comp->pending), struct conn_el, next);
        if (el == NULL) {
                pthread_mutex_unlock(&comp->mtx);
                log_err("Failed to get connection element.");
                return -1;
        }

        *conn = el->conn;

        list_del(&el->next);
        list_add(&el->next, &connmgr.comps[id].conns);

        pthread_mutex_unlock(&comp->mtx);

        return 0;
}
