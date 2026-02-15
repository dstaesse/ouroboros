/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Link state routing policy
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
#define _POSIX_C_SOURCE 200112L
#endif

#include "config.h"

#define OUROBOROS_PREFIX "link-state-routing"

#include <ouroboros/endian.h>
#include <ouroboros/dev.h>
#include <ouroboros/errno.h>
#include <ouroboros/fccntl.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/list.h>
#include <ouroboros/logs.h>
#include <ouroboros/notifier.h>
#include <ouroboros/pthread.h>
#include <ouroboros/rib.h>
#include <ouroboros/utils.h>

#include "addr-auth.h"
#include "common/comp.h"
#include "common/connmgr.h"
#include "graph.h"
#include "ipcp.h"
#include "link-state.h"
#include "pff.h"

#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>

#define LS_ENTRY_SIZE  104
#define Lspb           "lspb"

#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#endif

#define LINK_FMT ADDR_FMT32 "--" ADDR_FMT32
#define LINK_VAL(src, dst) ADDR_VAL32(&src), ADDR_VAL32(&dst)

#define LSU_FMT "LSU ["ADDR_FMT32 " -- " ADDR_FMT32 " seq: %09" PRIu64 "]"
#define LSU_VAL(src, dst, seqno) ADDR_VAL32(&src), ADDR_VAL32(&dst), seqno

struct lsa {
        uint64_t d_addr;
        uint64_t s_addr;
        uint64_t seqno;
} __attribute__((packed));

struct routing_i {
        struct list_head next;

        struct pff *     pff;
        pthread_t        calculator;

        bool             modified;
        pthread_mutex_t  lock;
};

/* TODO: link weight support. */
struct adjacency {
        struct list_head next;

        uint64_t         dst;
        uint64_t         src;

        uint64_t         seqno;

        time_t           stamp;
};

enum nb_type {
        NB_DT = 0,
        NB_MGMT
};

struct nb {
        struct list_head next;

        uint64_t         addr;
        int              fd;
        enum nb_type     type;
};

struct {
        uint64_t          addr;

        enum routing_algo routing_algo;

        struct ls_config  conf;

        fset_t *          mgmt_set;

        struct graph * graph;

        struct {
                struct llist     nbs;
                struct llist     db;
                pthread_rwlock_t lock;
        };

        struct {
                struct list_head list;
                pthread_mutex_t  mtx;
        } instances;

        pthread_t         lsupdate;
        pthread_t         lsreader;
        pthread_t         listener;
} ls;

struct routing_ops link_state_ops = {
        .init              = (int (*)(void *, enum pol_pff *)) link_state_init,
        .fini              = link_state_fini,
        .start             = link_state_start,
        .stop              = link_state_stop,
        .routing_i_create  = link_state_routing_i_create,
        .routing_i_destroy = link_state_routing_i_destroy
};

static int str_adj(struct adjacency * adj,
                   char *             buf,
                   size_t             len)
{
        char        tmstr[RIB_TM_STRLEN];
        char        srcbuf[64];
        char        dstbuf[64];
        char        seqnobuf[64];
        struct tm * tm;

        assert(adj);

        if (len < LS_ENTRY_SIZE)
                return -1;

        tm = gmtime(&adj->stamp);
        strftime(tmstr, sizeof(tmstr), RIB_TM_FORMAT, tm);

        sprintf(srcbuf, ADDR_FMT32, ADDR_VAL32(&adj->src));
        sprintf(dstbuf, ADDR_FMT32, ADDR_VAL32(&adj->dst));
        sprintf(seqnobuf, "%" PRIu64, adj->seqno);

        sprintf(buf, "src: %20s\ndst: %20s\nseqno: %18s\n"
                "upd: %s\n",
                srcbuf, dstbuf, seqnobuf, tmstr);

        return LS_ENTRY_SIZE;
}

static struct adjacency * get_adj(const char * path)
{
        struct list_head * p;
        char               entry[RIB_PATH_LEN + 1];

        assert(path);

        llist_for_each(p, &ls.db) {
                struct adjacency * a = list_entry(p, struct adjacency, next);
                sprintf(entry, LINK_FMT, LINK_VAL(a->src, a->dst));
                if (strcmp(entry, path) == 0)
                        return a;
        }

        return NULL;
}

static int lspb_rib_getattr(const char *      path,
                            struct rib_attr * attr)
{
        struct adjacency * adj;
        struct timespec    now;
        char *             entry;

        assert(path);
        assert(attr);

        entry = strstr(path, RIB_SEPARATOR) + 1;
        assert(entry);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_rwlock_rdlock(&ls.lock);

        adj = get_adj(entry);
        if (adj != NULL) {
                attr->mtime = adj->stamp;
                attr->size  = LS_ENTRY_SIZE;
        } else {
                attr->mtime = now.tv_sec;
                attr->size  = 0;
        }

        pthread_rwlock_unlock(&ls.lock);

        return 0;
}

static int lspb_rib_read(const char * path,
                         char *       buf,
                         size_t       len)
{
        struct adjacency * a;
        char *             entry;
        int                size;

        assert(path);

        entry = strstr(path, RIB_SEPARATOR) + 1;
        assert(entry);

        pthread_rwlock_rdlock(&ls.lock);

        if (llist_is_empty(&ls.db) && llist_is_empty(&ls.nbs))
                goto fail;

        a = get_adj(entry);
        if (a == NULL)
                goto fail;

        size = str_adj(a, buf, len);
        if (size < 0)
                goto fail;

        pthread_rwlock_unlock(&ls.lock);
        return size;

 fail:
        pthread_rwlock_unlock(&ls.lock);
        return -1;
}

static int lspb_rib_readdir(char *** buf)
{
        struct list_head * p;
        char               entry[RIB_PATH_LEN + 1];
        ssize_t            idx = 0;

        assert(buf != NULL);

        pthread_rwlock_rdlock(&ls.lock);

        if (llist_is_empty(&ls.db) && llist_is_empty(&ls.nbs)) {
                *buf = NULL;
                goto no_entries;
        }


        *buf = malloc(sizeof(**buf) * (ls.db.len + ls.nbs.len));
        if (*buf == NULL)
                goto fail_entries;

        llist_for_each(p, &ls.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                char * str = (nb->type == NB_DT ? ".dt " : ".mgmt ");
                sprintf(entry, "%s" ADDR_FMT32 , str, ADDR_VAL32(&nb->addr));
                (*buf)[idx] = malloc(strlen(entry) + 1);
                if ((*buf)[idx] == NULL)
                        goto fail_entry;

                strcpy((*buf)[idx++], entry);
        }

        llist_for_each(p, &ls.db) {
                struct adjacency * a = list_entry(p, struct adjacency, next);
                sprintf(entry,  LINK_FMT, LINK_VAL(a->src, a->dst));
                (*buf)[idx] = malloc(strlen(entry) + 1);
                if ((*buf)[idx] == NULL)
                        goto fail_entry;

                strcpy((*buf)[idx++], entry);
        }
 no_entries:
        pthread_rwlock_unlock(&ls.lock);

        return idx;

 fail_entry:
        while (idx-- > 0)
                free((*buf)[idx]);
        free(*buf);
 fail_entries:
        pthread_rwlock_unlock(&ls.lock);
        return -ENOMEM;
}

static struct rib_ops r_ops = {
        .read    = lspb_rib_read,
        .readdir = lspb_rib_readdir,
        .getattr = lspb_rib_getattr
};

static int lspb_add_nb(uint64_t     addr,
                       int          fd,
                       enum nb_type type)
{
        struct list_head * p;
        struct nb *        nb;

        pthread_rwlock_wrlock(&ls.lock);

        llist_for_each(p, &ls.nbs) {
                struct nb * el = list_entry(p, struct nb, next);
                if (addr > el->addr)
                        break;
                if (el->addr != addr || el->type != type)
                        continue;

                log_dbg("Already know %s neighbor " ADDR_FMT32 ".",
                        type == NB_DT ? "dt" : "mgmt", ADDR_VAL32(&addr));
                if (el->fd != fd) {
                        log_warn("Existing neighbor assigned new fd.");
                        el->fd = fd;
                }
                pthread_rwlock_unlock(&ls.lock);
                return -EPERM;
        }

        nb = malloc(sizeof(*nb));
        if (nb == NULL) {
                pthread_rwlock_unlock(&ls.lock);
                return -ENOMEM;
        }

        nb->addr  = addr;
        nb->fd    = fd;
        nb->type  = type;

        llist_add_tail_at(&nb->next, p, &ls.nbs);

        log_dbg("Type %s neighbor " ADDR_FMT32 " added.",
                nb->type == NB_DT ? "dt" : "mgmt", ADDR_VAL32(&addr));

        pthread_rwlock_unlock(&ls.lock);

        return 0;
}

static int lspb_del_nb(uint64_t addr,
                       int      fd)
{
        struct list_head * p;
        struct list_head * h;

        pthread_rwlock_wrlock(&ls.lock);

        llist_for_each_safe(p, h, &ls.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                if (nb->addr != addr || nb->fd != fd)
                        continue;

                llist_del(&nb->next, &ls.nbs);
                pthread_rwlock_unlock(&ls.lock);
                log_dbg("Type %s neighbor " ADDR_FMT32 " deleted.",
                        nb->type == NB_DT ? "dt" : "mgmt", ADDR_VAL32(&addr));
                free(nb);
                return 0;
        }

        pthread_rwlock_unlock(&ls.lock);

        return -EPERM;
}

static int nbr_to_fd(uint64_t addr)
{
        struct list_head * p;
        int                fd;

        pthread_rwlock_rdlock(&ls.lock);

        llist_for_each(p, &ls.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                if (nb->addr == addr && nb->type == NB_DT) {
                        fd = nb->fd;
                        pthread_rwlock_unlock(&ls.lock);
                        return fd;
                }
        }

        pthread_rwlock_unlock(&ls.lock);

        return -1;
}

static void calculate_pff(struct routing_i * instance)
{
        int                fd;
        struct list_head   table;
        struct list_head * p;
        struct list_head * q;
        int                fds[PROG_MAX_FLOWS];

        assert(instance);

        if (graph_routing_table(ls.graph, ls.routing_algo, ls.addr, &table))
                return;

        pff_lock(instance->pff);

        pff_flush(instance->pff);

        /* Calculate forwarding table from routing table. */
        list_for_each(p, &table) {
                int                    i = 0;
                struct routing_table * t =
                        list_entry(p, struct routing_table, next);

                list_for_each(q, &t->nhops) {
                        struct nhop * n = list_entry(q, struct nhop, next);

                        fd = nbr_to_fd(n->nhop);
                        if (fd == -1)
                                continue;

                        fds[i++] = fd;
                }
                if (i > 0)
                        pff_add(instance->pff, t->dst, fds, i);
        }

        pff_unlock(instance->pff);

        graph_free_routing_table(ls.graph, &table);
}

static void set_pff_modified(bool calc)
{
        struct list_head * p;

        pthread_mutex_lock(&ls.instances.mtx);
        list_for_each(p, &ls.instances.list) {
                struct routing_i * inst =
                        list_entry(p, struct routing_i, next);
                pthread_mutex_lock(&inst->lock);
                inst->modified = true;
                pthread_mutex_unlock(&inst->lock);
                if (calc)
                        calculate_pff(inst);
        }
        pthread_mutex_unlock(&ls.instances.mtx);
}

static int lspb_add_link(uint64_t    src,
                         uint64_t    dst,
                         uint64_t    seqno,
                         qosspec_t * qs)
{
        struct list_head * p;
        struct adjacency * adj;
        struct timespec    now;
        int                ret = -1;

        assert(qs);

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_rwlock_wrlock(&ls.lock);

        llist_for_each(p, &ls.db) {
                struct adjacency * a = list_entry(p, struct adjacency, next);
                if (a->dst == dst && a->src == src) {
                        if (a->seqno < seqno) {
                                a->stamp = now.tv_sec;
                                a->seqno = seqno;
                                ret = 0;
                        }
                        pthread_rwlock_unlock(&ls.lock);
                        return ret;
                }

                if (a->dst > dst || (a->dst == dst && a->src > src))
                        break;
        }

        adj = malloc(sizeof(*adj));
        if (adj == NULL) {
                pthread_rwlock_unlock(&ls.lock);
                return -ENOMEM;
        }

        adj->dst   = dst;
        adj->src   = src;
        adj->seqno = seqno;
        adj->stamp = now.tv_sec;

        llist_add_tail_at(&adj->next, p, &ls.db);

        if (graph_update_edge(ls.graph, src, dst, *qs))
                log_warn("Failed to add edge to graph.");

        pthread_rwlock_unlock(&ls.lock);

        set_pff_modified(true);

        return 0;
}

static int lspb_del_link(uint64_t src,
                         uint64_t dst)
{
        struct list_head * p;
        struct list_head * h;

        pthread_rwlock_wrlock(&ls.lock);

        llist_for_each_safe(p, h, &ls.db) {
                struct adjacency * a = list_entry(p, struct adjacency, next);
                if (a->dst == dst && a->src == src) {
                        llist_del(&a->next, &ls.db);
                        if (graph_del_edge(ls.graph, src, dst))
                                log_warn("Failed to delete edge from graph.");

                        pthread_rwlock_unlock(&ls.lock);
                        set_pff_modified(false);
                        free(a);
                        return 0;
                }
        }

        pthread_rwlock_unlock(&ls.lock);

        return -EPERM;
}

static void * periodic_recalc_pff(void * o)
{
        bool               modified;
        struct routing_i * inst;

        assert(o);

        inst = (struct routing_i *) o;

        while (true) {
                pthread_mutex_lock(&inst->lock);
                modified = inst->modified;
                inst->modified = false;
                pthread_mutex_unlock(&inst->lock);

                if (modified)
                        calculate_pff(inst);

                sleep(ls.conf.t_recalc);
        }

        return (void *) 0;
}

static void send_lsm(uint64_t src,
                     uint64_t dst,
                     uint64_t seqno)
{
        struct lsa         lsm;
        struct list_head * p;

        lsm.d_addr = hton64(dst);
        lsm.s_addr = hton64(src);
        lsm.seqno  = hton64(seqno);

        llist_for_each(p, &ls.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                if (nb->type != NB_MGMT)
                        continue;

                if (flow_write(nb->fd, &lsm, sizeof(lsm)) < 0)
                        log_err("Failed to send LSM to " ADDR_FMT32,
                                ADDR_VAL32(&nb->addr));
#ifdef DEBUG_PROTO_LS
                else
                        log_proto(LSU_FMT " --> " ADDR_FMT32,
                                LSU_VAL(src, dst, seqno),
                                ADDR_VAL32(&nb->addr));
#endif
        }
}

/* replicate the lspb to a mgmt neighbor */
static void lspb_replicate(int fd)
{
        struct list_head * p;
        struct list_head * h;
        struct list_head   copy;

        list_head_init(&copy);

        /* Lock the lspb, copy the lsms and send outside of lock. */
        pthread_rwlock_rdlock(&ls.lock);

        llist_for_each(p, &ls.db) {
                struct adjacency * adj;
                struct adjacency * cpy;
                adj = list_entry(p, struct adjacency, next);
                cpy = malloc(sizeof(*cpy));
                if (cpy == NULL) {
                        log_warn("Failed to replicate full lspb.");
                        break;
                }

                cpy->dst   = adj->dst;
                cpy->src   = adj->src;
                cpy->seqno = adj->seqno;

                list_add_tail(&cpy->next, &copy);
        }

        pthread_rwlock_unlock(&ls.lock);

        list_for_each_safe(p, h, &copy) {
                struct lsa         lsm;
                struct adjacency * adj;
                adj = list_entry(p, struct adjacency, next);
                lsm.d_addr = hton64(adj->dst);
                lsm.s_addr = hton64(adj->src);
                lsm.seqno  = hton64(adj->seqno);
                list_del(&adj->next);
                free(adj);
                flow_write(fd, &lsm, sizeof(lsm));
        }
}

static void * lsupdate(void * o)
{
        struct list_head * p;
        struct list_head * h;
        struct timespec    now;

        (void) o;

        while (true) {
                clock_gettime(CLOCK_REALTIME_COARSE, &now);

                pthread_rwlock_wrlock(&ls.lock);

                pthread_cleanup_push(__cleanup_rwlock_unlock, &ls.lock);

                llist_for_each_safe(p, h, &ls.db) {
                        struct adjacency * adj;
                        adj = list_entry(p, struct adjacency, next);
                        if (now.tv_sec > adj->stamp + ls.conf.t_timeo) {
                                llist_del(&adj->next, &ls.db);
                                log_dbg(LINK_FMT " timed out.",
                                        LINK_VAL(adj->src, adj->dst));
                                if (graph_del_edge(ls.graph, adj->src,
                                                   adj->dst))
                                        log_err("Failed to del edge.");
                                free(adj);
                                continue;
                        }

                        if (adj->src == ls.addr) {
                                adj->seqno++;
                                send_lsm(adj->src, adj->dst, adj->seqno);
                                adj->stamp = now.tv_sec;
                        }
                }

                pthread_cleanup_pop(true);

                sleep(ls.conf.t_update);
        }

        return (void *) 0;
}

static void * ls_conn_handle(void * o)
{
        struct conn conn;

        (void) o;

        while (true) {
                if (connmgr_wait(COMPID_MGMT, &conn)) {
                        log_err("Failed to get next MGMT connection.");
                        continue;
                }

                /* NOTE: connection acceptance policy could be here. */

                notifier_event(NOTIFY_MGMT_CONN_ADD, &conn);
        }

        return 0;
}


static void forward_lsm(uint8_t * buf,
                        size_t    len,
                        int       in_fd)
{
        struct list_head * p;
#ifdef DEBUG_PROTO_LS
        struct lsa lsm;

        assert(buf);
        assert(len >= sizeof(struct lsa));

        memcpy(&lsm, buf, sizeof(lsm));

        lsm.s_addr = ntoh64(lsm.s_addr);
        lsm.d_addr = ntoh64(lsm.d_addr);
        lsm.seqno  = ntoh64(lsm.seqno);
#endif
        pthread_rwlock_rdlock(&ls.lock);

        pthread_cleanup_push(__cleanup_rwlock_unlock, &ls.lock);

        llist_for_each(p, &ls.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                if (nb->type != NB_MGMT || nb->fd == in_fd)
                        continue;

                if (flow_write(nb->fd, buf, len) < 0)
                        log_err("Failed to forward LSM to " ADDR_FMT32,
                                ADDR_VAL32(&nb->addr));
#ifdef DEBUG_PROTO_LS
                else
                        log_proto(LSU_FMT " --> " ADDR_FMT32 " [forwarded]",
                                LSU_VAL(lsm.s_addr, lsm.d_addr, lsm.seqno),
                                ADDR_VAL32(&nb->addr));
#endif
        }

        pthread_cleanup_pop(true);
}

static void cleanup_fqueue(void * fq)
{
        fqueue_destroy((fqueue_t *) fq);
}

static void * lsreader(void * o)
{
        fqueue_t * fq;
        int        ret;
        uint8_t    buf[sizeof(struct lsa)];
        int        fd;
        qosspec_t  qs;
        struct lsa msg;
        size_t     len;

        (void) o;

        memset(&qs, 0, sizeof(qs));

        fq = fqueue_create();
        if (fq == NULL)
                return (void *) -1;

        pthread_cleanup_push(cleanup_fqueue, fq);

        while (true) {
                ret = fevent(ls.mgmt_set, fq, NULL);
                if (ret < 0) {
                        log_warn("Event error: %d.", ret);
                        continue;
                }

                while ((fd = fqueue_next(fq)) >= 0) {
                        if (fqueue_type(fq) != FLOW_PKT)
                                continue;

                        len = flow_read(fd, buf, sizeof(msg));
                        if (len <= 0 || len != sizeof(msg))
                                continue;

                        memcpy(&msg, buf, sizeof(msg));
                        msg.s_addr = ntoh64(msg.s_addr);
                        msg.d_addr = ntoh64(msg.d_addr);
                        msg.seqno  = ntoh64(msg.seqno);
#ifdef DEBUG_PROTO_LS
                        log_proto(LSU_FMT " <-- " ADDR_FMT32,
                                  LSU_VAL(msg.s_addr, msg.d_addr, msg.seqno),
                                  ADDR_VAL32(&ls.addr));
#endif
                        if (lspb_add_link(msg.s_addr,
                                          msg.d_addr,
                                          msg.seqno,
                                          &qs))
                                continue;

                        forward_lsm(buf, len, fd);
                }
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

static void flow_event(int  fd,
                       bool up)
{

        struct list_head * p;

        log_dbg("Notifying routing instances of flow event.");

        pthread_mutex_lock(&ls.instances.mtx);

        list_for_each(p, &ls.instances.list) {
                struct routing_i * ri = list_entry(p, struct routing_i, next);
                pff_flow_state_change(ri->pff, fd, up);
        }

        pthread_mutex_unlock(&ls.instances.mtx);
}

static void handle_event(void *       self,
                         int          event,
                         const void * o)
{
        /* FIXME: Apply correct QoS on graph */
        struct conn *      c;
        qosspec_t          qs;
        int                flags;

        (void) self;

        assert(o);

        c = (struct conn *) o;

        memset(&qs, 0, sizeof(qs));

        switch (event) {
        case NOTIFY_DT_CONN_ADD:
                pthread_rwlock_rdlock(&ls.lock);

                pthread_cleanup_push(__cleanup_rwlock_unlock, &ls.lock);

                send_lsm(ls.addr, c->conn_info.addr, 0);
                pthread_cleanup_pop(true);

                if (lspb_add_nb(c->conn_info.addr, c->flow_info.fd, NB_DT))
                        log_dbg("Failed to add neighbor to Lspb.");

                if (lspb_add_link(ls.addr, c->conn_info.addr, 0, &qs))
                        log_dbg("Failed to add new adjacency to Lspb.");
                break;
        case NOTIFY_DT_CONN_DEL:
                flow_event(c->flow_info.fd, false);

                if (lspb_del_nb(c->conn_info.addr, c->flow_info.fd))
                        log_dbg("Failed to delete neighbor from Lspb.");

                if (lspb_del_link(ls.addr, c->conn_info.addr))
                        log_dbg("Local link was not in Lspb.");
                break;
        case NOTIFY_DT_CONN_QOS:
                log_dbg("QoS changes currently unsupported.");
                break;
        case NOTIFY_DT_CONN_UP:
                flow_event(c->flow_info.fd, true);
                break;
        case NOTIFY_DT_CONN_DOWN:
                flow_event(c->flow_info.fd, false);
                break;
        case NOTIFY_MGMT_CONN_ADD:
                fccntl(c->flow_info.fd, FLOWGFLAGS, &flags);
                fccntl(c->flow_info.fd, FLOWSFLAGS, flags | FLOWFRNOPART);
                fset_add(ls.mgmt_set, c->flow_info.fd);
                if (lspb_add_nb(c->conn_info.addr, c->flow_info.fd, NB_MGMT))
                        log_warn("Failed to add mgmt neighbor to Lspb.");
                /* replicate the entire lspb */
                lspb_replicate(c->flow_info.fd);
                break;
        case NOTIFY_MGMT_CONN_DEL:
                fset_del(ls.mgmt_set, c->flow_info.fd);
                if (lspb_del_nb(c->conn_info.addr, c->flow_info.fd))
                        log_warn("Failed to delete mgmt neighbor from Lspb.");
                break;
        default:
                break;
        }
}

struct routing_i * link_state_routing_i_create(struct pff * pff)
{
        struct routing_i * tmp;

        assert(pff);

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                goto fail_tmp;

        tmp->pff      = pff;
        tmp->modified = false;

        if (pthread_mutex_init(&tmp->lock, NULL))
                goto fail_instance_lock_init;

        if (pthread_create(&tmp->calculator, NULL,
                           periodic_recalc_pff, tmp))
                goto fail_pthread_create_lsupdate;

        pthread_mutex_lock(&ls.instances.mtx);

        list_add(&tmp->next, &ls.instances.list);

        pthread_mutex_unlock(&ls.instances.mtx);

        return tmp;

 fail_pthread_create_lsupdate:
        pthread_mutex_destroy(&tmp->lock);
 fail_instance_lock_init:
        free(tmp);
 fail_tmp:
        return NULL;
}

void link_state_routing_i_destroy(struct routing_i * instance)
{
        assert(instance);

        pthread_mutex_lock(&ls.instances.mtx);

        list_del(&instance->next);

        pthread_mutex_unlock(&ls.instances.mtx);

        pthread_cancel(instance->calculator);

        pthread_join(instance->calculator, NULL);

        pthread_mutex_destroy(&instance->lock);

        free(instance);
}

int link_state_start(void)
{
        if (notifier_reg(handle_event, NULL)) {
                log_err("Failed to register link-state with notifier.");
                goto fail_notifier_reg;
        }

        if (pthread_create(&ls.lsupdate, NULL, lsupdate, NULL)) {
                log_err("Failed to create lsupdate thread.");
                goto fail_pthread_create_lsupdate;
        }

        if (pthread_create(&ls.lsreader, NULL, lsreader, NULL)) {
                log_err("Failed to create lsreader thread.");
                goto fail_pthread_create_lsreader;
        }

        if (pthread_create(&ls.listener, NULL, ls_conn_handle, NULL)) {
                log_err("Failed to create listener thread.");
                goto fail_pthread_create_listener;
        }

        return 0;

 fail_pthread_create_listener:
        pthread_cancel(ls.lsreader);
        pthread_join(ls.lsreader, NULL);
 fail_pthread_create_lsreader:
        pthread_cancel(ls.lsupdate);
        pthread_join(ls.lsupdate, NULL);
 fail_pthread_create_lsupdate:
        notifier_unreg(handle_event);
 fail_notifier_reg:
        return -1;
}

void link_state_stop(void)
{
        pthread_cancel(ls.listener);
        pthread_cancel(ls.lsreader);
        pthread_cancel(ls.lsupdate);

        pthread_join(ls.listener, NULL);
        pthread_join(ls.lsreader, NULL);
        pthread_join(ls.lsupdate, NULL);

        notifier_unreg(handle_event);
}


int link_state_init(struct ls_config * conf,
                    enum pol_pff *     pff_type)
{
        struct conn_info info;

        assert(conf != NULL);
        assert(pff_type != NULL);

        memset(&info, 0, sizeof(info));

        ls.addr = addr_auth_address();

        strcpy(info.comp_name, LS_COMP);
        strcpy(info.protocol, LS_PROTO);
        info.pref_version = 1;
        info.pref_syntax  = PROTO_GPB;
        info.addr         = ls.addr;

        ls.conf = *conf;

        switch (conf->pol) {
        case LS_SIMPLE:
                *pff_type = PFF_SIMPLE;
                ls.routing_algo = ROUTING_SIMPLE;
                log_dbg("Using Link State Routing policy.");
                break;
        case LS_LFA:
                ls.routing_algo = ROUTING_LFA;
                *pff_type = PFF_ALTERNATE;
                log_dbg("Using Loop-Free Alternates policy.");
                break;
        case LS_ECMP:
                ls.routing_algo = ROUTING_ECMP;
                *pff_type = PFF_MULTIPATH;
                log_dbg("Using Equal-Cost Multipath policy.");
                break;
        default:
                goto fail_graph;
        }

        log_dbg("LS update interval: %ld seconds.", ls.conf.t_update);
        log_dbg("LS link timeout   : %ld seconds.", ls.conf.t_timeo);
        log_dbg("LS recalc interval: %ld seconds.", ls.conf.t_recalc);

        ls.graph = graph_create();
        if (ls.graph == NULL)
                goto fail_graph;

        if (pthread_rwlock_init(&ls.lock, NULL)) {
                log_err("Failed to init lock.");
                goto fail_lock_init;
        }

        if (pthread_mutex_init(&ls.instances.mtx, NULL)) {
                log_err("Failed to init instances mutex.");
                goto fail_routing_i_lock_init;
        }

        if (connmgr_comp_init(COMPID_MGMT, &info)) {
                log_err("Failed to init connmgr.");
                goto fail_connmgr_comp_init;
        }

        ls.mgmt_set = fset_create();
        if (ls.mgmt_set == NULL) {
                log_err("Failed to create fset.");
                goto fail_fset_create;
        }

        llist_init(&ls.db);
        llist_init(&ls.nbs);
        list_head_init(&ls.instances.list);

        if (rib_reg(Lspb, &r_ops))
                goto fail_rib_reg;

        return 0;

 fail_rib_reg:
        fset_destroy(ls.mgmt_set);
 fail_fset_create:
        connmgr_comp_fini(COMPID_MGMT);
 fail_connmgr_comp_init:
        pthread_mutex_destroy(&ls.instances.mtx);
 fail_routing_i_lock_init:
        pthread_rwlock_destroy(&ls.lock);
 fail_lock_init:
        graph_destroy(ls.graph);
 fail_graph:
        return -1;
}

void link_state_fini(void)
{
        struct list_head * p;
        struct list_head * h;

        rib_unreg(Lspb);

        fset_destroy(ls.mgmt_set);

        connmgr_comp_fini(COMPID_MGMT);

        graph_destroy(ls.graph);

        pthread_rwlock_wrlock(&ls.lock);

        llist_for_each_safe(p, h, &ls.db) {
                struct adjacency * a = list_entry(p, struct adjacency, next);
                llist_del(&a->next, &ls.db);
                free(a);
        }

        pthread_rwlock_unlock(&ls.lock);

        pthread_rwlock_destroy(&ls.lock);

        pthread_mutex_destroy(&ls.instances.mtx);
}
