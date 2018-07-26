/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * Link state routing policy
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
#include <ouroboros/rib.h>
#include <ouroboros/utils.h>

#include "comp.h"
#include "connmgr.h"
#include "graph.h"
#include "ipcp.h"
#include "link_state.h"
#include "pff.h"

#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>

#define RECALC_TIME    4
#define LS_UPDATE_TIME 15
#define LS_TIMEO       60
#define LS_ENTRY_SIZE  104
#define LSDB           "lsdb"

#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE CLOCK_REALTIME
#endif

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

typedef int (* rtable_fn_t)(struct graph *     graph,
                            uint64_t           s_addr,
                            struct list_head * table);

struct {
        struct list_head nbs;
        size_t           nbs_len;
        fset_t *         mgmt_set;

        struct list_head db;
        size_t           db_len;

        pthread_rwlock_t db_lock;

        struct graph *   graph;

        pthread_t        lsupdate;
        pthread_t        lsreader;
        pthread_t        listener;

        struct list_head routing_instances;
        pthread_mutex_t  routing_i_lock;

        rtable_fn_t      rtable;
} ls;

struct pol_routing_ops link_state_ops = {
        .init              = link_state_init,
        .fini              = link_state_fini,
        .routing_i_create  = link_state_routing_i_create,
        .routing_i_destroy = link_state_routing_i_destroy
};

static int str_adj(struct adjacency * adj,
                   char *             buf,
                   size_t             len)
{
        char        tmbuf[64];
        char        srcbuf[64];
        char        dstbuf[64];
        char        seqnobuf[64];
        struct tm * tm;

        if (len < LS_ENTRY_SIZE)
                return -1;

        tm = localtime(&adj->stamp);
        strftime(tmbuf, sizeof(tmbuf), "%F %T", tm); /* 19 chars */

        sprintf(srcbuf, "%" PRIu64, adj->src);
        sprintf(dstbuf, "%" PRIu64, adj->dst);
        sprintf(seqnobuf, "%" PRIu64, adj->seqno);

        sprintf(buf, "src: %20s\ndst: %20s\nseqno: %18s\nupd: %20s\n",
                srcbuf, dstbuf, seqnobuf, tmbuf);

        return LS_ENTRY_SIZE;
}

static struct adjacency * get_adj(const char * path)
{
        struct list_head * p;
        char               entry[RIB_PATH_LEN + 1];

        assert(path);

        list_for_each(p, &ls.db) {
                struct adjacency * a = list_entry(p, struct adjacency, next);
                sprintf(entry, "%" PRIu64 ".%" PRIu64, a->src, a->dst);
                if (strcmp(entry, path) == 0)
                        return a;
        }

        return NULL;
}

static int lsdb_getattr(const char *  path,
                        struct stat * st)
{
        struct adjacency * adj;
        struct timespec    now;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_rwlock_rdlock(&ls.db_lock);

        adj = get_adj(path);
        if (adj != NULL) {
                st->st_mtime = adj->stamp;
                st->st_size  = LS_ENTRY_SIZE;
        } else {
                st->st_mtime = now.tv_sec;
                st->st_size  = 0;
        }

        st->st_mode  = S_IFREG | 0755;
        st->st_nlink = 1;
        st->st_uid   = getuid();
        st->st_gid   = getgid();

        pthread_rwlock_unlock(&ls.db_lock);

        return 0;
}

static int lsdb_read(const char * path,
                     char *       buf,
                     size_t       len)
{
        struct adjacency * a;
        int                size;

        pthread_rwlock_rdlock(&ls.db_lock);

        if (ls.db_len + ls.nbs_len == 0)
                goto fail;

        a = get_adj(path);
        if (a == NULL)
                goto fail;

        size = str_adj(a, buf, len);
        if (size < 0)
                goto fail;

        pthread_rwlock_unlock(&ls.db_lock);
        return size;

 fail:
        pthread_rwlock_unlock(&ls.db_lock);
        return -1;
}

static int lsdb_readdir(char *** buf)
{
        struct list_head * p;
        char               entry[RIB_PATH_LEN + 1];
        ssize_t            idx = 0;

        pthread_rwlock_rdlock(&ls.db_lock);

        if (ls.db_len + ls.nbs_len == 0) {
                pthread_rwlock_unlock(&ls.db_lock);
                return 0;
        }

        *buf = malloc(sizeof(**buf) * (ls.db_len + ls.nbs_len));
        if (*buf == NULL) {
                pthread_rwlock_unlock(&ls.db_lock);
                return -ENOMEM;
        }

        list_for_each(p, &ls.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                char * str = (nb->type == NB_DT ? "dt." : "mgmt.");
                sprintf(entry, "%s%" PRIu64, str, nb->addr);
                (*buf)[idx] = malloc(strlen(entry) + 1);
                if ((*buf)[idx] == NULL) {
                        while (idx-- > 0)
                                free((*buf)[idx]);
                        free(buf);
                        pthread_rwlock_unlock(&ls.db_lock);
                        return -ENOMEM;
                }

                strcpy((*buf)[idx], entry);

                idx++;
        }

        list_for_each(p, &ls.db) {
                struct adjacency * a = list_entry(p, struct adjacency, next);
                sprintf(entry, "%" PRIu64 ".%" PRIu64, a->src, a->dst);
                (*buf)[idx] = malloc(strlen(entry) + 1);
                if ((*buf)[idx] == NULL) {
                        ssize_t j;
                        for (j = 0; j < idx; ++j)
                                free(*buf[j]);
                        free(buf);
                        pthread_rwlock_unlock(&ls.db_lock);
                        return -ENOMEM;
                }

                strcpy((*buf)[idx], entry);

                idx++;
        }

        pthread_rwlock_unlock(&ls.db_lock);

        return idx;
}

static struct rib_ops r_ops = {
        .read    = lsdb_read,
        .readdir = lsdb_readdir,
        .getattr = lsdb_getattr
};

static int lsdb_add_nb(uint64_t     addr,
                       int          fd,
                       enum nb_type type)
{
        struct list_head * p;
        struct nb *        nb;

        pthread_rwlock_wrlock(&ls.db_lock);

        list_for_each(p, &ls.nbs) {
                struct nb * el = list_entry(p, struct nb, next);
                if (el->addr == addr && el->type == type) {
                        log_dbg("Already know %s neighbor %" PRIu64 ".",
                                type == NB_DT ? "dt" : "mgmt", addr);
                        if (el->fd != fd) {
                                log_warn("Existing neighbor assigned new fd.");
                                el->fd = fd;
                        }
                        pthread_rwlock_unlock(&ls.db_lock);
                        return -EPERM;
                }

                if (addr > el->addr)
                        break;
        }

        nb = malloc(sizeof(*nb));
        if (nb == NULL) {
                pthread_rwlock_unlock(&ls.db_lock);
                return -ENOMEM;
        }

        nb->addr  = addr;
        nb->fd    = fd;
        nb->type  = type;

        list_add_tail(&nb->next, p);

        ++ls.nbs_len;

        log_dbg("Type %s neighbor %" PRIu64 " added.",
                nb->type == NB_DT ? "dt" : "mgmt", addr);

        pthread_rwlock_unlock(&ls.db_lock);

        return 0;
}

static int lsdb_del_nb(uint64_t     addr,
                       int          fd)
{
        struct list_head * p;
        struct list_head * h;

        pthread_rwlock_wrlock(&ls.db_lock);

        list_for_each_safe(p, h, &ls.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                if (nb->addr == addr && nb->fd == fd) {
                        list_del(&nb->next);
                        --ls.nbs_len;
                        pthread_rwlock_unlock(&ls.db_lock);
                        log_dbg("Type %s neighbor %" PRIu64 " deleted.",
                                nb->type == NB_DT ? "dt" : "mgmt", addr);
                        free(nb);
                        return 0;
                }
        }

        pthread_rwlock_unlock(&ls.db_lock);

        return -EPERM;
}

static void set_pff_modified(void)
{
        struct list_head * p;

        pthread_mutex_lock(&ls.routing_i_lock);
        list_for_each(p, &ls.routing_instances) {
                struct routing_i * inst =
                        list_entry(p, struct routing_i, next);
                pthread_mutex_lock(&inst->lock);
                inst->modified = true;
                pthread_mutex_unlock(&inst->lock);
        }
        pthread_mutex_unlock(&ls.routing_i_lock);
}

static int lsdb_add_link(uint64_t    src,
                         uint64_t    dst,
                         uint64_t    seqno,
                         qosspec_t * qs)
{
        struct list_head * p;
        struct adjacency * adj;
        struct timespec    now;
        int                ret = -1;

        clock_gettime(CLOCK_REALTIME_COARSE, &now);

        pthread_rwlock_wrlock(&ls.db_lock);

        list_for_each(p, &ls.db) {
                struct adjacency * a = list_entry(p, struct adjacency, next);
                if (a->dst == dst && a->src == src) {
                        if (a->seqno < seqno) {
                                a->stamp = now.tv_sec;
                                a->seqno = seqno;
                                ret = 0;
                        }
                        pthread_rwlock_unlock(&ls.db_lock);
                        return ret;
                }

                if (a->dst > dst || (a->dst == dst && a->src > src))
                        break;
        }

        adj = malloc(sizeof(*adj));
        if (adj == NULL) {
                pthread_rwlock_unlock(&ls.db_lock);
                return -ENOMEM;
        }

        adj->dst   = dst;
        adj->src   = src;
        adj->seqno = seqno;
        adj->stamp = now.tv_sec;

        list_add_tail(&adj->next, p);

        ls.db_len++;

        if (graph_update_edge(ls.graph, src, dst, *qs))
                log_warn("Failed to add edge to graph.");

        pthread_rwlock_unlock(&ls.db_lock);

        set_pff_modified();

        return 0;
}

static int lsdb_del_link(uint64_t src,
                         uint64_t dst)
{
        struct list_head * p;
        struct list_head * h;

        pthread_rwlock_wrlock(&ls.db_lock);

        list_for_each_safe(p, h, &ls.db) {
                struct adjacency * a = list_entry(p, struct adjacency, next);
                if (a->dst == dst && a->src == src) {
                        list_del(&a->next);
                        if (graph_del_edge(ls.graph, src, dst))
                                log_warn("Failed to delete edge from graph.");

                        ls.db_len--;

                        pthread_rwlock_unlock(&ls.db_lock);
                        set_pff_modified();
                        free(a);
                        return 0;
                }
        }

        pthread_rwlock_unlock(&ls.db_lock);

        return -EPERM;
}

static int nbr_to_fd(uint64_t addr)
{
        struct list_head * p;

        pthread_rwlock_rdlock(&ls.db_lock);

        list_for_each(p, &ls.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                if (nb->addr == addr && nb->type == NB_DT) {
                        pthread_rwlock_unlock(&ls.db_lock);
                        return nb->fd;
                }
        }

        pthread_rwlock_unlock(&ls.db_lock);

        return -1;
}

static void calculate_pff(struct routing_i * instance)
{
        int                fd;
        struct list_head   table;
        struct list_head * p;
        struct list_head * q;
        int                fds[PROG_MAX_FLOWS];

        if (ls.rtable(ls.graph, ipcpi.dt_addr, &table))
                return;

        pff_lock(instance->pff);

        pff_flush(instance->pff);

        /* Calulcate forwarding table from routing table. */
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

                pff_add(instance->pff, t->dst, fds, i);
        }

        pff_unlock(instance->pff);

        graph_free_routing_table(ls.graph, &table);
}

static void * periodic_recalc_pff(void * o)
{
        bool               modified;
        struct routing_i * inst = (struct routing_i *) o;

        while (true) {
                pthread_mutex_lock(&inst->lock);
                modified = inst->modified;
                inst->modified = false;
                pthread_mutex_unlock(&inst->lock);

                if (modified)
                        calculate_pff(inst);
                sleep(RECALC_TIME);
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

        list_for_each(p, &ls.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                if (nb->type == NB_MGMT)
                        flow_write(nb->fd, &lsm, sizeof(lsm));
        }
}

/* replicate the lsdb to a mgmt neighbor */
static void lsdb_replicate(int fd)
{
        struct list_head * p;
        struct list_head * h;
        struct list_head   copy;

        list_head_init(&copy);

        /* Lock the lsdb, copy the lsms and send outside of lock. */
        pthread_rwlock_rdlock(&ls.db_lock);

        list_for_each(p, &ls.db) {
                struct adjacency * adj;
                struct adjacency * cpy;
                adj = list_entry(p, struct adjacency, next);
                cpy = malloc(sizeof(*cpy));
                if (cpy == NULL) {
                        log_warn("Failed to replicate full lsdb.");
                        break;
                }

                cpy->dst   = adj->dst;
                cpy->src   = adj->src;
                cpy->seqno = adj->seqno;

                list_add_tail(&cpy->next, &copy);
        }

        pthread_rwlock_unlock(&ls.db_lock);

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

                pthread_rwlock_rdlock(&ls.db_lock);

                pthread_cleanup_push((void (*) (void *)) pthread_rwlock_unlock,
                                     (void *) &ls.db_lock);

                list_for_each_safe(p, h, &ls.db) {
                        struct adjacency * adj;
                        adj = list_entry(p, struct adjacency, next);
                        if (now.tv_sec - adj->stamp > LS_TIMEO) {
                                list_del(&adj->next);
                                log_dbg("%" PRIu64 " - %" PRIu64" timed out.",
                                        adj->src, adj->dst);
                                if (graph_del_edge(ls.graph, adj->src,
                                                   adj->dst))
                                        log_err("Failed to del edge.");
                                free(adj);
                                continue;
                        }

                        if (adj->src == ipcpi.dt_addr) {
                                adj->seqno++;
                                send_lsm(adj->src, adj->dst, adj->seqno);
                                adj->stamp = now.tv_sec;
                        }
                }

                pthread_cleanup_pop(true);

                sleep(LS_UPDATE_TIME);
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

        pthread_rwlock_rdlock(&ls.db_lock);

        pthread_cleanup_push((void (*))(void *) pthread_rwlock_unlock,
                             &ls.db_lock);

        list_for_each(p, &ls.nbs) {
                struct nb * nb = list_entry(p, struct nb, next);
                if (nb->type == NB_MGMT && nb->fd != in_fd)
                        flow_write(nb->fd, buf, len);
        }

        pthread_cleanup_pop(true);
}

static void * lsreader(void * o)
{
        fqueue_t *   fq;
        int          ret;
        uint8_t      buf[sizeof(struct lsa)];
        int          fd;
        qosspec_t    qs;
        struct lsa * msg;
        size_t       len;

        (void) o;

        memset(&qs, 0, sizeof(qs));

        fq = fqueue_create();
        if (fq == NULL)
                return (void *) -1;

        pthread_cleanup_push((void (*) (void *)) fqueue_destroy,
                             (void *) fq);

        while (true) {
                ret = fevent(ls.mgmt_set, fq, NULL);
                if (ret < 0) {
                        log_warn("Event error: %d.", ret);
                        continue;
                }

                while ((fd = fqueue_next(fq)) >= 0) {
                        if (fqueue_type(fq) != FLOW_PKT)
                                continue;

                        len = flow_read(fd, buf, sizeof(*msg));
                        if (len <= 0 || len != sizeof(*msg))
                                continue;

                        msg = (struct lsa *) buf;

                        if (lsdb_add_link(ntoh64(msg->s_addr),
                                          ntoh64(msg->d_addr),
                                          ntoh64(msg->seqno),
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

        pthread_mutex_lock(&ls.routing_i_lock);

        list_for_each(p, &ls.routing_instances) {
                struct routing_i * ri = list_entry(p, struct routing_i, next);
                pff_flow_state_change(ri->pff, fd, up);
        }

        pthread_mutex_unlock(&ls.routing_i_lock);
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

        c = (struct conn *) o;

        memset(&qs, 0, sizeof(qs));

        switch (event) {
        case NOTIFY_DT_CONN_ADD:
                if (lsdb_add_nb(c->conn_info.addr, c->flow_info.fd, NB_DT))
                        log_dbg("Failed to add neighbor to LSDB.");

                if (lsdb_add_link(ipcpi.dt_addr, c->conn_info.addr, 0, &qs))
                        log_dbg("Failed to add new adjacency to LSDB.");

                send_lsm(ipcpi.dt_addr, c->conn_info.addr, 0);

                break;
        case NOTIFY_DT_CONN_DEL:
                flow_event(c->flow_info.fd, false);

                if (lsdb_del_nb(c->conn_info.addr, c->flow_info.fd))
                        log_dbg("Failed to delete neighbor from LSDB.");

                if (lsdb_del_link(ipcpi.dt_addr, c->conn_info.addr))
                        log_dbg("Local link was not in LSDB.");
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
                if (lsdb_add_nb(c->conn_info.addr, c->flow_info.fd, NB_MGMT))
                        log_warn("Failed to add mgmt neighbor to LSDB.");
                /* replicate the entire lsdb */
                lsdb_replicate(c->flow_info.fd);
                break;
        case NOTIFY_MGMT_CONN_DEL:
                fset_del(ls.mgmt_set, c->flow_info.fd);
                if (lsdb_del_nb(c->conn_info.addr, c->flow_info.fd))
                        log_warn("Failed to delete mgmt neighbor from LSDB.");
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

        pthread_mutex_lock(&ls.routing_i_lock);

        list_add(&tmp->next, &ls.routing_instances);

        pthread_mutex_unlock(&ls.routing_i_lock);

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

        pthread_mutex_lock(&ls.routing_i_lock);

        list_del(&instance->next);

        pthread_mutex_unlock(&ls.routing_i_lock);

        pthread_cancel(instance->calculator);

        pthread_join(instance->calculator, NULL);

        pthread_mutex_destroy(&instance->lock);

        free(instance);
}

int link_state_init(enum pol_routing pr)
{
        struct conn_info info;

        memset(&info, 0, sizeof(info));

        strcpy(info.comp_name, LS_COMP);
        strcpy(info.protocol, LS_PROTO);
        info.pref_version = 1;
        info.pref_syntax  = PROTO_GPB;
        info.addr         = ipcpi.dt_addr;

        switch (pr) {
        case ROUTING_LINK_STATE:
                log_dbg("Using link state routing policy.");
                ls.rtable = graph_routing_table;
                break;
        case ROUTING_LINK_STATE_LFA:
                log_dbg("Using Loop-Free Alternates policy.");
                ls.rtable = graph_routing_table_lfa;
                break;
        default:
                goto fail_graph;
        }

        ls.graph = graph_create();
        if (ls.graph == NULL)
                goto fail_graph;

        if (notifier_reg(handle_event, NULL))
                goto fail_notifier_reg;

        if (pthread_rwlock_init(&ls.db_lock, NULL))
                goto fail_db_lock_init;

        if (pthread_mutex_init(&ls.routing_i_lock, NULL))
                goto fail_routing_i_lock_init;

        if (connmgr_comp_init(COMPID_MGMT, &info))
                goto fail_connmgr_comp_init;

        ls.mgmt_set = fset_create();
        if (ls.mgmt_set == NULL)
                goto fail_fset_create;

        list_head_init(&ls.db);
        list_head_init(&ls.nbs);
        list_head_init(&ls.routing_instances);

        if (pthread_create(&ls.lsupdate, NULL, lsupdate, NULL))
                goto fail_pthread_create_lsupdate;

        if (pthread_create(&ls.lsreader, NULL, lsreader, NULL))
                goto fail_pthread_create_lsreader;

        if (pthread_create(&ls.listener, NULL, ls_conn_handle, NULL))
                goto fail_pthread_create_listener;

        if (rib_reg(LSDB, &r_ops))
                goto fail_rib_reg;

        ls.db_len      = 0;
        ls.nbs_len     = 0;

        return 0;

 fail_rib_reg:
        pthread_cancel(ls.listener);
        pthread_join(ls.listener, NULL);
 fail_pthread_create_listener:
        pthread_cancel(ls.lsreader);
        pthread_join(ls.lsreader, NULL);
 fail_pthread_create_lsreader:
        pthread_cancel(ls.lsupdate);
        pthread_join(ls.lsupdate, NULL);
 fail_pthread_create_lsupdate:
        fset_destroy(ls.mgmt_set);
 fail_fset_create:
        connmgr_comp_fini(COMPID_MGMT);
 fail_connmgr_comp_init:
        pthread_mutex_destroy(&ls.routing_i_lock);
 fail_routing_i_lock_init:
        pthread_rwlock_destroy(&ls.db_lock);
 fail_db_lock_init:
        notifier_unreg(handle_event);
 fail_notifier_reg:
        graph_destroy(ls.graph);
 fail_graph:
        return -1;
}

void link_state_fini(void)
{
        struct list_head * p;
        struct list_head * h;

        rib_unreg(LSDB);

        pthread_cancel(ls.listener);
        pthread_join(ls.listener, NULL);

        pthread_cancel(ls.lsreader);
        pthread_join(ls.lsreader, NULL);

        pthread_cancel(ls.lsupdate);
        pthread_join(ls.lsupdate, NULL);

        fset_destroy(ls.mgmt_set);

        connmgr_comp_fini(COMPID_MGMT);

        graph_destroy(ls.graph);

        pthread_rwlock_wrlock(&ls.db_lock);

        list_for_each_safe(p, h, &ls.db) {
                struct adjacency * a = list_entry(p, struct adjacency, next);
                list_del(&a->next);
                free(a);
        }

        pthread_rwlock_unlock(&ls.db_lock);

        pthread_rwlock_destroy(&ls.db_lock);

        pthread_mutex_destroy(&ls.routing_i_lock);

        notifier_unreg(handle_event);
}
