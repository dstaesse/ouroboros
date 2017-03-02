/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Handles the different AP connections
 *
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "normal-ipcp"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/dev.h>
#include <ouroboros/cacep.h>
#include <ouroboros/cdap.h>
#include <ouroboros/errno.h>

#include "ae.h"
#include "connmgr.h"
#include "enroll.h"
#include "fmgr.h"
#include "frct.h"
#include "ipcp.h"
#include "ribmgr.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

#define FRCT_PROTO "frct"

struct ae_conn {
        struct list_head next;
        struct conn      conn;
};

struct ae {
        struct list_head next;
        struct conn_info info;

        struct list_head conn_list;
        pthread_cond_t   conn_cond;
        pthread_mutex_t  conn_lock;
};

struct {
        pthread_t        acceptor;

        struct list_head aes;
        pthread_mutex_t  aes_lock;
} connmgr;

static int add_ae_conn(struct ae *        ae,
                       int                fd,
                       qosspec_t          qs,
                       struct conn_info * rcv_info)
{
        struct ae_conn * ae_conn = NULL;

        ae_conn = malloc(sizeof(*ae_conn));
        if (ae_conn == NULL) {
                log_err("Not enough memory.");
                return -1;
        }

        ae_conn->conn.conn_info = *rcv_info;
        ae_conn->conn.flow_info.fd = fd;
        ae_conn->conn.flow_info.qs = qs;

        list_head_init(&ae_conn->next);

        pthread_mutex_lock(&ae->conn_lock);
        list_add(&ae_conn->next, &ae->conn_list);
        pthread_cond_signal(&ae->conn_cond);
        pthread_mutex_unlock(&ae->conn_lock);

        return 0;
}

static struct ae * find_ae_by_name(char * name)
{
        struct list_head * p = NULL;

        list_for_each(p, &connmgr.aes) {
                struct ae * ae = list_entry(p, struct ae, next);
                if (strcmp(ae->info.ae_name, name) == 0)
                        return ae;
        }

        return NULL;
}

static void * flow_acceptor(void * o)
{
        int               fd;
        qosspec_t         qs;
        struct conn_info  rcv_info;
        struct conn_info  fail_info;
        struct ae *       ae = NULL;

        (void) o;

        memset(&fail_info, 0, sizeof(fail_info));

        while (true) {
                pthread_rwlock_rdlock(&ipcpi.state_lock);

                if (ipcp_get_state() != IPCP_OPERATIONAL) {
                        pthread_rwlock_unlock(&ipcpi.state_lock);
                        log_info("Shutting down flow acceptor.");
                        return 0;
                }

                pthread_rwlock_unlock(&ipcpi.state_lock);

                fd = flow_accept(&qs);
                if (fd < 0) {
                        if (fd != -EIRMD)
                                log_warn("Flow accept failed: %d", fd);
                        continue;
                }

                if (flow_alloc_resp(fd, 0)) {
                        log_err("Failed to respond to flow alloc request.");
                        continue;
                }

                if (cacep_rcv(fd, &rcv_info)) {
                        log_err("Error establishing application connection.");
                        flow_dealloc(fd);
                        continue;
                }

                pthread_mutex_lock(&connmgr.aes_lock);
                ae = find_ae_by_name(rcv_info.ae_name);
                pthread_mutex_unlock(&connmgr.aes_lock);

                if (ae != NULL) {
                        if (cacep_snd(fd, &ae->info)) {
                                log_err("Failed to respond to req.");
                                flow_dealloc(fd);
                                continue;
                        }

                        if (add_ae_conn(ae, fd, qs, &rcv_info)) {
                                log_err("Failed to add ae conn.");
                                flow_dealloc(fd);
                                continue;
                        }
                } else {
                        cacep_snd(fd, &fail_info);
                        flow_dealloc(fd);
                }
        }

        return (void *) 0;
}

int connmgr_init(void)
{
        list_head_init(&connmgr.aes);

        if (pthread_mutex_init(&connmgr.aes_lock, NULL))
                return -1;

        return 0;
}

int connmgr_start(void)
{
        pthread_create(&connmgr.acceptor, NULL, flow_acceptor, NULL);

        return 0;
}

void connmgr_stop(void)
{
        pthread_cancel(connmgr.acceptor);
        pthread_join(connmgr.acceptor, NULL);
}

void connmgr_fini(void)
{
        struct list_head * p = NULL;
        struct list_head * n = NULL;

        pthread_mutex_lock(&connmgr.aes_lock);

        list_for_each_safe(p, n, &connmgr.aes) {
                struct ae * e = list_entry(p, struct ae, next);
                connmgr_ae_destroy(e);
        }

        pthread_mutex_unlock(&connmgr.aes_lock);

        pthread_mutex_destroy(&connmgr.aes_lock);
}

struct ae * connmgr_ae_create(struct conn_info info)
{
        struct ae * ae;

        ae = malloc(sizeof(*ae));
        if (ae == NULL)
                return NULL;

        list_head_init(&ae->next);
        list_head_init(&ae->conn_list);

        ae->info = info;

        if (pthread_mutex_init(&ae->conn_lock, NULL)) {
                free(ae);
                return NULL;
        }

        if (pthread_cond_init(&ae->conn_cond, NULL)) {
                pthread_mutex_destroy(&ae->conn_lock);
                free(ae);
                return NULL;
        }

        pthread_mutex_lock(&connmgr.aes_lock);
        list_add(&ae->next, &connmgr.aes);
        pthread_mutex_unlock(&connmgr.aes_lock);

        return ae;
}

void connmgr_ae_destroy(struct ae * ae)
{
        struct list_head * p = NULL;
        struct list_head * n = NULL;

        assert(ae);

        pthread_mutex_lock(&connmgr.aes_lock);
        pthread_mutex_lock(&ae->conn_lock);

        list_for_each_safe(p, n, &ae->conn_list) {
                struct ae_conn * e = list_entry(p, struct ae_conn, next);
                list_del(&e->next);
                free(e);
        }

        pthread_mutex_unlock(&ae->conn_lock);

        pthread_cond_destroy(&ae->conn_cond);
        pthread_mutex_destroy(&ae->conn_lock);

        list_del(&ae->next);

        pthread_mutex_unlock(&connmgr.aes_lock);

        free(ae);
}

int connmgr_alloc(struct ae *   ae,
                  char *        dst_name,
                  qosspec_t     qs,
                  struct conn * conn)
{
        assert(ae);
        assert(dst_name);
        assert(conn);

        memset(&conn->conn_info, 0, sizeof(conn->conn_info));

        conn->flow_info.fd = flow_alloc(dst_name, &qs);
        if (conn->flow_info.fd < 0) {
                log_err("Failed to allocate flow to %s.", dst_name);
                return -1;
        }

        conn->flow_info.qs = qs;

        if (flow_alloc_res(conn->flow_info.fd)) {
                log_err("Flow allocation to %s failed.", dst_name);
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (cacep_snd(conn->flow_info.fd, &ae->info)) {
                log_err("Failed to create application connection.");
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (cacep_rcv(conn->flow_info.fd, &conn->conn_info)) {
                log_err("Failed to connect to application.");
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        if (strcmp(ae->info.protocol, conn->conn_info.protocol) ||
            ae->info.pref_version != conn->conn_info.pref_version ||
            ae->info.pref_syntax != conn->conn_info.pref_syntax) {
                flow_dealloc(conn->flow_info.fd);
                return -1;
        }

        return 0;
}

int connmgr_wait(struct ae *   ae,
                 struct conn * conn)
{
        struct ae_conn * ae_conn;

        assert(ae);
        assert(conn);

        pthread_mutex_lock(&ae->conn_lock);

        pthread_cleanup_push((void(*)(void *))pthread_mutex_unlock,
                             (void *) &ae->conn_lock);

        while (list_is_empty(&ae->conn_list))
                pthread_cond_wait(&ae->conn_cond, &ae->conn_lock);

        ae_conn = list_first_entry((&ae->conn_list), struct ae_conn, next);
        if (ae_conn == NULL) {
                pthread_mutex_unlock(&ae->conn_lock);
                return -1;
        }

        *conn = ae_conn->conn;

        list_del(&ae_conn->next);
        free(ae_conn);

        pthread_cleanup_pop(true);

        return 0;
}
