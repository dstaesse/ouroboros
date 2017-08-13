/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Data transfer neighbors
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

#ifndef OUROBOROS_IPCPD_NORMAL_NEIGHBORS_H
#define OUROBOROS_IPCPD_NORMAL_NEIGHBORS_H

#include <ouroboros/ipcp.h>
#include <ouroboros/list.h>
#include <ouroboros/qos.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/cacep.h>

#include "connmgr.h"

enum nb_event {
        NEIGHBOR_ADDED,
        NEIGHBOR_REMOVED,
        NEIGHBOR_QOS_CHANGE
};

typedef int (* nb_notify_t)(enum nb_event event,
                            struct conn   conn);

struct nb_notifier {
        struct list_head next;
        nb_notify_t      notify_call;
};

struct nb {
        struct list_head next;
        struct conn      conn;
};

struct nbs {
        struct list_head notifiers;
        pthread_mutex_t  notifiers_lock;

        struct list_head list;
        pthread_mutex_t  list_lock;
};

struct nbs * nbs_create(void);

void         nbs_destroy(struct nbs * nbs);

int          nbs_add(struct nbs * nbs,
                     struct conn  conn);

int          nbs_update_qos(struct nbs * nbs,
                            int          fd,
                            qosspec_t    qs);

int          nbs_del(struct nbs * nbs,
                     int          fd);

bool         nbs_has(struct nbs * nbs,
                     uint64_t     addr);

int          nbs_reg_notifier(struct nbs *         nbs,
                              struct nb_notifier * notify);

int          nbs_unreg_notifier(struct nbs *         nbs,
                                struct nb_notifier * notify);

#endif
