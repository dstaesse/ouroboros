/*
 * Ouroboros - Copyright (C) 2016
 *
 * Normal IPCP - RIB Manager - CDAP request
 *
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#ifndef OUROBOROS_IPCPD_NORMAL_CDAP_REQUEST_H
#define OUROBOROS_IPCPD_NORMAL_CDAP_REQUEST_H

#include <ouroboros/config.h>
#include <ouroboros/cdap.h>
#include <ouroboros/list.h>

#include <pthread.h>

enum cdap_opcode {
        READ = 0,
        WRITE,
        START,
        STOP,
        CREATE,
        DELETE
};

enum creq_state {
        REQ_INIT = 0,
        REQ_PENDING,
        REQ_RESPONSE,
        REQ_DONE,
        REQ_DESTROY
};

struct cdap_request {
        struct list_head next;

        enum cdap_opcode code;
        char *           name;
        int              invoke_id;
        struct cdap *    instance;

        int              result;

        enum creq_state  state;
        pthread_cond_t   cond;
        pthread_mutex_t  lock;
};

struct cdap_request * cdap_request_create(enum cdap_opcode code,
                                          char *           name,
                                          int              invoke_id,
                                          struct cdap *    instance);

void                  cdap_request_destroy(struct cdap_request * creq);

int                   cdap_request_wait(struct cdap_request * creq);

void                  cdap_request_respond(struct cdap_request * creq,
                                           int                   response);

#endif /* OUROBOROS_IPCPD_NORMAL_CDAP_REQUEST_H */
