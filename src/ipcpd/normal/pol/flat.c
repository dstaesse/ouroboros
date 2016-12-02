/*
 * Ouroboros - Copyright (C) 2016
 *
 * Policy for flat addresses in a distributed way
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "flat-addr-auth"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/errno.h>
#include <ouroboros/time_utils.h>

#include "shm_pci.h"
#include "ribmgr.h"
#include "ro.h"
#include "path.h"

#include <time.h>
#include <stdlib.h>
#include <math.h>
#include <string.h>
#include <assert.h>

#define POL_RO_ROOT "flat_addr"

#define TIMEOUT  100 /* ms */
#define STR_SIZE 100

#define FLAT_ADDR_REQ   0
#define FLAT_ADDR_REPLY 1

struct flat_addr_msg {
        uint8_t  code;
        uint64_t addr;
};

struct {
        int      sid;
        uint64_t addr;
        bool     addr_in_use;

        pthread_cond_t  cond;
        pthread_mutex_t lock;
} flat;

static char * addr_name(void)
{
        char * name;
        /* uint64_t as a string has 25 chars */
        char   addr_name[30];

        sprintf(addr_name, "%lu", (unsigned long) flat.addr);

        name = pathname_create(POL_RO_ROOT);
        if (name == NULL)
                return NULL;

        name = pathname_append(name, addr_name);
        return name;
}

static void ro_created(const char * name,
                       uint8_t *    data,
                       size_t       len)
{
        struct flat_addr_msg * msg;

        assert(name);
        assert(data);
        assert(len >= sizeof(*msg));

        msg = (struct flat_addr_msg *) data;
        if (msg->code == FLAT_ADDR_REQ && msg->addr == flat.addr) {
                msg->code = FLAT_ADDR_REPLY;
                ro_write(name, data, len);
        }
}

static void ro_updated(const char * name,
                       uint8_t *    data,
                       size_t       len)
{
        struct flat_addr_msg * msg;
        char * ro_name;

        assert(name);
        assert(data);
        assert(len >= sizeof(*msg));
        (void) len;

        ro_name = addr_name();
        if (ro_name == NULL) {
                free(data);
                return;
        }

        msg = (struct flat_addr_msg *) data;
        if (msg->code == FLAT_ADDR_REPLY &&
            strcmp(name, ro_name) == 0) {
                pthread_mutex_lock(&flat.lock);
                flat.addr_in_use = true;
                pthread_cond_broadcast(&flat.cond);
                pthread_mutex_unlock(&flat.lock);
        }

        free(data);
        free(ro_name);
}

static struct ro_sub_ops flat_sub_ops = {
        .ro_created = ro_created,
        .ro_updated = ro_updated,
        .ro_deleted = NULL
};

int flat_init(void)
{
        struct ro_attr     rattr;
        pthread_condattr_t cattr;
        char *             name;

        srand(time(NULL));
        flat.addr_in_use = false;

        ro_attr_init(&rattr);
        pthread_mutex_init(&flat.lock, NULL);
        pthread_condattr_init(&cattr);
#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        pthread_cond_init(&flat.cond, &cattr);

        flat.sid = ro_subscribe(POL_RO_ROOT, &flat_sub_ops);
        if (flat.sid < 0) {
                LOG_ERR("Could not subscribe to RIB.");
                pthread_cond_destroy(&flat.cond);
                pthread_mutex_destroy(&flat.lock);
                return -1;
        }

        name = pathname_create(POL_RO_ROOT);
        if (name == NULL) {
                pthread_cond_destroy(&flat.cond);
                pthread_mutex_destroy(&flat.lock);
                ro_unsubscribe(flat.sid);
                return -1;
        }

        if (ro_create(name, &rattr, NULL, 0)) {
                LOG_ERR("Could not create RO.");
                pathname_destroy(name);
                pthread_cond_destroy(&flat.cond);
                pthread_mutex_destroy(&flat.lock);
                ro_unsubscribe(flat.sid);
                return -1;
        }

        pathname_destroy(name);

        return 0;
}

int flat_fini(void)
{
        pthread_cond_destroy(&flat.cond);
        pthread_mutex_destroy(&flat.lock);
        ro_unsubscribe(flat.sid);
        return 0;
}

uint64_t flat_address(void)
{
        int                    ret = 0;
        uint64_t               max_addr;
        struct dt_const *      dtc;
        struct timespec        timeout = {(TIMEOUT / 1000),
                                          (TIMEOUT % 1000) * MILLION};
        struct timespec        abstime;
        struct ro_attr         attr;
        struct flat_addr_msg * msg;
        uint8_t *              buf;
        char *                 ro_name;

        dtc = ribmgr_dt_const();
        if (dtc == NULL)
                return INVALID_ADDR;

        if (dtc->addr_size == 8) {
                LOG_ERR("Policy cannot be used with 64 bit addresses.");
                return INVALID_ADDR;
        }

        while (ret != -ETIMEDOUT) {
                clock_gettime(PTHREAD_COND_CLOCK, &abstime);
                ts_add(&abstime, &timeout, &abstime);

                max_addr = (1 << (8 * dtc->addr_size)) - 1;
                flat.addr = (rand() % (max_addr - 1)) + 1;

                ro_attr_init(&attr);
                attr.recv_set = ALL_MEMBERS;
                attr.expiry.tv_sec = TIMEOUT / 1000;
                attr.expiry.tv_nsec = (TIMEOUT % 1000) * MILLION;

                buf = malloc(sizeof(*msg));
                if (buf == NULL)
                        return INVALID_ADDR;

                msg = (struct flat_addr_msg *) buf;
                msg->code = FLAT_ADDR_REQ;
                msg->addr = flat.addr;

                ro_name = addr_name();
                if (ro_name == NULL) {
                        free(buf);
                        return INVALID_ADDR;
                }

                pthread_mutex_lock(&flat.lock);
                if (ro_create(ro_name, &attr, buf, sizeof(*msg))) {
                        pthread_mutex_unlock(&flat.lock);
                        free(ro_name);
                        free(buf);
                        return INVALID_ADDR;
                }
                free(ro_name);

                while (flat.addr_in_use == false) {
                        ret = -pthread_cond_timedwait(&flat.cond,
                                                      &flat.lock,
                                                      &abstime);
                        if (ret == -ETIMEDOUT)
                                break;
                }
                pthread_mutex_unlock(&flat.lock);
        }

        return flat.addr;
}
