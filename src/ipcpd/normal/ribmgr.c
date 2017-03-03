/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * RIB manager of the IPC Process
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "rib-manager"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/cdap.h>
#include <ouroboros/list.h>
#include <ouroboros/time_utils.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/rib.h>

#include "ae.h"
#include "gam.h"
#include "ribconfig.h"
#include "ribmgr.h"

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

struct {
        flow_set_t *       fs;
        fqueue_t *         fq;

        struct gam *       gam;
        struct nbs *       nbs;
        struct ae *        ae;

        struct nb_notifier nb_notifier;
} ribmgr;

static int ribmgr_neighbor_event(enum nb_event event,
                                 struct conn   conn)
{
        /* We are only interested in neighbors being added and removed. */
        switch (event) {
        case NEIGHBOR_ADDED:
                flow_set_add(ribmgr.fs, conn.flow_info.fd);
                break;
        case NEIGHBOR_REMOVED:
                flow_set_del(ribmgr.fs, conn.flow_info.fd);
                break;
        default:
                break;
        }

        return 0;
}

int ribmgr_init(void)
{
        enum pol_gam     pg;
        struct conn_info info;

        strcpy(info.ae_name, MGMT_AE);
        strcpy(info.protocol, CDAP_PROTO);
        info.pref_version = 1;
        info.pref_syntax = PROTO_GPB;

        ribmgr.nbs = nbs_create();
        if (ribmgr.nbs == NULL) {
                log_err("Failed to create neighbors.");
                return -1;
        }

        ribmgr.ae = connmgr_ae_create(info);
        if (ribmgr.ae == NULL) {
                log_err("Failed to create AE struct.");
                nbs_destroy(ribmgr.nbs);
                return -1;
        }

        if (rib_read(BOOT_PATH "/rm/gam/type", &pg, sizeof(pg))
            != sizeof(pg)) {
                log_err("Failed to read policy for ribmgr gam.");
                connmgr_ae_destroy(ribmgr.ae);
                nbs_destroy(ribmgr.nbs);
                return -1;
        }

        ribmgr.gam = gam_create(pg, ribmgr.nbs, ribmgr.ae);
        if (ribmgr.gam == NULL) {
                log_err("Failed to create gam.");
                connmgr_ae_destroy(ribmgr.ae);
                nbs_destroy(ribmgr.nbs);
                return -1;
        }

        ribmgr.fs = flow_set_create();
        if (ribmgr.fs == NULL) {
                log_err("Failed to create flow set.");
                gam_destroy(ribmgr.gam);
                connmgr_ae_destroy(ribmgr.ae);
                nbs_destroy(ribmgr.nbs);
                return -1;
        }

        ribmgr.fq = fqueue_create();
        if (ribmgr.fq == NULL) {
                log_err("Failed to create fq.");
                flow_set_destroy(ribmgr.fs);
                gam_destroy(ribmgr.gam);
                connmgr_ae_destroy(ribmgr.ae);
                nbs_destroy(ribmgr.nbs);
                return -1;
        }

        ribmgr.nb_notifier.notify_call = ribmgr_neighbor_event;
        if (nbs_reg_notifier(ribmgr.nbs, &ribmgr.nb_notifier)) {
                log_err("Failed to register notifier.");
                fqueue_destroy(ribmgr.fq);
                flow_set_destroy(ribmgr.fs);
                gam_destroy(ribmgr.gam);
                connmgr_ae_destroy(ribmgr.ae);
                nbs_destroy(ribmgr.nbs);
                return -1;
        }

        return 0;
}

void ribmgr_fini(void)
{
        nbs_unreg_notifier(ribmgr.nbs, &ribmgr.nb_notifier);
        flow_set_destroy(ribmgr.fs);
        fqueue_destroy(ribmgr.fq);
        gam_destroy(ribmgr.gam);
        connmgr_ae_destroy(ribmgr.ae);
        nbs_destroy(ribmgr.nbs);
}

int ribmgr_disseminate(char *           path,
                       enum diss_target target,
                       enum diss_freq   freq,
                       size_t           delay)
{
        (void) path;
        (void) target;
        (void) freq;
        (void) delay;

        return 0;
}
