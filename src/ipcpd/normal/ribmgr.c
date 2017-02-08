/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * RIB manager of the IPC Process
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#include "timerwheel.h"
#include "addr_auth.h"
#include "ribmgr.h"
#include "gam.h"
#include "ae.h"

#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#define BOOT_PATH "/" BOOT_NAME

struct {
        flow_set_t *   fs;
        fqueue_t *     fq;
        struct gam *   gam;
} ribmgr;


int ribmgr_init(void)
{
        enum pol_cacep pc;
        enum pol_gam   pg;

        if (rib_read(BOOT_PATH "/rm/gam/type", &pg, sizeof(pg))
            != sizeof(pg)) {
                log_err("Failed to read policy for ribmgr gam.");
                return -1;
        }

        if (rib_read(BOOT_PATH "/rm/gam/cacep", &pc, sizeof(pc))
            != sizeof(pc)) {
                log_err("Failed to read CACEP policy for ribmgr gam.");
                return -1;
        }

        /* FIXME: Implement cacep policies */
        (void) pc;

        ribmgr.gam = gam_create(pg, MGMT_AE);
        if (ribmgr.gam == NULL) {
                log_err("Failed to create gam.");
                return -1;
        }

        ribmgr.fs = flow_set_create();
        if (ribmgr.fs == NULL) {
                log_err("Failed to create flow set.");
                gam_destroy(ribmgr.gam);
                return -1;
        }

        ribmgr.fq = fqueue_create();
        if (ribmgr.fq == NULL) {
                log_err("Failed to create fq.");
                flow_set_destroy(ribmgr.fs);
                gam_destroy(ribmgr.gam);
                return -1;
        }

        return 0;
}

void ribmgr_fini(void)
{
        flow_set_destroy(ribmgr.fs);
        fqueue_destroy(ribmgr.fq);
        gam_destroy(ribmgr.gam);
}

int ribmgr_flow_arr(int       fd,
                    qosspec_t qs)
{
        assert(ribmgr.gam);

        if (gam_flow_arr(ribmgr.gam, fd, qs))
                return -1;

        return 0;
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
