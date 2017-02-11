/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * DIF directory
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/rib.h>

#include "dir.h"
#include "ipcp.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define DIR_PATH "/" DIR_NAME

static char dir_path[RIB_MAX_PATH_LEN + 1];

static void dir_path_reset(void) {
        dir_path[strlen(DIR_PATH)]= '\0';
        assert(strcmp(DIR_PATH, dir_path) == 0);
}

int dir_init(void)
{
        /*FIXME: set ribmgr dissemination here */
        if (rib_add(RIB_ROOT, DIR_NAME))
                return -1;

        strcpy(dir_path, DIR_PATH);

        return 0;
}

int dir_fini(void)
{
        /* FIXME: remove ribmgr dissemination here*/

        dir_path_reset();
        rib_del(dir_path);

        return 0;
}

int dir_name_reg(char * name)
{
        int ret;

        assert(name);

        if (ipcp_get_state() != IPCP_OPERATIONAL)
                return -EPERM;

        dir_path_reset();

        ret = rib_add(dir_path, name);
        if (ret == -ENOMEM)
                return -ENOMEM;

        rib_path_append(dir_path, name);
        ret = rib_add(dir_path, ipcpi.name);
        if (ret == -EPERM)
                return -EPERM;
        if (ret == -ENOMEM) {
                if (rib_children(dir_path, NULL) == 0)
                        rib_del(dir_path);
                return -ENOMEM;
        }

        return 0;
}

int dir_name_unreg(char * name)
{
        size_t len;

        assert(name);

        if (ipcp_get_state() != IPCP_OPERATIONAL)
                return -EPERM;

        dir_path_reset();

        rib_path_append(dir_path, name);

        if (!rib_has(dir_path))
                return 0;

        len = strlen(dir_path);

        rib_path_append(dir_path, ipcpi.name);

        rib_del(dir_path);

        dir_path[len] = '\0';

        if (rib_children(dir_path, NULL) == 0)
                rib_del(dir_path);

        return 0;
}

int dir_name_query(char * name)
{
        size_t len;

        if (ipcp_get_state() != IPCP_OPERATIONAL)
                return -EPERM;

        dir_path_reset();

        rib_path_append(dir_path, name);

        if (!rib_has(dir_path))
                return -1;

        /* FIXME: assert after local IPCP is deprecated */
        len = strlen(dir_path);

        rib_path_append(dir_path, ipcpi.name);

        if (rib_has(dir_path)) {
                dir_path[len] = '\0';
                if (rib_children(dir_path, NULL) == 1)
                        return -1;
        }

        return 0;
}
