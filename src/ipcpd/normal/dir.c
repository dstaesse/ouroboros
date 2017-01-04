/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * DIF directory
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

#define OUROBOROS_PREFIX "directory"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/errno.h>

#include "dir.h"
#include "ro.h"
#include "pathname.h"
#include "ribmgr.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

char * create_path(char * name)
{
        char * path;

        path = pathname_create(RO_DIR);
        if (path == NULL)
                return NULL;

        path = pathname_append(path, name);
        if (path == NULL) {
                pathname_destroy(path);
                return NULL;
        }

        return path;
}

int dir_init(void)
{
        char * path;
        struct ro_attr attr;

        ro_attr_init(&attr);
        attr.enrol_sync = true;
        attr.recv_set = ALL_MEMBERS;

        path = pathname_create(RO_DIR);
        if (path == NULL)
                return -1;

        if (ro_create(path, &attr, NULL, 0)) {
                pathname_destroy(path);
                LOG_ERR("Failed to create RIB object.");
                return -1;
        }

        pathname_destroy(path);

        return 0;
}

int dir_fini(void)
{
        char * path;

        path = pathname_create(RO_DIR);
        if (path == NULL)
                return -1;

        ro_delete(path);
        pathname_destroy(path);

        return 0;
}

int dir_name_reg(char * name)
{
        struct ro_attr attr;
        char * path;
        uint64_t * addr;

        assert(name);

        ro_attr_init(&attr);
        attr.enrol_sync = true;
        attr.recv_set = ALL_MEMBERS;

        path = create_path(name);
        if (path == NULL)
                return -ENOMEM;

        addr = malloc(sizeof(*addr));
        if (addr == NULL) {
                pathname_destroy(path);
                return -ENOMEM;
        }

        *addr = ribmgr_address();

        if (ro_create(path, &attr, (uint8_t *) addr, sizeof(*addr))) {
                pathname_destroy(path);
                free(addr);
                LOG_ERR("Failed to create RIB object.");
                return -1;
        }

        LOG_DBG("Registered %s.", name);
        pathname_destroy(path);

        free(name);

        return 0;
}

int dir_name_unreg(char * name)
{
        char * path;

        assert(name);

        path = create_path(name);
        if (path == NULL)
                return -ENOMEM;

        if (ro_delete(path)) {
                pathname_destroy(path);
                LOG_ERR("No such RIB object exists.");
                return -1;
        }

        pathname_destroy(path);

        return 0;
}

int dir_name_query(char * name)
{
        char * path;
        int ret = -1;
        uint8_t * ro_data;
        uint64_t addr;
        struct dt_const * dtc;

        path = create_path(name);
        if (path == NULL)
                return -ENOMEM;

        if (ro_exists(path)) {
                if (ro_read(path, &ro_data) < 0) {
                        pathname_destroy(path);
                        return -1;
                }
                addr = *((uint64_t *) ro_data);
                free(ro_data);

                dtc = ribmgr_dt_const();
                if (dtc == NULL) {
                        pathname_destroy(path);
                        return -1;
                }

                ret = (addr == ribmgr_address()) ? -1 : 0;
        }

        pathname_destroy(path);

        return ret;
}
