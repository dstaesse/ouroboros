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

#ifndef OUROBOROS_IPCPD_NORMAL_RIBMGR_H
#define OUROBOROS_IPCPD_NORMAL_RIBMGR_H

#include <ouroboros/irm_config.h>
#include <ouroboros/utils.h>
#include <ouroboros/qos.h>

enum diss_target {
        NONE = 0,
        NEIGHBORS,
        ALL_MEMBERS
};

enum diss_freq {
        SINGLE = 0,
        PERIODIC
};

int  ribmgr_init(void);

void ribmgr_fini(void);

int  ribmgr_disseminate(char *           path,
                        enum diss_target target,
                        enum diss_freq   freq,
                        size_t           delay);

#endif /* OUROBOROS_IPCPD_NORMAL_RIBMGR_H */
