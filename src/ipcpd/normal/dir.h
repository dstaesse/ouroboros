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

#ifndef OUROBOROS_IPCPD_NORMAL_DIR_H
#define OUROBOROS_IPCPD_NORMAL_DIR_H

#define RO_DIR "directory"

int dir_init(void);

int dir_fini(void);

int dir_name_reg(char * name);

int dir_name_unreg(char * name);

int dir_name_query(char * name);

#endif /* OUROBOROS_IPCPD_NORMAL_DIR_H */
