/*
 * Ouroboros - Copyright (C) 2016
 *
 * Functions to construct pathnames
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

#ifndef OUROBOROS_IPCPD_NORMAL_PATHNAME_H
#define OUROBOROS_IPCPD_NORMAL_PATHNAME_H

#define PATH_DELIMITER "/"

char * pathname_create(const char * name);

char * pathname_append(char *       pname,
                       const char * name);

void   pathname_destroy(char * pname);

#endif /* OUROBOROS_IPCPD_NORMAL_PATHNAME_H */
