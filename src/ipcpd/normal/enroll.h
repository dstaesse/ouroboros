/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Enrollment Task
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#ifndef OUROBOROS_IPCPD_NORMAL_ENROLL_H
#define OUROBOROS_IPCPD_NORMAL_ENROLL_H

int  enroll_init(void);

void enroll_fini(void);

int  enroll_start(void);

void enroll_stop(void);

int  enroll_boot(char * dst_name);

#endif /* OUROBOROS_IPCPD_NORMAL_ENROLL_H */
