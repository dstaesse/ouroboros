/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Policy for flat addresses in a distributed way
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

#ifndef OUROBOROS_IPCPD_NORMAL_FLAT_H
#define OUROBOROS_IPCPD_NORMAL_FLAT_H

int      flat_init(void);
int      flat_fini(void);
uint64_t flat_address(void);

#endif /* OUROBOROS_IPCPD_NORMAL_FLAT_H */
