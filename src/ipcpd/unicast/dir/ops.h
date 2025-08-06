/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Directory policy ops
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_IPCPD_UNICAST_DIR_OPS_H
#define OUROBOROS_IPCPD_UNICAST_DIR_OPS_H

struct dir_ops {
        int      (* init)(void * config);

        void     (* fini)(void);

        int      (* start)(void);

        void     (* stop)(void);

        int      (* reg)(const uint8_t * hash);

        int      (* unreg)(const uint8_t * hash);

        uint64_t (* query)(const uint8_t * hash);
};

#endif /* OUROBOROS_IPCPD_UNICAST_DIR_OPS_H */
