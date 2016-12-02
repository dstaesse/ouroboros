/*
 * Ouroboros - Copyright (C) 2016
 *
 * RIB objects
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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

#ifndef OUROBOROS_IPCPD_NORMAL_RO_H
#define OUROBOROS_IPCPD_NORMAL_RO_H

enum ro_recv_set {
        NO_SYNC = 0,
        NEIGHBORS,
        ALL_MEMBERS
};

struct ro_attr {
        bool             enrol_sync;
        enum ro_recv_set recv_set;
        struct timespec  expiry;
};

/* All RIB-objects have a pathname, separated by a slash. */
/* Takes ownership of the data */
int          ro_create(const char *     name,
                       struct ro_attr * attr,
                       uint8_t *        data,
                       size_t           len);

int          ro_attr_init(struct ro_attr * attr);

int          ro_delete(const char * name);

int          ro_write(const char * name,
                      uint8_t *    data,
                      size_t       len);

/* Reader takes ownership of data */
ssize_t      ro_read(const char * name,
                     uint8_t **   data);

ssize_t      ro_children(const char * name,
                         char ***     children);

bool         ro_exists(const char * name);

/* Callback passes ownership of the data */
struct ro_sub_ops {
        void (* ro_created)(const char * name,
                            uint8_t *    data,
                            size_t       len);
        void (* ro_updated)(const char * name,
                            uint8_t *    data,
                            size_t       len);
        void (* ro_deleted)(const char * name);
};

/* Returns subscriber-id */
int          ro_subscribe(const char *        name,
                          struct ro_sub_ops * ops);

int          ro_unsubscribe(int sid);

#endif /* OUROBOROS_IPCPD_NORMAL_RO_H */
