/*
 * Ouroboros - Copyright (C) 2016
 *
 * The Common Distributed Application Protocol
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

#ifndef OUROBOROS_CDAP_H
#define OUROBOROS_CDAP_H

#include "common.h"
#include <stdbool.h>

struct cdap;

struct cdap_ops {
        /* Sender related callbacks */
        int (* handle_connect_r)(port_id_t id,
                                 int invoke_id,
                                 int result);
        int (* handle_release_r)(port_id_t id,
                                 int invoke_id,
                                 int result);
        int (* handle_read_r)(port_id_t id,
                              int invoke_id,
                              int result,
                              char * reason,
                              char * obj_val,
                              bool complete);
        int (* handle_cancelread_r)(port_id_t id,
                                    int invoke_id,
                                    int result);
        int (* handle_write_r)(port_id_t id,
                               int invoke_id,
                               int result,
                               char * reason,
                               char * obj_val);
        int (* handle_create_r)(port_id_t id,
                                int invoke_id,
                                int result);
        int (* handle_delete_r)(port_id_t id,
                                int invoke_id,
                                int result);
        int (* handle_start_r)(port_id_t id,
                               int invoke_id,
                               int result);
        int (* handle_stop_r)(port_id_t id,
                              int invoke_id,
                              int result);

        /* Receiver related callbacks */
        int (* handle_connect)(port_id_t id,
                               int invoke_id,
                               rina_name_t src,
                               rina_name_t dst,
                               char * auth_mech,
                               char * auth_val);
        int (* handle_release)(port_id_t id,
                               int invoke_id);
        int (* handle_cancelread)(port_id_t id,
                                  int invoke_id);
        int (* handle_write)(port_id_t id,
                             int invoke_id,
                             char * obj_name,
                             char * obj_val);
        int (* handle_create)(port_id_t id,
                              int invoke_id,
                              char * obj_class,
                              char * obj_name,
                              char * obj_val);
        int (* handle_delete)(port_id_t id,
                              int invoke_id,
                              char * obj_name);
        int (* handle_start)(port_id_t id,
                             int invoke_id,
                             char * obj_name,
                             char * obj_val);
        int (* handle_stop)(port_id_t id,
                            int invoke_id,
                            char * obj_name,
                            char * obj_val);
};

struct cdap * cdap_create(struct cdap_ops ops,
                          port_id_t id);
int           cdap_destroy(struct cdap * instance);

/* Sender related functions */
int           cdap_send_connect(struct cdap * instance,
                                int invoke_id,
                                rina_name_t src,
                                rina_name_t dst,
                                char * auth_mech,
                                char * auth_val);
int           cdap_send_release(struct cdap * instance,
                                int invoke_id);
int           cdap_send_read(struct cdap * instance,
                             int invoke_id,
                             char * obj_name);
int           cdap_send_cancelread(struct cdap * instance,
                                   int invoke_id,
                                   char * obj_name);
int           cdap_send_write(struct cdap * instance,
                              int invoke_id,
                              char * obj_name,
                              char * obj_val);
int           cdap_send_create(struct cdap * instance,
                               int invoke_id,
                               char * obj_name,
                               char * obj_val);
int           cdap_send_delete(struct cdap * instance,
                               int invoke_id,
                               char * obj_name);
int           cdap_send_start(struct cdap * instance,
                              int invoke_id,
                              char * obj_name,
                              char * obj_val);
int           cdap_send_stop(struct cdap * instance,
                             int invoke_id,
                             char * obj_name,
                             char * obj_val);

/* Receiver related functions */
int           cdap_send_connect_r(struct cdap * instance,
                                  int invoke_id,
                                  int result);
int           cdap_send_release_r(struct cdap * instance,
                                  int invoke_id,
                                  int result);
int           cdap_send_read_r(struct cdap * instance,
                               int invoke_id,
                               int result,
                               char * reason,
                               char * obj_val,
                               bool complete);
int           cdap_send_cancelread_r(struct cdap * instance,
                                     int invoke_id,
                                     int result);
int           cdap_send_write_r(struct cdap * instance,
                                int invoke_id,
                                int result,
                                char * obj_name,
                                char * obj_val);
int           cdap_send_create_r(struct cdap * instance,
                                 int invoke_id,
                                 int result);
int           cdap_send_delete_r(struct cdap * instance,
                                 int invoke_id,
                                 int result);
int           cdap_send_start_r(struct cdap * instance,
                                int invoke_id,
                                int result);
int           cdap_send_stop_r(struct cdap * instance,
                               int invoke_id,
                               int result);
#endif
