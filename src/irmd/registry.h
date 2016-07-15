/*
 * Ouroboros - Copyright (C) 2016
 *
 * The IPC Resource Manager - Registry
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#ifndef OUROBOROS_IRMD_REGISTRY_H
#define OUROBOROS_IRMD_REGISTRY_H

#include <ouroboros/config.h>
#include <ouroboros/list.h>
#include <ouroboros/irm_config.h>

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>

#define registry_has_name(r, name) \
        (registry_get_entry_by_name(r, name) != NULL)
#define registry_name_has_api(r, name) \
        (registry_get_api_by_name(r, name) != NULL)

enum reg_name_state {
        REG_NAME_NULL = 0,
        REG_NAME_IDLE,
        REG_NAME_AUTO_ACCEPT,
        REG_NAME_AUTO_EXEC,
        REG_NAME_FLOW_ACCEPT,
        REG_NAME_FLOW_ARRIVED
};

enum reg_i_state {
        REG_I_NULL = 0,
        REG_I_SLEEP,
        REG_I_WAKE
};

struct reg_api {
        struct list_head next;
        pid_t            api;

        /* the api will block on this */
        enum reg_i_state state;
        pthread_cond_t   cond_state;
        pthread_mutex_t  mutex;
};

/* an entry in the registry */
struct reg_entry {
        struct list_head    next;
        char *              name;

        /* DIFs in which this name is registered */
        struct list_head    difs;

        /* names of the APs that can listen to this name */
        struct list_head    bindings;
        /* known instances */
        struct list_head    reg_apis;

        /* flow handling information */
        enum reg_name_state state;
        char *              req_ae_name;
        int                 response;
        pthread_cond_t      acc_signal;
        pthread_mutex_t     state_lock;
};

struct reg_api *      reg_api_create(pid_t api);
void                  reg_api_destroy(struct reg_api * i);
void                  reg_api_sleep(struct reg_api * i);
void                  reg_api_wake(struct reg_api * i);



struct reg_binding *  reg_binding_create(char *   apn,
                                         uint32_t opts,
                                         char **  argv);
void                  reg_binding_destroy();

struct reg_entry *    reg_entry_create();
struct reg_entry *    reg_entry_init(struct reg_entry * e,
                                     char *             name);
void                  reg_entry_destroy(struct reg_entry * e);

struct reg_binding *  reg_entry_get_binding(struct reg_entry * e,
                                            char *             apn);
char **               reg_entry_get_auto_info(struct reg_entry * e);
void                  reg_entry_del_binding(struct reg_entry * e,
                                            char *             apn);
struct reg_api *      reg_entry_get_reg_api(struct reg_entry * e,
                                            pid_t              api);

pid_t                 reg_entry_resolve_api(struct reg_entry * e);
bool                  reg_entry_is_local_in_dif(struct reg_entry * e,
                                                char *             dif_name);
int                   reg_entry_add_local_in_dif(struct reg_entry * e,
                                                 char *             dif_name,
                                                 enum ipcp_type     type);
void                  reg_entry_del_local_from_dif(struct reg_entry * e,
                                                   char *             dif_name);

struct reg_entry *    registry_assign(struct list_head * registry,
                                      char *             name);
void                  registry_deassign(struct list_head * registry,
                                        char *             name);
int                   registry_add_binding(struct list_head * registry,
                                           char *             name,
                                           char *             apn,
                                           uint32_t           flags,
                                           char **            argv);
void                  registry_del_binding(struct list_head * registry,
                                           char *             name,
                                           char *             apn);
struct reg_api *      registry_add_api_name(struct list_head * registry,
                                            pid_t              api,
                                            char *             name);
void                  registry_del_api(struct list_head * registry,
                                       pid_t              api);
struct reg_api *      registry_get_api_by_name(struct list_head * registry,
                                               char *             name);
struct reg_entry *    registry_get_entry_by_name(struct list_head * registry,
                                                 char *             name);
struct reg_entry *    registry_get_entry_by_apn(struct list_head * registry,
                                                char *             apn);
struct reg_entry *    registry_get_entry_by_api(struct list_head * registry,
                                                pid_t              api);
char *                registry_get_dif_for_dst(struct list_head * registry,
                                               char *             dst_name);
int                   registry_add_name_to_dif(struct list_head * registry,
                                               char *             name,
                                               char *             dif_name,
                                               enum ipcp_type     type);
void                  registry_del_name_from_dif(struct list_head * registry,
                                                 char *             name,
                                                 char *             dif_name);
#endif
