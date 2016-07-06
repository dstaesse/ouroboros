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

#include <ouroboros/list.h>

#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>

#define reg_entry_has_api(e, id) (reg_entry_get_reg_instance(e, id) != NULL)
#define reg_entry_has_ap_name(e, name) (reg_entry_get_ap_name(e, name) != NULL)
#define reg_entry_has_ap_auto(e, name) (reg_entry_get_reg_auto(e, name) != NULL)

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

struct reg_instance {
        struct list_head next;
        pid_t            api;

        /* the api will block on this */
        enum reg_i_state state;
        pthread_cond_t   wakeup;
        pthread_mutex_t  mutex;
};

/* an entry in the registry */
struct reg_entry {
        struct list_head next;

        /* generic name */
        char * name;

        /* names of the aps that can listen to this name */
        struct list_head ap_names;

        enum reg_name_state state;

        uint32_t flags;

        /* auto execution info */
        struct list_head auto_ap_info;

        /* known instances */
        struct list_head ap_instances;

        char * req_ae_name;
        int    response;

        pthread_cond_t  acc_signal;
        pthread_mutex_t state_lock;
};

struct reg_auto {
        struct list_head next;
        char * ap_name;
        char ** argv;
};

struct reg_ap_name {
        struct list_head next;
        char * ap_name;
};

struct reg_instance * reg_instance_create(pid_t api);
void                  reg_instance_destroy(struct reg_instance * i);

void                  reg_instance_sleep(struct reg_instance * i);
void                  reg_instance_wake(struct reg_instance * i);

struct reg_entry *    reg_entry_create();
struct reg_entry *    reg_entry_init(struct reg_entry * e,
                                     char *             name,
                                     char *             ap_name,
                                     uint32_t           flags);
void                  reg_entry_destroy(struct reg_entry * e);

struct reg_ap_name *  reg_entry_get_ap_name(struct reg_entry * e,
                                            char *             ap_name);
struct reg_instance * reg_entry_get_reg_instance(struct reg_entry * e,
                                                 pid_t              api);

struct reg_auto *     reg_entry_get_reg_auto(struct reg_entry * e,
                                             char *             ap_name);
pid_t                 reg_entry_resolve_api(struct reg_entry * e);
char **               reg_entry_resolve_auto(struct reg_entry * e);

int                   registry_add_entry(struct list_head * registry,
                                         char *             name,
                                         char *             ap_name,
                                         uint16_t           flags);
int                   registry_add_ap_auto(struct list_head * registry,
                                           char *             name,
                                           char *             ap_name,
                                           char **            argv);
int                   registry_remove_ap_auto(struct list_head * registry,
                                              char *             name,
                                              char *             ap_name);
struct reg_instance * registry_add_api_name(struct list_head * registry,
                                            pid_t              api,
                                            char *             name);
int                   registry_remove_api_name(struct list_head * registry,
                                               pid_t              api,
                                               char *             name);
struct reg_entry *    registry_get_entry_by_name(struct list_head * registry,
                                                 char *             name);
struct reg_entry *    registry_get_entry_by_ap_name(struct list_head * registry,
                                                    char *             ap_name);
struct reg_entry *    registry_get_entry_by_ap_id(struct list_head * registry,
                                                  pid_t              api);
void                  registry_del_name(struct list_head * registry,
                                        char *             name);

#endif
