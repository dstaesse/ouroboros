/*
 * Ouroboros - Copyright (C) 2016
 *
 * The API to instruct the IRM
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

#define OUROBOROS_PREFIX "libouroboros-irm"

#include <ouroboros/irm.h>
#include <ouroboros/common.h>
#include <ouroboros/logs.h>
#include <ouroboros/sockets.h>
#include <ouroboros/instance_name.h>

#include <stdlib.h>

int irm_create_ipcp(instance_name_t * api,
                    char *            ipcp_type)
{
        irm_msg_t msg = IRM_MSG__INIT;

        if (api == NULL || ipcp_type == NULL || api->name == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_CREATE_IPCP;
        msg.ap_name = api->name;
        msg.has_api_id = true;
        msg.api_id = api->id;
        msg.ipcp_type = ipcp_type;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int irm_destroy_ipcp(instance_name_t * api)
{
        irm_msg_t msg = IRM_MSG__INIT;

        if (api == NULL || api->name == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_DESTROY_IPCP;
        msg.ap_name = api->name;
        msg.has_api_id = true;
        msg.api_id = api->id;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int irm_bootstrap_ipcp(instance_name_t   * api,
                       struct dif_config * conf)
{
        irm_msg_t msg = IRM_MSG__INIT;

        if (api == NULL || api->name == NULL || conf == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP;
        msg.ap_name = api->name;
        msg.has_api_id = true;
        msg.api_id = api->id;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int irm_enroll_ipcp(instance_name_t * api,
                    char *            dif_name)
{
        irm_msg_t msg = IRM_MSG__INIT;

        if (api == NULL || api->name == NULL || dif_name == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_ENROLL_IPCP;
        msg.ap_name = api->name;
        msg.has_api_id = true;
        msg.api_id = api->id;
        msg.n_dif_name = 1;
        msg.dif_name = malloc(sizeof(*(msg.dif_name)));
        if (msg.dif_name == NULL) {
                LOG_ERR("Failed to malloc");
                return -1;
        }
        msg.dif_name[0] = dif_name;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                free(msg.dif_name);
                return -1;
        }

        free(msg.dif_name);

        return 0;
}

int irm_reg_ipcp(instance_name_t * api,
                 char **           difs,
                 size_t            difs_size)
{
        irm_msg_t msg = IRM_MSG__INIT;

        if (api->name == NULL ||
            difs == NULL ||
            difs_size == 0 ||
            difs[0] == NULL) {
                return -EINVAL;
        }

        msg.code = IRM_MSG_CODE__IRM_REG_IPCP;
        msg.ap_name = api->name;
        msg.has_api_id = true;
        msg.api_id = api->id;
        msg.dif_name = difs;
        msg.n_dif_name = difs_size;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}

int irm_unreg_ipcp(const instance_name_t * api,
                   char **                 difs,
                   size_t                  difs_size)
{
        irm_msg_t msg = IRM_MSG__INIT;

        if (api == NULL ||
            api->name == NULL ||
            difs == NULL ||
            difs_size == 0 ||
            difs[0] == NULL) {
                return -EINVAL;
        }

        msg.code = IRM_MSG_CODE__IRM_UNREG_IPCP;
        msg.ap_name = api->name;
        msg.has_api_id = true;
        msg.api_id = api->id;
        msg.dif_name = difs;
        msg.n_dif_name = difs_size;

        if (send_irm_msg(&msg)) {
                LOG_ERR("Failed to send message to daemon");
                return -1;
        }

        return 0;
}
