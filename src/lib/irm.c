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

pid_t irm_create_ipcp(char *         ipcp_name,
                      enum ipcp_type ipcp_type)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (ipcp_name == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_CREATE_IPCP;
        msg.ap_name = ipcp_name;
        msg.has_ipcp_type = true;
        msg.ipcp_type = ipcp_type;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_destroy_ipcp(instance_name_t * api)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (api == NULL || api->name == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_DESTROY_IPCP;
        msg.ap_name = api->name;
        msg.has_api_id = true;
        msg.api_id = api->id;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_bootstrap_ipcp(instance_name_t   * api,
                       struct dif_config * conf)
{
        irm_msg_t msg = IRM_MSG__INIT;
        dif_config_msg_t config = DIF_CONFIG_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (api == NULL || api->name == NULL || conf == NULL)
                return -EINVAL;

        msg.code       = IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP;
        msg.ap_name    = api->name;
        msg.has_api_id = true;
        msg.api_id     = api->id;

        msg.conf = &config;
        config.dif_name = conf->dif_name;
        config.ipcp_type = conf->type;

        switch (conf->type) {
        case IPCP_NORMAL:
                config.has_addr_size = true;
                config.has_cep_id_size = true;
                config.has_pdu_length_size = true;
                config.has_qos_id_size = true;
                config.has_seqno_size = true;
                config.has_ttl_size = true;
                config.has_chk_size = true;
                config.has_min_pdu_size = true;
                config.has_max_pdu_size = true;

                config.addr_size = conf->addr_size;
                config.cep_id_size = conf->cep_id_size;
                config.pdu_length_size = conf->pdu_length_size;
                config.qos_id_size = conf->qos_id_size;
                config.seqno_size = conf->seqno_size;
                config.ttl_size = conf->ttl_size;
                config.chk_size = conf->chk_size;
                config.min_pdu_size = conf->min_pdu_size;
                config.max_pdu_size = conf->max_pdu_size;
                break;
        case IPCP_SHIM_UDP:
                config.has_ip_addr = true;
                config.ip_addr = conf->ip_addr;
                config.has_dns_addr = true;
                config.dns_addr = conf->dns_addr;
                break;
        case IPCP_LOCAL:
                break;
        case IPCP_SHIM_ETH_LLC:
                config.if_name = conf->if_name;
                break;
        default:
                return -1;
        }

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                return -1;
        }

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_enroll_ipcp(instance_name_t * api,
                    char *            dif_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

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

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                free(msg.dif_name);
                return -1;
        }

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        free(msg.dif_name);
        return ret;
}

int irm_reg(char *            name,
            instance_name_t * api,
            int               argc,
            char **           argv,
            bool              autoexec,
            char **           difs,
            size_t            difs_len)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (name == NULL || api->name == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_AP_REG;
        msg.dst_name = name;
        msg.ap_name = api->name;
        if (difs != NULL) {
                msg.dif_name = difs;
                msg.n_dif_name = difs_len;
        }

        if (argv != NULL) {
                msg.n_args = argc;
                msg.args = argv;
        } else {
                msg.has_api_id = true;
                msg.api_id = api->id;
        }

        msg.has_autoexec = true;
        msg.autoexec = autoexec;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_unreg(char *                  name,
              const instance_name_t * api,
              char **                 difs,
              size_t                  difs_len,
              bool                    hard)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (name == NULL && api == NULL)
                return -EINVAL;

        if (difs == NULL ||
            difs_len == 0 ||
            difs[0] == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_AP_UNREG;
        if (api != NULL) {
                msg.ap_name = api->name;
                msg.has_api_id = true;
                msg.api_id = api->id;
        }

        msg.dif_name = difs;
        msg.n_dif_name = difs_len;
        if (name != NULL)
                msg.dst_name = name;
        msg.hard = hard;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}
