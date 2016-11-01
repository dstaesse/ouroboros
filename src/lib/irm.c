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

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/irm.h>
#include <ouroboros/utils.h>
#include <ouroboros/logs.h>
#include <ouroboros/sockets.h>

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

pid_t irm_create_ipcp(char *         name,
                      enum ipcp_type ipcp_type)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        msg.code = IRM_MSG_CODE__IRM_CREATE_IPCP;
        msg.dst_name = name;
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

int irm_destroy_ipcp(pid_t api)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (api == -1)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_DESTROY_IPCP;
        msg.has_api = true;
        msg.api     = api;

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

int irm_bootstrap_ipcp(pid_t               api,
                       struct dif_config * conf)
{
        irm_msg_t msg = IRM_MSG__INIT;
        dif_config_msg_t config = DIF_CONFIG_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (api == -1 || conf == NULL)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP;
        msg.has_api = true;
        msg.api     = api;

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
                config.has_has_ttl = true;
                config.has_has_chk = true;
                config.has_min_pdu_size = true;
                config.has_max_pdu_size = true;
                config.has_addr_auth_type = true;

                config.addr_size = conf->addr_size;
                config.cep_id_size = conf->cep_id_size;
                config.pdu_length_size = conf->pdu_length_size;
                config.qos_id_size = conf->qos_id_size;
                config.seqno_size = conf->seqno_size;
                config.has_ttl = conf->has_ttl;
                config.has_chk = conf->has_chk;
                config.min_pdu_size = conf->min_pdu_size;
                config.max_pdu_size = conf->max_pdu_size;
                config.addr_auth_type = conf->addr_auth_type;
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
                return -EIPCPTYPE;
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

ssize_t irm_list_ipcps(char *   name,
                       pid_t ** apis)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        size_t nr = 0;
        size_t i;

        if (apis == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_LIST_IPCPS;
        msg.dst_name = name;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL) {
                free(msg.dif_name);
                return -1;
        }

        if (recv_msg->apis == NULL) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        nr = recv_msg->n_apis;
        *apis = malloc(nr * sizeof(pid_t));
        if (*apis == NULL) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -ENOMEM;
        }

        for (i = 0; i < nr; i++) {
                (*apis)[i] = recv_msg->apis[i];
        }

        irm_msg__free_unpacked(recv_msg, NULL);

        return nr;
}

int irm_enroll_ipcp(pid_t  api,
                    char * dif_name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (api == -1 || dif_name == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_ENROLL_IPCP;
        msg.has_api = true;
        msg.api = api;
        msg.n_dif_name = 1;
        msg.dif_name = malloc(sizeof(*(msg.dif_name)));
        if (msg.dif_name == NULL) {
                LOG_ERR("Failed to malloc");
                return -ENOMEM;
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

static int check_ap(char * ap_name)
{
        struct stat s;

        if (stat(ap_name, &s) != 0)
                return -ENOENT;

        if (!(s.st_mode & S_IXUSR))
                return -EPERM;

        return 0;
}

static int check_ap_path(char ** ap_name)
{
        char * path = getenv("PATH");
        char * path_end = path + strlen(path) + 1;
        char * pstart;
        char * pstop = path;
        char * tmp;
        char * tstop;
        char * tstart;
        bool   perm = true;
        int    ret = 0;

        if (*ap_name == NULL || path == NULL)
                return -EINVAL;

        if (!strlen(path) || strchr(*ap_name, '/') != NULL) {
                if ((ret = check_ap(*ap_name)) < 0)
                        return ret;
                return 0;
        }

        tmp = malloc(strlen(path) + strlen(*ap_name) + 2);
        if (tmp == NULL)
                return -ENOMEM;

        tstop = tmp + strlen(path) + 1;
        strcpy(tstop--, *ap_name);

        while (pstop < path_end) {
                ret = 0;
                pstart = pstop;
                if (*pstart != '/') {
                        free(tmp);
                        return -EINVAL;
                }

                while (*pstop != '\0' && *pstop != ':')
                        pstop++;

                *pstop = '\0';
                tstart = tstop - (pstop++ - pstart);
                strcpy(tstart, pstart);
                *tstop = '/';

                if ((ret = check_ap(tstart)) < 0) {
                        if (ret == -EPERM)
                                perm = false;
                        continue;
                }

                free(*ap_name);
                *ap_name = strdup(tstart);
                free(tmp);

                if (*ap_name == NULL)
                        return -ENOMEM;

                return 0;
        }

        free(tmp);
        if (!perm)
                return -EPERM;

        return -ENOENT;
}

int irm_bind_ap(char *   ap,
                char *   name,
                uint16_t opts,
                int      argc,
                char **  argv)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;
        char * full_ap_name;

        if (ap == NULL || name == NULL)
                return -EINVAL;

        full_ap_name = strdup(ap);
        if (full_ap_name == NULL)
                return -ENOMEM;

        if ((ret = check_ap_path(&full_ap_name)) < 0) {
                free(full_ap_name);
                return ret;
        }

        msg.code = IRM_MSG_CODE__IRM_BIND_AP;
        msg.dst_name = name;
        msg.ap_name = full_ap_name;

        if (argv != NULL) {
                msg.n_args = argc;
                msg.args = argv;
        }

        msg.has_opts = true;
        msg.opts = opts;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -1;

        if (recv_msg->has_result == false) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        free(full_ap_name);
        return ret;
}

int irm_bind_api(pid_t api, char * name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_BIND_API;
        msg.has_api  = true;
        msg.api      = api;
        msg.dst_name = name;

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

int irm_unbind_ap(char * ap, char * name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_UNBIND_AP;
        msg.ap_name  = ap;
        msg.dst_name = name;

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

int irm_unbind_api(pid_t api, char * name)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_UNBIND_API;
        msg.has_api  = true;
        msg.api      = api;
        msg.dst_name = name;

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

int irm_reg(char *   name,
            char **  difs,
            size_t   difs_size)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (name == NULL || difs == NULL || difs_size == 0)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_REG;

        msg.dst_name = name;

        msg.dif_name = difs;
        msg.n_dif_name = difs_size;

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


int irm_unreg(char *   name,
              char **  difs,
              size_t   difs_size)
{
        irm_msg_t msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int ret = -1;

        if (name == NULL || difs == NULL || difs_size == 0)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_UNREG;

        msg.dst_name = name;

        msg.dif_name = difs;
        msg.n_dif_name = difs_size;

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
