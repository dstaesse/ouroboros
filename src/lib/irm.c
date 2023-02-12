/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * The API to instruct the IRM
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <ouroboros/errno.h>
#include <ouroboros/hash.h>
#include <ouroboros/irm.h>
#include <ouroboros/utils.h>
#include <ouroboros/sockets.h>

#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

pid_t irm_create_ipcp(const char *   name,
                      enum ipcp_type type)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code          = IRM_MSG_CODE__IRM_CREATE_IPCP;
        msg.name          = (char *) name;
        msg.has_ipcp_type = true;
        msg.ipcp_type     = type;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EIRMD;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_destroy_ipcp(pid_t pid)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;

        if (pid < 0)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_DESTROY_IPCP;
        msg.has_pid = true;
        msg.pid     = pid;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_bootstrap_ipcp(pid_t                      pid,
                       const struct ipcp_config * conf)
{
        irm_msg_t         msg            = IRM_MSG__INIT;
        ipcp_config_msg_t cfg_msg        = IPCP_CONFIG_MSG__INIT;
        layer_info_msg_t  layer_info_msg = LAYER_INFO_MSG__INIT;
        dt_config_msg_t   dt_cfg_msg     = DT_CONFIG_MSG__INIT;
        uni_config_msg_t  uni_cfg_msg    = UNI_CONFIG_MSG__INIT;
        eth_config_msg_t  eth_cfg_msg    = ETH_CONFIG_MSG__INIT;
        udp_config_msg_t  udp_cfg_msg    = UDP_CONFIG_MSG__INIT;
        irm_msg_t *       recv_msg       = NULL;
        int               ret            = -1;

        if (pid == -1 || conf == NULL)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP;
        msg.has_pid = true;
        msg.pid     = pid;

        cfg_msg.ipcp_type = conf->type;
        layer_info_msg.layer_name = (char *) conf->layer_info.layer_name;
        layer_info_msg.dir_hash_algo  = conf->layer_info.dir_hash_algo;

        switch (conf->type) {
        case IPCP_UNICAST:
                dt_cfg_msg.addr_size       = conf->unicast.dt.addr_size;
                dt_cfg_msg.eid_size        = conf->unicast.dt.eid_size;
                dt_cfg_msg.max_ttl         = conf->unicast.dt.max_ttl;
                dt_cfg_msg.routing_type    = conf->unicast.dt.routing_type;
                uni_cfg_msg.dt             = &dt_cfg_msg;
                uni_cfg_msg.addr_auth_type = conf->unicast.addr_auth_type;
                uni_cfg_msg.cong_avoid     = conf->unicast.cong_avoid;
                cfg_msg.unicast            = &uni_cfg_msg;
                break;
        case IPCP_UDP:
                udp_cfg_msg.ip_addr  = conf->udp.ip_addr;
                udp_cfg_msg.dns_addr = conf->udp.dns_addr;
                udp_cfg_msg.port     = conf->udp.port;
                cfg_msg.udp          = &udp_cfg_msg;
                break;
        case IPCP_LOCAL:
                /* FALLTHRU */
        case IPCP_BROADCAST:
                break;
        case IPCP_ETH_DIX:
                eth_cfg_msg.has_ethertype = true;
                eth_cfg_msg.ethertype     = conf->eth.ethertype;
                /* FALLTHRU */
        case IPCP_ETH_LLC:
                eth_cfg_msg.dev = conf->eth.dev;
                cfg_msg.eth = &eth_cfg_msg;
                break;
        default:
                return -EIPCPTYPE;
        }

        cfg_msg.layer_info = &layer_info_msg;
        msg.conf           = &cfg_msg;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EIRMD;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_connect_ipcp(pid_t        pid,
                     const char * dst,
                     const char * component,
                     qosspec_t    qs)
{
        irm_msg_t     msg    = IRM_MSG__INIT;
        qosspec_msg_t qs_msg = QOSSPEC_MSG__INIT;
        irm_msg_t *   recv_msg;
        int           ret;


        msg.code      = IRM_MSG_CODE__IRM_CONNECT_IPCP;
        msg.dst       = (char *) dst;
        msg.comp      = (char *) component;
        msg.has_pid   = true;
        msg.pid       = pid;
        qs_msg        = spec_to_msg(&qs);
        msg.qosspec   = &qs_msg;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EIRMD;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_disconnect_ipcp(pid_t        pid,
                        const char * dst,
                        const char * component)
{
        irm_msg_t   msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg;
        int         ret;

        msg.code    = IRM_MSG_CODE__IRM_DISCONNECT_IPCP;
        msg.dst     = (char *) dst;
        msg.comp    = (char *) component;
        msg.has_pid = true;
        msg.pid     = pid;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -EIRMD;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

ssize_t irm_list_ipcps(struct ipcp_info ** ipcps)
{
        irm_msg_t   msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg;
        size_t      nr;
        size_t      i;

        if (ipcps == NULL)
                return -EINVAL;

        *ipcps = NULL;

        msg.code     = IRM_MSG_CODE__IRM_LIST_IPCPS;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (recv_msg->ipcps == NULL) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return 0;
        }

        nr = recv_msg->n_ipcps;
        if (nr == 0) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return 0;
        }

        *ipcps = malloc(nr * sizeof(**ipcps));
        if (*ipcps == NULL) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -ENOMEM;
        }

        for (i = 0; i < nr; i++) {
                (*ipcps)[i].pid   = recv_msg->ipcps[i]->pid;
                (*ipcps)[i].type  = recv_msg->ipcps[i]->type;
                strcpy((*ipcps)[i].name, recv_msg->ipcps[i]->name);
                strcpy((*ipcps)[i].layer, recv_msg->ipcps[i]->layer);
        }

        irm_msg__free_unpacked(recv_msg, NULL);

        return nr;
}

int irm_enroll_ipcp(pid_t        pid,
                    const char * dst)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;

        if (pid == -1 || dst == NULL)
                return -EINVAL;

        msg.code         = IRM_MSG_CODE__IRM_ENROLL_IPCP;
        msg.has_pid      = true;
        msg.pid          = pid;
        msg.dst          = (char *) dst;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

static int check_prog(const char * prog)
{
        struct stat s;

        if (stat(prog, &s) != 0)
                return -ENOENT;

        if (!(s.st_mode & S_IXUSR))
                return -EPERM;

        return 0;
}

static int check_prog_path(char ** prog)
{
        char * path;
        char * path_end;
        char * pstart;
        char * pstop;
        char * tmp;
        char * tstop;
        char * tstart;
        bool   perm = true;
        int    ret = 0;

        assert(prog);

        if (*prog == NULL)
                return -EINVAL;

        path = getenv("PATH");
        if (path == NULL)
                return -ENOENT;

        pstop = path;
        path_end = path + strlen(path) + 1;
        if (!strlen(path) || strchr(*prog, '/') != NULL) {
                if ((ret = check_prog(*prog)) < 0)
                        return ret;
                return 0;
        }

        tmp = malloc(strlen(path) + strlen(*prog) + 2);
        if (tmp == NULL)
                return -ENOMEM;

        tstop = tmp + strlen(path) + 1;
        strcpy(tstop--, *prog);

        while (pstop < path_end) {
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

                if ((ret = check_prog(tstart)) < 0) {
                        if (ret == -EPERM)
                                perm = false;
                        continue;
                }

                free(*prog);
                *prog = strdup(tstart);
                free(tmp);

                if (*prog == NULL)
                        return -ENOMEM;

                return 0;
        }

        free(tmp);
        if (!perm)
                return -EPERM;

        return -ENOENT;
}

int irm_bind_program(const char * prog,
                     const char * name,
                     uint16_t     opts,
                     int          argc,
                     char **      argv)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;
        char *      full_name;

        if (prog == NULL || name == NULL)
                return -EINVAL;

        full_name = strdup(prog);
        if (full_name == NULL)
                return -ENOMEM;

        if ((ret = check_prog_path(&full_name)) < 0) {
                free(full_name);
                return ret;
        }

        msg.code = IRM_MSG_CODE__IRM_BIND_PROGRAM;
        msg.name = (char *) name;
        msg.prog = full_name;

        if (argv != NULL) {
                msg.n_args = argc;
                msg.args = (char **) argv;
        }

        msg.has_opts = true;
        msg.opts = opts;

        recv_msg = send_recv_irm_msg(&msg);

        free(full_name);

        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_bind_process(pid_t        pid,
                     const char * name)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_BIND_PROCESS;
        msg.has_pid = true;
        msg.pid     = pid;
        msg.name    = (char *) name;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_unbind_program(const char * prog,
                       const char * name)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code = IRM_MSG_CODE__IRM_UNBIND_PROGRAM;
        msg.prog = (char *) prog;
        msg.name = (char *) name;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_unbind_process(pid_t        pid,
                       const char * name)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_UNBIND_PROCESS;
        msg.has_pid = true;
        msg.pid     = pid;
        msg.name    = (char *) name;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_create_name(const char *     name,
                    enum pol_balance pol)
{
        irm_msg_t       msg      = IRM_MSG__INIT;
        name_info_msg_t ni_msg   = NAME_INFO_MSG__INIT;
        irm_msg_t *     recv_msg;
        int             ret;

        if (name == NULL)
                return -EINVAL;

        msg.code      = IRM_MSG_CODE__IRM_CREATE_NAME;
        ni_msg.name   = (char *) name;
        ni_msg.pol_lb = pol;
        msg.n_names   = 1;

        msg.names = malloc(sizeof(*msg.names));
        if (msg.names == NULL) {
                return -ENOMEM;
        }

        msg.names[0]  = &ni_msg;

        recv_msg = send_recv_irm_msg(&msg);

        free(msg.names);

        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_destroy_name(const char * name)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_DESTROY_NAME;
        msg.name    = (char *) name;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

ssize_t irm_list_names(struct name_info ** names)
{
        irm_msg_t   msg = IRM_MSG__INIT;
        irm_msg_t * recv_msg;
        size_t      nr;
        size_t      i;

        if (names == NULL)
                return -EINVAL;

        *names = NULL;

        msg.code = IRM_MSG_CODE__IRM_LIST_NAMES;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (recv_msg->names == NULL) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return 0;
        }

        nr = recv_msg->n_names;
        if (nr == 0) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return 0;
        }

        *names = malloc(nr * sizeof(**names));
        if (*names == NULL) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -ENOMEM;
        }

        for (i = 0; i < nr; i++) {
                (*names)[i].pol_lb = recv_msg->names[i]->pol_lb;
                /* Truncate names > NAME_SIZE */
                if (strlen(recv_msg->names[i]->name) >= NAME_SIZE)
                    recv_msg->names[i]->name[NAME_SIZE - 1] = 0;

                strcpy((*names)[i].name, recv_msg->names[i]->name);
        }

        irm_msg__free_unpacked(recv_msg, NULL);

        return nr;
}

int irm_reg_name(const char * name,
                 pid_t        pid)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_REG_NAME;
        msg.has_pid = true;
        msg.pid     = pid;
        msg.name    = (char *) name;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}

int irm_unreg_name(const char * name,
                   pid_t        pid)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_UNREG_NAME;
        msg.has_pid = true;
        msg.pid     = pid;
        msg.name    = (char *) name;

        recv_msg = send_recv_irm_msg(&msg);
        if (recv_msg == NULL)
                return -EIRMD;

        if (!recv_msg->has_result) {
                irm_msg__free_unpacked(recv_msg, NULL);
                return -1;
        }

        ret = recv_msg->result;
        irm_msg__free_unpacked(recv_msg, NULL);

        return ret;
}
