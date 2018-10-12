/*
 * Ouroboros - Copyright (C) 2016 - 2018
 *
 * The API to instruct the IRM
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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
        irm_msg_t         msg        = IRM_MSG__INIT;
        ipcp_config_msg_t config     = IPCP_CONFIG_MSG__INIT;
        layer_info_msg_t  layer_info = LAYER_INFO_MSG__INIT;
        irm_msg_t *       recv_msg   = NULL;
        int               ret        = -1;

        if (pid == -1 || conf == NULL)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP;
        msg.has_pid = true;
        msg.pid     = pid;

        config.layer_info     = &layer_info;
        msg.conf              = &config;
        layer_info.layer_name = (char *) conf->layer_info.layer_name;

        config.ipcp_type = conf->type;

        if (conf->type != IPCP_UDP)
                layer_info.dir_hash_algo  = conf->layer_info.dir_hash_algo;

        switch (conf->type) {
        case IPCP_NORMAL:
                config.has_addr_size      = true;
                config.addr_size          = conf->addr_size;
                config.has_eid_size       = true;
                config.eid_size           = conf->eid_size;
                config.has_max_ttl        = true;
                config.max_ttl            = conf->max_ttl;
                config.has_addr_auth_type = true;
                config.addr_auth_type     = conf->addr_auth_type;
                config.has_routing_type   = true;
                config.routing_type       = conf->routing_type;
                config.has_pff_type       = true;
                config.pff_type           = conf->pff_type;
                break;
        case IPCP_UDP:
                config.has_ip_addr  = true;
                config.ip_addr      = conf->ip_addr;
                config.has_dns_addr = true;
                config.dns_addr     = conf->dns_addr;
                break;
        case IPCP_LOCAL:
        case IPCP_RAPTOR:
                break;
        case IPCP_ETH_LLC:
                config.dev = conf->dev;
                break;
        case IPCP_ETH_DIX:
                config.dev = conf->dev;
                config.has_ethertype = true;
                config.ethertype = conf->ethertype;
                break;
        default:
                return -EIPCPTYPE;
        }

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
                     const char * component)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret;

        msg.code      = IRM_MSG_CODE__IRM_CONNECT_IPCP;
        msg.dst       = (char *) dst;
        msg.comp      = (char *) component;
        msg.has_pid   = true;
        msg.pid       = pid;

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
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
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
        irm_msg_t msg        = IRM_MSG__INIT;
        irm_msg_t * recv_msg;
        size_t nr;
        size_t i;

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

int irm_reg(pid_t        pid,
            const char * name)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_REG;
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


int irm_unreg(pid_t        pid,
              const char * name)
{
        irm_msg_t   msg      = IRM_MSG__INIT;
        irm_msg_t * recv_msg = NULL;
        int         ret      = -1;

        if (name == NULL)
                return -EINVAL;

        msg.code    = IRM_MSG_CODE__IRM_UNREG;
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
