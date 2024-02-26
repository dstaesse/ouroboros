/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager / Configuration from file
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


#include "config.h"

#if defined (HAVE_TOML)

#define _POSIX_C_SOURCE 200809L
#define _XOPEN_SOURCE   500

#define OUROBOROS_PREFIX "irmd/configuration"

#include <ouroboros/errno.h>
#include <ouroboros/ipcp.h>
#include <ouroboros/logs.h>
#include <ouroboros/utils.h>

#include "irmd.h"
#include "configfile.h"

#include "reg/reg.h"

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <toml.h>
#include <arpa/inet.h>

#define ERRBUFSZ 200

static int toml_hash(toml_table_t *      table,
                     struct layer_info * info)
{
        toml_datum_t hash;

        hash = toml_string_in(table, "hash");
        if (!hash.ok) {
                log_dbg("No hash specified, using default.");
                return 0;
        }

        if (strcmp(hash.u.s, "SHA3_224") == 0) {
                info->dir_hash_algo = DIR_HASH_SHA3_224;
        } else if (strcmp(hash.u.s, "SHA3_256") == 0) {
                info->dir_hash_algo = DIR_HASH_SHA3_256;
        } else if (strcmp(hash.u.s, "SHA3_384") == 0) {
                info->dir_hash_algo = DIR_HASH_SHA3_384;
        } else if (strcmp(hash.u.s, "SHA3_512") == 0) {
                info->dir_hash_algo = DIR_HASH_SHA3_512;
        } else {
                log_err("Unknown hash algorithm: %s.", hash.u.s);
                free(hash.u.s);
                return -1;
        }

        free(hash.u.s);

        return 0;
}

static int toml_local(toml_table_t *       table,
                      struct ipcp_config * conf)
{
        *conf = local_default_conf;

        return toml_hash(table, &conf->layer_info);
}

static int toml_eth_dev(toml_table_t *      table,
                        struct eth_config * conf)
{
        toml_datum_t dev;

        dev = toml_string_in(table, "dev");
        if (!dev.ok) {
                log_err("Missing device.");
                return -1;
        }

        if (strlen(dev.u.s) > DEV_NAME_SIZE) {
                log_err("Device name too long: %s", dev.u.s);
                free(dev.u.s);
                return -1;
        }

        strcpy(conf->dev, dev.u.s);
        free(dev.u.s);

        return 0;
}

static int toml_eth_llc(toml_table_t *       table,
                        struct ipcp_config * conf)
{
        *conf = eth_llc_default_conf;

        if (toml_hash(table, &conf->layer_info) < 0)
                return -1;

        return toml_eth_dev(table, &conf->eth);
}


static int toml_ethertype(toml_table_t *      table,
                          struct eth_config * conf)
{
        toml_datum_t ethertype;

        ethertype = toml_int_in(table, "ethertype");
        if (ethertype.ok)
                conf->ethertype = ethertype.u.i;

        if (conf->ethertype < 0x0600 || conf->ethertype == 0xFFFF)
                return -1;

        return 0;
}

static int toml_eth_dix(toml_table_t *       table,
                        struct ipcp_config * conf)
{
        *conf = eth_dix_default_conf;

        if (toml_hash(table, &conf->layer_info) < 0)
                return -1;

        if (toml_eth_dev(table, &conf->eth) < 0)
                return -1;

        if (toml_ethertype(table, &conf->eth) < 0) {
                log_err("Ethertype not in valid range.");
                return -1;
        }

        return 0;
}

static int toml_udp(toml_table_t *       table,
                    struct ipcp_config * conf)
{
        toml_datum_t ip;
        toml_datum_t port;
        toml_datum_t dns;

        *conf = udp_default_conf;

        ip = toml_string_in(table, "ip");
        if (!ip.ok) {
                log_err("No IP address specified!");
                goto fail_ip;
        }

        if (inet_pton (AF_INET, ip.u.s, &conf->udp.ip_addr) != 1) {
                log_err("Failed to parse IPv4 address %s.", ip.u.s);
                goto fail_addr;
        }

        port = toml_int_in(table, "port");
        if (port.ok)
                conf->udp.port = port.u.i;

        dns = toml_string_in(table, "dns");
        if (dns.ok) {
                if (inet_pton(AF_INET, dns.u.s, &conf->udp.dns_addr) < 0) {
                        log_err("Failed to parse DNS address %s.", ip.u.s);
                        goto fail_dns;
                }

                free(dns.u.s);
        }

        free(ip.u.s);

        return 0;

 fail_dns:
        free(dns.u.s);
 fail_addr:
        free(ip.u.s);
 fail_ip:
        return -1;
}

static int toml_broadcast(toml_table_t *       table,
                          struct ipcp_config * conf)
{
        (void) table;
        (void) conf;

        /* Nothing to do here. */

        return 0;
}

static int toml_routing(toml_table_t *     table,
                        struct dt_config * conf)
{
        toml_datum_t routing;

        routing = toml_string_in(table, "routing");
        if (routing.ok) {
                if (strcmp(routing.u.s, "link-state") == 0)
                        conf->routing_type = ROUTING_LINK_STATE;
                else if (strcmp(routing.u.s, "lfa") == 0)
                        conf->routing_type = ROUTING_LINK_STATE_LFA;
                else if (strcmp(routing.u.s, "ecmp") == 0)
                        conf->routing_type = ROUTING_LINK_STATE_ECMP;
                else
                        conf->routing_type = ROUTING_INVALID;
                free(routing.u.s);
        }

        if (conf->routing_type == ROUTING_INVALID)
                return -1;

        return 0;
}

static int toml_addr_auth(toml_table_t *      table,
                          struct uni_config * conf)
{
        toml_datum_t addr_auth;

        addr_auth = toml_string_in(table, "addr-auth");
        if (addr_auth.ok) {
                if (strcmp(addr_auth.u.s, "flat") == 0)
                        conf->addr_auth_type = ADDR_AUTH_FLAT_RANDOM;
                else
                        conf->addr_auth_type = ADDR_AUTH_INVALID;
                free(addr_auth.u.s);
        }

        if (conf->addr_auth_type == ADDR_AUTH_INVALID)
                return -1;

        return 0;
}

static int toml_congestion(toml_table_t *      table,
                           struct uni_config * conf)
{
        toml_datum_t congestion;

        congestion = toml_string_in(table, "congestion");
        if (congestion.ok) {
                if (strcmp(congestion.u.s, "none") == 0)
                        conf->cong_avoid = CA_NONE;
                else if (strcmp(congestion.u.s, "lfa") == 0)
                        conf->cong_avoid = CA_MB_ECN;
                else
                        conf->cong_avoid = CA_INVALID;
                free(congestion.u.s);

        }

        if (conf->cong_avoid == CA_INVALID)
                return -1;

        return 0;
}

static int toml_dt(toml_table_t *     table,
                   struct dt_config * conf)
{
        toml_datum_t addr;
        toml_datum_t eid;
        toml_datum_t ttl;

        addr = toml_int_in(table, "addr_size");
        if (addr.ok)
                conf->addr_size = addr.u.i;

        eid = toml_int_in(table, "eid_size");
        if (eid.ok)
                conf->eid_size = eid.u.i;

        ttl = toml_int_in(table, "max_ttl");
        if (ttl.ok)
                conf->max_ttl = ttl.u.i;

        if (toml_routing(table, conf) < 0) {
                log_err("Invalid routing option.");
                return -1;
        }

        return 0;
}

static int toml_unicast(toml_table_t *       table,
                        struct ipcp_config * conf)
{


        *conf = uni_default_conf;

        if (toml_hash(table, &conf->layer_info) < 0)
                return -1;

        if (toml_dt(table, &conf->unicast.dt) < 0) {
                log_err("Invalid DT configuration.");
                return -1;
        }

        if (toml_addr_auth(table, &conf->unicast) < 0) {
                log_err("Invalid address authority");
                return -1;
        }

        if (toml_congestion(table, &conf->unicast) < 0) {
                log_err("Invalid congestion avoidance algorithm.");
                return -1;
        }

        return 0;
}

static int toml_autobind(toml_table_t * table,
                         pid_t          pid,
                         const char *   name,
                         const char *   layer)
{
        toml_datum_t autobind;

        autobind = toml_bool_in(table, "autobind");
        if (!autobind.ok)
                return 0;

        if (bind_process(pid, name) < 0) {
                log_err("Failed to bind IPCP process %d to %s.", pid, name);
                return -1;
        }

        if (layer != NULL && bind_process(pid, layer) < 0) {
                log_err("Failed to bind IPCP process %d to %s.", pid, layer);
                return -1;
        }

        return 0;
}

static int toml_register(toml_table_t * table,
                         pid_t          pid)
{
        toml_array_t *   reg;
        int              i;
        int              ret = 0;
        struct name_info info = {
                .pol_lb = LB_SPILL
        };

        reg = toml_array_in(table, "reg");
        if (reg == NULL)
                return 0;

        for (i = 0; ret == 0; i++) {
                toml_datum_t name;

                name = toml_string_at(reg, i);
                if (!name.ok)
                        break;

                log_dbg("Registering %s in %d", name.u.s, pid);

                strcpy(info.name, name.u.s);

                ret = name_create(&info);
                if (ret < 0 && ret != -ENAME) {
                        free(name.u.s);
                        break;
                }

                ret = name_reg(name.u.s, pid);
                free(name.u.s);
        }

        return ret;
}

static int toml_connect(toml_table_t * table,
                        pid_t          pid)
{
        toml_array_t * conn;
        int            i;
        int            ret = 0;

        conn = toml_array_in(table, "conn");
        if (conn == NULL)
                return 0;

        for (i=0; ret == 0; i++) {
                toml_datum_t dst;
                qosspec_t    qs = qos_raw;

                dst = toml_string_at(conn, i);
                if (!dst.ok)
                        break;

                log_dbg("Connecting %d to %s", pid, dst.u.s);

                ret = connect_ipcp(pid, dst.u.s, MGMT_COMP, qs);
                if (ret == 0)
                        ret = connect_ipcp(pid, dst.u.s, DT_COMP, qs);

                free(dst.u.s);
        }

        return ret;
}

static int toml_ipcp(toml_table_t *       table,
                     struct ipcp_info *   info,
                     struct ipcp_config * conf)
{
        toml_datum_t bootstrap;
        toml_datum_t enrol;
        int          ret;

        log_dbg("Found IPCP %s in configuration file.", info->name);

        if (create_ipcp(info) < 0) {
                log_err("Failed to create IPCP %s.", info->name);
                return -1;
        }

        bootstrap = toml_string_in(table, "bootstrap");
        enrol     = toml_string_in(table, "enrol");

        if (bootstrap.ok && enrol.ok) {
                log_err("Ignoring bootstrap for IPCP %s.", info->name);
                free(bootstrap.u.s);
                bootstrap.ok = false;
        }

        if (!bootstrap.ok && !enrol.ok) {
                log_dbg("Nothing more to do for %s.", info->name);
                return 0;
        }

        if (enrol.ok) {
                struct layer_info layer;
                ret = enroll_ipcp(info->pid, enrol.u.s);
                free(enrol.u.s);
                if (ret < 0) {
                        log_err("Failed to enrol %s.", info->name);
                        return -1;
                }

                if (reg_get_ipcp(info, &layer) < 0)
                        return -1;

                if (toml_autobind(table, info->pid, info->name, layer.name))
                        return -1;

                if (toml_register(table, info->pid) < 0) {
                        log_err("Failed to register names.");
                        return -1;
                }

                if (toml_connect(table, info->pid) < 0) {
                        log_err("Failed to register names.");
                        return -1;
                }

                return 0;
        }

        assert(bootstrap.ok);

        if (strlen(bootstrap.u.s) > LAYER_NAME_SIZE) {
                log_err("Layer name too long: %s", bootstrap.u.s);
                free(bootstrap.u.s);
                return -1;
        }

        switch (conf->type) {
        case IPCP_LOCAL:
                ret = toml_local(table, conf);
                break;
        case IPCP_ETH_DIX:
                ret = toml_eth_dix(table, conf);
                break;
        case IPCP_ETH_LLC:
                ret = toml_eth_llc(table, conf);
                break;
        case IPCP_UDP:
                ret = toml_udp(table, conf);
                break;
        case IPCP_BROADCAST:
                ret = toml_broadcast(table, conf);
                break;
        case IPCP_UNICAST:
                ret = toml_unicast(table, conf);
                break;
        default:
                log_err("Invalid IPCP type");
                ret = -1;
        }

        if (ret < 0)
                return -1;

        strcpy(conf->layer_info.name, bootstrap.u.s);
        free(bootstrap.u.s);

        if (bootstrap_ipcp(info->pid, conf) < 0)
                return -1;

        if (toml_autobind(table, info->pid, info->name,
                          conf->layer_info.name) < 0)
                return -1;

        if (toml_register(table, info->pid) < 0) {
                log_err("Failed to register names.");
                return -1;
        }

        return 0;
}

static int toml_ipcp_list(toml_table_t * table,
                          enum ipcp_type type)
{
        int  i   = 0;
        int  ret = 0;

        for (i = 0; ret == 0; i++) {
                const char *       key;
                struct ipcp_info   info;
                struct ipcp_config conf;

                memset(&conf, 0, sizeof(conf));
                memset(&info, 0, sizeof(info));

                key = toml_key_in(table, i);
                if (key == NULL)
                        break;

                if (strlen(key) > IPCP_NAME_SIZE) {
                        log_err("IPCP name too long: %s,", key);
                        return -1;
                }

                info.type = type;
                strcpy(info.name,key);
                conf.type = type;

                ret = toml_ipcp(toml_table_in(table, key), &info, &conf);
        }

        return ret;
}

static int args_to_argv(const char * prog,
                        const char * args,
                        char ***     argv)
{
        char * tok;
        char * str;
        int    argc = 0;

        str = (char *) args;

        if (str != NULL) {
                tok = str;
                while (*(tok += strspn(tok, " ")) != '\0') {
                        tok  += strcspn(tok, " ");
                        argc++;
                }
        }

        *argv = malloc((argc + 2) * sizeof(**argv));
        if (*argv == NULL)
                goto fail_malloc;

        (*argv)[0] = strdup(prog);
        if ((*argv)[0] == NULL)
                goto fail_malloc2;

        argc = 1;

        if (str == NULL)
                goto finish;

        tok = str;
        while (*(tok += strspn(tok, " ")) != '\0') {
                size_t toklen = strcspn(tok, " ");
                (*argv)[argc] = malloc((toklen + 1) * sizeof(***argv));
                if ((*argv)[argc] == NULL)
                        goto fail_malloc2;

                strncpy((*argv)[argc], tok, toklen);
                (*argv)[argc++][toklen] = '\0';
                tok += toklen;
        }

 finish:
        (*argv)[argc] = NULL;

        return argc;

 fail_malloc2:
        argvfree(*argv);
 fail_malloc:
        return -1;

}

static int toml_prog(const char * prog,
                     const char * args,
                     const char * name)
{
        uint16_t flags = 0;
        int      argc;
        char **  exec;
        int      ret;

        if (args != NULL)
                flags |= BIND_AUTO;

        argc = args_to_argv(prog, args, &exec);
        if (argc < 0) {
                log_err("Failed to parse arguments: %s", args);
                return -1;
        }

        ret = bind_program(exec, name, flags);
        if (ret < 0)
                log_err("Failed to bind program %s %s for name %s.",
                        prog, args, name);

        argvfree(exec);

        return ret;
}

static int toml_prog_list(toml_array_t * progs,
                          toml_array_t * args,
                          const char *   name)
{
        int ret = 0;
        int i;

        for (i = 0; ret == 0; i++) {
                toml_datum_t prog;
                toml_datum_t arg;

                prog = toml_string_at(progs, i);
                if (!prog.ok)
                        break;

                if (args == NULL) {
                        ret = toml_prog(prog.u.s, NULL, name);
                } else {
                        arg = toml_string_at(args, i);
                        if (!arg.ok) {
                                args = NULL; /* no more arguments in list. */
                                assert(arg.u.s == NULL);
                        }

                        ret = toml_prog(prog.u.s, arg.u.s, name);

                        if (arg.ok)
                                free(arg.u.s);
                }

                free(prog.u.s);
        }

        return ret;
}

static int toml_name(toml_table_t * table,
                     const char *   name)
{
        toml_array_t *   progs;
        toml_array_t *   args;
        toml_datum_t     lb;
        struct name_info info = {
                .pol_lb = LB_SPILL
        };

        log_dbg("Found service name %s in configuration file.", name);

        lb = toml_string_in(table, "lb");
        if (lb.ok) {
                if (strcmp(lb.u.s, "spill") == 0)
                        info.pol_lb = LB_SPILL;
                else if (strcmp(lb.u.s, "round-robin") == 0)
                        info.pol_lb = LB_RR;
                else
                        info.pol_lb = LB_INVALID;
                free(lb.u.s);
        }

        if (info.pol_lb == LB_INVALID) {
                log_err("Invalid load-balancing policy for %s.", name);
                return -1;
        }

        strcpy(info.name, name);

        if (name_create(&info) < 0) {
                log_err("Failed to create name %s.", name);
                return -1;
        }

        progs = toml_array_in(table, "prog");
        if (progs == NULL)
                return 0;

        args = toml_array_in(table, "args");
        if (toml_prog_list(progs, args, name) < 0)
                return -1;

        return 0;
}

static int toml_name_list(toml_table_t * table)
{
        int  i   = 0;
        int  ret = 0;

        for (i = 0; ret == 0; i++) {
                const char * key;

                key = toml_key_in(table, i);
                if (key == NULL)
                        break;

                ret = toml_name(toml_table_in(table, key), key);
        }

        return ret;
        return 0;
}

static int toml_toplevel(toml_table_t * table,
                         const char *   key)
{
        toml_table_t * subtable;

        subtable = toml_table_in(table, key);

        if (strcmp(key, "local") == 0)
                return toml_ipcp_list(subtable, IPCP_LOCAL);
        else if (strcmp(key, "eth-dix") == 0)
                return toml_ipcp_list(subtable, IPCP_ETH_DIX);
        else if (strcmp(key, "eth-llc") == 0)
                return toml_ipcp_list(subtable, IPCP_ETH_LLC);
        else if (strcmp(key, "udp") == 0)
                return toml_ipcp_list(subtable, IPCP_UDP);
        else if (strcmp(key, "broadcast") == 0)
                return toml_ipcp_list(subtable, IPCP_BROADCAST);
        else if (strcmp(key, "unicast") == 0)
                return toml_ipcp_list(subtable, IPCP_UNICAST);
        else if (strcmp(key, "name") == 0)
                return toml_name_list(subtable);

        log_err("Unkown toplevel key: %s.", key);
        return -1;
}

static int toml_load(toml_table_t * table)
{
        int  i   = 0;
        int  ret = 0;

        for (i = 0; ret == 0; i++) {
                const char *   key;

                key = toml_key_in(table, i);
                if (key == NULL)
                        break;

                ret = toml_toplevel(table, key);
        }

        return ret;
}

static int toml_cfg(FILE * fp)
{
        toml_table_t * table;
        char           errbuf[ERRBUFSZ + 1];

        assert(fp != NULL);

        table = toml_parse_file(fp, errbuf, sizeof(errbuf));
        if (table == NULL) {
                log_err("Failed to parse config file: %s.", errbuf);
                goto fail_parse;
        }

        if (toml_load(table) < 0) {
                log_err("Failed to load configuration.");
                goto fail_load;
        }

        toml_free(table);

        return 0;

 fail_load:
       toml_free(table);
 fail_parse:
        return -1;
}

int irm_configure(const char * path)
{
        FILE * fp;
        char * rp;

        if (path == NULL)
                return 0;

        rp = realpath(path, NULL);
        if (rp == NULL) {
                log_err("Failed to resolve path for %s", path);
                goto fail_resolve;
        }

        log_info("Reading configuration from file %s", rp);

        fp = fopen(rp, "r");
        if (fp == NULL) {
                log_err("Failed to open config file: %s\n", strerror(errno));
                goto fail_fopen;
        }

        if (toml_cfg(fp) < 0) {
                log_err("Failed to load config file.");
                goto fail_cfg;
        }

        fclose(fp);
        free(rp);

        return 0;

 fail_cfg:
        fclose(fp);
 fail_fopen:
        free(rp);
 fail_resolve:
        return -1;
}

#endif /* HAVE_TOML */
