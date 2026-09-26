/*
 * Ouroboros - Copyright (C) 2016 - 2026
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tomlc17.h>
#include <arpa/inet.h>
#ifdef __FreeBSD__
#include <sys/socket.h>
#endif

#define DATUMSZ 256

static int toml_hash(toml_datum_t        table,
                     struct layer_info * info)
{
        toml_datum_t hash;

        hash = toml_get(table, "hash");
        if (hash.type != TOML_STRING) {
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
                return -1;
        }

        return 0;
}

static int toml_local(toml_datum_t         table,
                      struct ipcp_config * conf)
{
        *conf = local_default_conf;

        return toml_hash(table, &conf->layer_info);
}


/* Defined with the peer helpers below; shared grammar for both paths. */
static int toml_udp_str(const char * str,
                        char *       host,
                        int *        port);

/* Attach the PoAs an IPCP is given; one call per PoA. */
static int poa_eth_set(struct poa_spec * poa,
                       const char *      dev,
                       uint16_t          ethertype)
{
        if (strlen(dev) > DEV_NAME_SIZE) {
                log_err("Invalid device name %s.", dev);
                return -1;
        }

        memset(poa, 0, sizeof(*poa));

        poa->type          = POA_ETH;
        poa->eth.ethertype = ethertype;

        strcpy(poa->eth.dev, dev);

        return 0;
}

static int toml_poa_eth(toml_datum_t      tbl,
                        struct poa_spec * poa)
{
        toml_datum_t dev;
        toml_datum_t et;
        uint16_t     ethertype = POA_ETHERTYPE;

        dev = toml_get(tbl, "dev");
        if (dev.type != TOML_STRING) {
                log_err("An eth PoA needs a device.");
                return -1;
        }

        et = toml_get(tbl, "ethertype");
        if (et.type == TOML_INT64) {
                if (et.u.int64 < 0 || et.u.int64 > 0xFFFF) {
                        log_err("Invalid ethertype.");
                        return -1;
                }

                ethertype = et.u.int64;
        }

        return poa_eth_set(poa, dev.u.s, ethertype);
}

/* A PoA is bound locally: only literal addresses are accepted here. */
static int toml_poa_udp(const char *      str,
                        struct poa_spec * poa)
{
        char host[POA_HOST_STRLEN + 1];
        int  port;

        if (toml_udp_str(str, host, &port) < 0)
                return -1;

        memset(poa, 0, sizeof(*poa));

        if (inet_pton(AF_INET, host, &poa->udp4.ip_addr.s_addr) == 1) {
                poa->type      = POA_UDP4;
                poa->udp4.port = port;
                return 0;
        }

        if (inet_pton(AF_INET6, host, &poa->udp6.ip_addr) == 1) {
                poa->type      = POA_UDP6;
                poa->udp6.port = port;
                return 0;
        }

        log_err("Invalid IP address %s.", host);

        return -1;
}

/* Attaches every PoA in the "udp" or "eth" array; string or table. */
static int toml_poa_array(toml_datum_t table,
                          pid_t        pid,
                          const char * key)
{
        struct poa_spec poa;
        toml_datum_t    arr;
        int             i;
        bool            is_eth;

        arr = toml_get(table, key);
        if (arr.type != TOML_ARRAY) {
                /* A table here would otherwise attach nothing, silently. */
                if (arr.type == TOML_TABLE) {
                        log_err("A %s PoA is an array: %s = [...] "
                                "or [[%s]].", key, key, key);
                        return -1;
                }

                return 0;
        }

        is_eth = strcmp(key, "eth") == 0;

        for (i = 0; i < arr.u.arr.size; i++) {
                toml_datum_t d = arr.u.arr.elem[i];
                toml_datum_t addr;
                int          ret;

                if (d.type == TOML_STRING) {
                        if (is_eth)
                                ret = poa_eth_set(&poa, d.u.s, POA_ETHERTYPE);
                        else
                                ret = toml_poa_udp(d.u.s, &poa);
                } else if (d.type != TOML_TABLE) {
                        log_err("Invalid %s PoA entry.", key);
                        return -1;
                } else if (is_eth) {
                        ret = toml_poa_eth(d, &poa);
                } else {
                        addr = toml_get(d, "addr");
                        if (addr.type != TOML_STRING) {
                                log_err("No addr for udp PoA.");
                                return -1;
                        }

                        ret = toml_poa_udp(addr.u.s, &poa);
                }

                if (ret < 0)
                        return -1;

                if (attach_ipcp(pid, &poa, true) < 0)
                        return -1;
        }

        return 0;
}

static int toml_attach(toml_datum_t table,
                       pid_t        pid)
{
        if (toml_poa_array(table, pid, "udp") < 0)
                return -1;

        return toml_poa_array(table, pid, "eth");
}

static int toml_broadcast(toml_datum_t         table,
                          struct ipcp_config * conf)
{
        (void) table;

        *conf = bc_default_conf;

        return 0;
}

#define BETWEEN(a, b, c) ((a) >= (b) && (a) <= (c))
#define DHT(conf, x) (conf)->dht.params.x
static int toml_dir(toml_datum_t        table,
                    struct dir_config * conf)
{
        toml_datum_t dir;
        toml_datum_t alpha;
        toml_datum_t t_expire;
        toml_datum_t t_refresh;
        toml_datum_t t_replicate;
        toml_datum_t k;

        dir = toml_get(table, "directory");
        if (dir.type == TOML_STRING) {
                log_dbg("Found directory type: %s", dir.u.s);

                if (strlen(dir.u.s) > DATUMSZ) {
                        log_err("Directory name too long: %s", dir.u.s);
                        return -1;
                }

                if (strcmp(dir.u.s, "DHT") == 0)
                        conf->pol = DIR_DHT;
                else if (strcmp(dir.u.s, "dht") == 0)
                        conf->pol = DIR_DHT;
                else {
                        log_err("Unknown directory type: %s", dir.u.s);
                        return -EINVAL;
                }
        }

        switch(conf->pol) {
        case DIR_DHT:
                log_info("Using DHT directory policy.");

                alpha = toml_get(table, "dht_alpha");
                if (alpha.type == TOML_INT64) {
                        if (!BETWEEN(alpha.u.int64,
                                DHT_ALPHA_MIN, DHT_ALPHA_MAX)) {
                                log_err("Invalid alpha value: %ld",
                                        (long) alpha.u.int64);
                                return -EINVAL;
                        }
                        DHT(conf, alpha) = alpha.u.int64;
                }

                t_expire = toml_get(table, "dht_t_expire");
                if (t_expire.type == TOML_INT64) {
                        if (!BETWEEN(t_expire.u.int64,
                                DHT_T_EXPIRE_MIN, DHT_T_EXPIRE_MAX)) {
                                log_err("Invalid expire time: %ld",
                                        (long) t_expire.u.int64);
                                return -EINVAL;
                        }
                        DHT(conf, t_expire) = t_expire.u.int64;
                }

                t_refresh = toml_get(table, "dht_t_refresh");
                if (t_refresh.type == TOML_INT64) {
                        if (!BETWEEN(t_refresh.u.int64,
                                DHT_T_REFRESH_MIN, DHT_T_REFRESH_MAX)) {
                                log_err("Invalid refresh time: %ld",
                                        (long) t_refresh.u.int64);
                                return -EINVAL;
                        }
                        DHT(conf, t_refresh) = t_refresh.u.int64;
                }

                t_replicate = toml_get(table, "dht_t_replicate");
                if (t_replicate.type == TOML_INT64) {
                        if (!BETWEEN(t_replicate.u.int64,
                                DHT_T_REPLICATE_MIN, DHT_T_REPLICATE_MAX)) {
                                log_err("Invalid replication time: %ld",
                                        (long) t_replicate.u.int64);
                                return -EINVAL;
                        }
                        DHT(conf, t_replicate) = t_replicate.u.int64;
                }

                k = toml_get(table, "dht_k");
                if (k.type == TOML_INT64) {
                        if (!BETWEEN(k.u.int64, DHT_K_MIN, DHT_K_MAX)) {
                                log_err("Invalid replication factor: %ld",
                                        (long) k.u.int64);
                                return -EINVAL;
                        }
                        DHT(conf, k) = k.u.int64;
                }
                break;
        default:
                assert(false);
                break;
        }

        return 0;
}

static int toml_routing(toml_datum_t       table,
                        struct dt_config * conf)
{
        toml_datum_t routing;
        toml_datum_t t_recalc;
        toml_datum_t t_update;
        toml_datum_t t_timeo;

        routing = toml_get(table, "routing");
        if (routing.type == TOML_STRING) {
                if (strcmp(routing.u.s, "link-state") == 0) {
                        conf->routing.pol = ROUTING_LINK_STATE;
                        conf->routing.ls.pol = LS_SIMPLE;
                } else if (strcmp(routing.u.s, "lfa") == 0) {
                        conf->routing.pol = ROUTING_LINK_STATE;
                        conf->routing.ls.pol = LS_LFA;
                } else if (strcmp(routing.u.s, "ecmp") == 0) {
                        conf->routing.pol = ROUTING_LINK_STATE;
                        conf->routing.ls.pol = LS_ECMP;
                } else {
                        conf->routing.pol = ROUTING_INVALID;
                        return -EINVAL;
                }
        }

        switch (conf->routing.pol) {
        case ROUTING_LINK_STATE:
                log_info("Using Link State routing policy.");

                t_recalc = toml_get(table, "ls_t_recalc");
                if (t_recalc.type == TOML_INT64) {
                        if (t_recalc.u.int64 < 1) {
                                log_err("Invalid ls_t_recalc value: %ld",
                                        (long) t_recalc.u.int64);
                                return -EINVAL;
                        }
                        conf->routing.ls.t_recalc = t_recalc.u.int64;
                }

                t_update = toml_get(table, "ls_t_update");
                if (t_update.type == TOML_INT64) {
                        if (t_update.u.int64 < 1) {
                                log_err("Invalid ls_t_update value: %ld",
                                        (long) t_update.u.int64);
                                return -EINVAL;
                        }
                        conf->routing.ls.t_update = t_update.u.int64;
                }

                t_timeo = toml_get(table, "ls_t_timeo");
                if (t_timeo.type == TOML_INT64) {
                        if (t_timeo.u.int64 < 1) {
                                log_err("Invalid ls_t_timeo value: %ld",
                                        (long) t_timeo.u.int64);
                                return -EINVAL;
                        }
                        conf->routing.ls.t_timeo = t_timeo.u.int64;
                }
                break;
        default:
                log_err("Invalid routing policy: %d", conf->routing.pol);
                return -EINVAL;
        }

        return 0;
}

static int toml_addr_auth(toml_datum_t        table,
                          struct uni_config * conf)
{
        toml_datum_t addr_auth;

        addr_auth = toml_get(table, "addr-auth");
        if (addr_auth.type == TOML_STRING) {
                if (strcmp(addr_auth.u.s, "flat") == 0)
                        conf->addr_auth_type = ADDR_AUTH_FLAT_RANDOM;
                else
                        conf->addr_auth_type = ADDR_AUTH_INVALID;
        }

        if (conf->addr_auth_type == ADDR_AUTH_INVALID)
                return -1;

        return 0;
}

static int toml_congestion(toml_datum_t        table,
                           struct uni_config * conf)
{
        toml_datum_t congestion;

        congestion = toml_get(table, "congestion");
        if (congestion.type == TOML_STRING) {
                if (strcmp(congestion.u.s, "none") == 0)
                        conf->cong_avoid = CA_NONE;
                else if (strcmp(congestion.u.s, "mb-ecn") == 0)
                        conf->cong_avoid = CA_MB_ECN;
                else
                        conf->cong_avoid = CA_INVALID;
        }

        if (conf->cong_avoid == CA_INVALID)
                return -1;

        return 0;
}

static int toml_dt(toml_datum_t       table,
                   struct dt_config * conf)
{
        toml_datum_t addr;
        toml_datum_t eid;
        toml_datum_t ttl;
        toml_datum_t max_rtt;

        addr = toml_get(table, "addr_size");
        if (addr.type == TOML_INT64)
                conf->addr_size = addr.u.int64;

        eid = toml_get(table, "eid_size");
        if (eid.type == TOML_INT64)
                conf->eid_size = eid.u.int64;

        ttl = toml_get(table, "max_ttl");
        if (ttl.type == TOML_INT64)
                conf->max_ttl = ttl.u.int64;

        max_rtt = toml_get(table, "max_rtt");
        if (max_rtt.type == TOML_INT64)
                conf->max_rtt = max_rtt.u.int64;

        if (toml_routing(table, conf) < 0) {
                log_err("Invalid routing option.");
                return -1;
        }

        return 0;
}

static int toml_unicast(toml_datum_t         table,
                        struct ipcp_config * conf)
{
        *conf = uni_default_conf;
        if (toml_hash(table, &conf->layer_info) < 0)
                return -1;

        if (toml_dir(table, &conf->unicast.dir) < 0) {
                log_err("Invalid directory configuration.");
                return -1;
        }

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

static int toml_autobind(toml_datum_t table,
                         pid_t        pid,
                         const char * name,
                         const char * layer)
{
        toml_datum_t autobind;

        autobind = toml_get(table, "autobind");
        if (autobind.type != TOML_BOOLEAN || !autobind.u.boolean)
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

static int toml_register(toml_datum_t table,
                         pid_t        pid)
{
        toml_datum_t reg;
        toml_datum_t name;
        int          i;
        int          ret = 0;
        struct name_info info = {
                .pol_lb = LB_SPILL
        };

        reg = toml_get(table, "reg");
        if (reg.type != TOML_ARRAY)
                return 0;

        for (i = 0; ret == 0 && i < reg.u.arr.size; i++) {
                name = reg.u.arr.elem[i];
                if (name.type != TOML_STRING)
                        break;

                log_dbg("Registering %s in %d", name.u.s, pid);

                strcpy(info.name, name.u.s);

                ret = name_create(&info);
                if (ret < 0 && ret != -ENAME)
                        break;

                ret = name_reg(name.u.s, pid);
        }

        return ret;
}

/* Fills in a peer's eth PoA; dst MAC stays zero, the resolve marker. */
static int toml_peer_eth(toml_datum_t      tbl,
                         struct poa_addr * addr)
{
        toml_datum_t dev;
        toml_datum_t et;

        dev = toml_get(tbl, "dev");

        memset(addr, 0, sizeof(*addr));

        addr->type = POA_ETH;
        addr->eth.src.ethertype = POA_ETHERTYPE;
        addr->eth.dst.ethertype = POA_ETHERTYPE;

        et = toml_get(tbl, "ethertype");
        if (et.type == TOML_INT64) {
                if (et.u.int64 < 0 || et.u.int64 > 0xFFFF) {
                        log_err("Invalid ethertype.");
                        return -1;
                }

                addr->eth.src.ethertype = et.u.int64;
                addr->eth.dst.ethertype = et.u.int64;
        }

        if (dev.type == TOML_STRING) {
                if (strlen(dev.u.s) > DEV_NAME_SIZE) {
                        log_err("Invalid device name %s.", dev.u.s);
                        return -1;
                }

                strcpy(addr->eth.src.dev, dev.u.s);
        }

        return 0;
}

/* Same grammar as the CLI's udp keyword; see irm_utils.c parse_udp_str. */
static int toml_udp_str(const char * str,
                        char *       host,
                        int *        port)
{
        struct in6_addr v6;
        char            buf[POA_HOST_STRLEN + 1];
        char *          p;
        char *          end;
        long            n;

        *port = POA_UDP_PORT;

        if (strlen(str) > POA_HOST_STRLEN)
                goto fail;

        strcpy(buf, str);

        if (buf[0] == '[') {
                p = strchr(buf, ']');
                if (p == NULL)
                        goto fail;

                *p++ = '\0';

                strcpy(host, buf + 1);

                if (*p == '\0')
                        return 0;

                if (*p != ':')
                        goto fail;

                ++p;
        } else if (inet_pton(AF_INET6, buf, &v6) == 1) {
                strcpy(host, buf);
                return 0;
        } else {
                p = strrchr(buf, ':');
                if (p == NULL) {
                        strcpy(host, buf);
                        return 0;
                }

                *p++ = '\0';

                strcpy(host, buf);
        }

        n = strtol(p, &end, 10);
        if (*p == '\0' || *end != '\0' || n < 1 || n > 65535)
                goto fail;

        *port = (int) n;

        return 0;
 fail:
        log_err("Invalid UDP address: %s.", str);
        return -1;
}

/* Fills in a peer's udp PoA; an unresolved name is left for the IRMd. */
static int toml_peer_udp(const char *      str,
                         struct poa_addr * addr)
{
        char host[POA_HOST_STRLEN + 1];
        int  port;

        if (toml_udp_str(str, host, &port) < 0)
                return -1;

        memset(addr, 0, sizeof(*addr));

        if (inet_pton(AF_INET, host, &addr->udp4.ip_addr) == 1) {
                addr->type      = POA_UDP4;
                addr->udp4.port = port;
                return 0;
        }

        if (inet_pton(AF_INET6, host, &addr->udp6.ip_addr) == 1) {
                addr->type      = POA_UDP6;
                addr->udp6.port = port;
                return 0;
        }

        addr->type      = POA_UDP;
        addr->udp4.port = port;

        strcpy(addr->hostname, host);

        return 0;
}

/*
 * An entry is a name, or a table naming a PoA to reach it over.
 * On entry, *paddr already points at the caller's struct poa_addr to
 * fill in. Set to NULL wherever there is no PoA to dial: a bare
 * dst-only table (recursive lookup) or any parse failure.
 */
static int toml_peer(toml_datum_t       tbl,
                     char *             dst,
                     struct poa_addr ** paddr)
{
        struct poa_addr * addr = *paddr;
        toml_datum_t      name;
        toml_datum_t      eth;
        toml_datum_t      udp;
        int               ret;

        name = toml_get(tbl, "dst");
        if (name.type != TOML_STRING) {
                log_err("PoA table entry has no dst.");

                *paddr = NULL;
                return -1;
        }

        if (strlen(name.u.s) > LAYER_NAME_SIZE) {
                log_err("Destination name too long: %s.", name.u.s);

                *paddr = NULL;
                return -1;
        }

        strcpy(dst, name.u.s);

        eth = toml_get(tbl, "eth");
        udp = toml_get(tbl, "udp");
        if (eth.type == TOML_TABLE && udp.type == TOML_STRING) {
                log_err("A PoA is eth or udp, not both.");

                *paddr = NULL;
                return -1;
        }

        if (eth.type != TOML_TABLE && udp.type != TOML_STRING) {
                *paddr = NULL;
                return 0;
        }

        if (eth.type == TOML_TABLE)
                ret = toml_peer_eth(eth, addr);
        else
                ret = toml_peer_udp(udp.u.s, addr);

        if (ret < 0)
                *paddr = NULL;

        return ret;
}

static int toml_connect(toml_datum_t table,
                        pid_t        pid)
{
        toml_datum_t conn;
        int          i;
        int          ret = 0;

        conn = toml_get(table, "conn");
        if (conn.type != TOML_ARRAY)
                return 0;

        for (i = 0; ret == 0 && i < conn.u.arr.size; i++) {
                toml_datum_t      entry;
                struct poa_addr   addr;
                struct poa_addr * paddr = &addr;
                char              buf[LAYER_NAME_SIZE + 1];
                const char *      d;
                qosspec_t         qs = qos_raw;

                entry = conn.u.arr.elem[i];
                if (entry.type == TOML_STRING) {
                        d     = entry.u.s;
                        paddr = NULL;
                } else if (entry.type == TOML_TABLE) {
                        ret = toml_peer(entry, buf, &paddr);
                        if (ret < 0)
                                break;

                        d = buf;
                } else {
                        break;
                }

                log_dbg("Connecting %d to %s", pid, d);

                ret = connect_ipcp_resolve(pid, d, MGMT_COMP, qs, paddr);
                if (ret == 0)
                        ret = connect_ipcp_resolve(pid, d, DT_COMP, qs, paddr);
        }

        return ret;
}

static int toml_ipcp(toml_datum_t         table,
                     struct ipcp_info *   info,
                     struct ipcp_config * conf)
{
        toml_datum_t bootstrap;
        toml_datum_t enrol;
        toml_datum_t transit;
        bool         have_boot;
        bool         have_enrol;
        int          ret;

        log_dbg("Found IPCP %s in configuration file.", info->name);

        transit = toml_get(table, "transit");
        if (transit.type == TOML_BOOLEAN && !transit.u.boolean)
                info->flags &= ~IPCP_FLAG_TRANSIT;

        if (create_ipcp(info) < 0) {
                log_err("Failed to create IPCP %s.", info->name);
                return -1;
        }

        bootstrap = toml_get(table, "bootstrap");
        enrol     = toml_get(table, "enrol");

        have_boot  = bootstrap.type == TOML_STRING;
        have_enrol = enrol.type == TOML_STRING || enrol.type == TOML_TABLE;
        if (have_boot && have_enrol) {
                log_err("Ignoring bootstrap for IPCP %s.", info->name);

                have_boot = false;
        }

        if (!have_boot && !have_enrol) {
                log_dbg("Nothing more to do for %s.", info->name);
                return 0;
        }

        /* Endpoints come first: enrolment reaches the peer over one. */
        if (toml_attach(table, info->pid) < 0) {
                log_err("Failed to attach PoAs for %s.", info->name);
                return -1;
        }

        if (have_enrol) {
                struct layer_info layer;
                struct poa_addr   addr;
                struct poa_addr * paddr = &addr;
                char              buf[LAYER_NAME_SIZE + 1];
                const char *      dst;

                if (enrol.type == TOML_STRING) {
                        dst   = enrol.u.s;
                        paddr = NULL;
                } else {
                        if (toml_peer(enrol, buf, &paddr) < 0) {
                                log_err("Invalid enrol table for %s.",
                                        info->name);
                                return -1;
                        }
                        dst = buf;
                }

                ret = enroll_ipcp_resolve(info->pid, dst, paddr);
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

        assert(have_boot);

        if (strlen(bootstrap.u.s) > LAYER_NAME_SIZE) {
                log_err("Layer name too long: %s", bootstrap.u.s);
                return -1;
        }

        switch (conf->type) {
        case IPCP_LOCAL:
                ret = toml_local(table, conf);
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

static int toml_ipcp_list(toml_datum_t   table,
                          enum ipcp_type type)
{
        int i   = 0;
        int ret = 0;

        for (i = 0; ret == 0 && i < table.u.tab.size; i++) {
                const char *       key;
                struct ipcp_info   info;
                struct ipcp_config conf;

                memset(&conf, 0, sizeof(conf));
                memset(&info, 0, sizeof(info));

                key = table.u.tab.key[i];
                if (strlen(key) > IPCP_NAME_SIZE) {
                        log_err("IPCP name too long: %s,", key);
                        return -1;
                }

                if (table.u.tab.value[i].type != TOML_TABLE) {
                        log_err("IPCP %s is not a table.", key);
                        return -1;
                }

                info.type  = type;
                info.flags = IPCP_FLAG_TRANSIT;

                strcpy(info.name, key);

                conf.type = type;

                ret = toml_ipcp(table.u.tab.value[i], &info, &conf);
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

/* Arguments pair with programs by index until the first one missing. */
static int toml_prog_list(toml_datum_t progs,
                          toml_datum_t args,
                          const char * name)
{
        toml_datum_t prog;
        const char * arg;
        int          nargs;
        int          ret = 0;
        int          i;

        nargs = args.type == TOML_ARRAY ? args.u.arr.size : 0;

        for (i = 0; ret == 0 && i < progs.u.arr.size; i++) {
                prog = progs.u.arr.elem[i];
                if (prog.type != TOML_STRING)
                        break;

                arg = NULL;

                if (i < nargs && args.u.arr.elem[i].type == TOML_STRING)
                        arg = args.u.arr.elem[i].u.s;
                else
                        nargs = 0;

                ret = toml_prog(prog.u.s, arg, name);
        }

        return ret;
}

static int cp_chk_path(char *       buf,
                       const char * path)
{
        char * rp;

        assert(path != NULL);

        rp = realpath(path, NULL);
        if (rp == NULL) {
                log_err("Failed to check path %s: %s.", path, strerror(errno));
                goto fail_rp;
        }

        if (strlen(rp) > NAME_PATH_SIZE) {
                log_err("File path too long: %s.", rp);
                goto fail_len;
        }

        strcpy(buf, rp);
        free(rp);

        return 0;

 fail_len:
        free(rp);
 fail_rp:
        return -1;
}

static int toml_name(toml_datum_t table,
                     const char * name)
{
        toml_datum_t progs;
        toml_datum_t lb;
        toml_datum_t ssec;
        toml_datum_t scrt;
        toml_datum_t skey;
        toml_datum_t csec;
        toml_datum_t ccrt;
        toml_datum_t ckey;

        struct name_info info = {
                .pol_lb = LB_SPILL
        };

        log_dbg("Found service name %s in configuration file.", name);

        if (strlen(name) > NAME_SIZE) {
                log_err("Name too long: %s", name);
                return -1;
        }

        strcpy(info.name, name);

        lb = toml_get(table, "lb");
        if (lb.type == TOML_STRING) {
                if (strcmp(lb.u.s, "spill") == 0)
                        info.pol_lb = LB_SPILL;
                else if (strcmp(lb.u.s, "round-robin") == 0)
                        info.pol_lb = LB_RR;
                else
                        info.pol_lb = LB_INVALID;
        }

        if (info.pol_lb == LB_INVALID) {
                log_err("Invalid load-balancing policy for %s.", name);
                return -1;
        }

        ssec = toml_get(table, "server_sec_file");
        if (ssec.type == TOML_STRING && cp_chk_path(info.s.sec, ssec.u.s) < 0)
                return -1;

        scrt = toml_get(table, "server_crt_file");
        if (scrt.type == TOML_STRING && cp_chk_path(info.s.crt, scrt.u.s) < 0)
                return -1;

        skey = toml_get(table, "server_key_file");
        if (skey.type == TOML_STRING && cp_chk_path(info.s.key, skey.u.s) < 0)
                return -1;

        csec = toml_get(table, "client_sec_file");
        if (csec.type == TOML_STRING && cp_chk_path(info.c.sec, csec.u.s) < 0)
                return -1;

        ccrt = toml_get(table, "client_crt_file");
        if (ccrt.type == TOML_STRING && cp_chk_path(info.c.crt, ccrt.u.s) < 0)
                return -1;

        ckey = toml_get(table, "client_key_file");
        if (ckey.type == TOML_STRING && cp_chk_path(info.c.key, ckey.u.s) < 0)
                return -1;

        if (name_create(&info) < 0) {
                log_err("Failed to create name %s.", name);
                return -1;
        }

        progs = toml_get(table, "prog");
        if (progs.type != TOML_ARRAY)
                return 0;

        if (toml_prog_list(progs, toml_get(table, "args"), name) < 0)
                return -1;

        return 0;
}

static int toml_name_list(toml_datum_t table)
{
        int i;
        int ret = 0;

        for (i = 0; ret == 0 && i < table.u.tab.size; i++) {
                if (table.u.tab.value[i].type != TOML_TABLE) {
                        log_err("Name %s is not a table.", table.u.tab.key[i]);
                        return -1;
                }

                ret = toml_name(table.u.tab.value[i], table.u.tab.key[i]);
        }

        return ret;
}

static int toml_toplevel(toml_datum_t sub,
                         const char * key)
{
        if (sub.type != TOML_TABLE) {
                log_err("Toplevel key %s is not a table.", key);
                return -1;
        }

        if (strcmp(key, "name") == 0)
                return toml_name_list(sub);
        else if (strcmp(key, "local") == 0)
                return toml_ipcp_list(sub, IPCP_LOCAL);
        else if (strcmp(key, "broadcast") == 0)
                return toml_ipcp_list(sub, IPCP_BROADCAST);
        else if (strcmp(key, "unicast") == 0)
                return toml_ipcp_list(sub, IPCP_UNICAST);
        else
                log_err("Unkown toplevel key: %s.", key);

        return -1;
}

static int toml_load(toml_datum_t table)
{
        int i;
        int ret = 0;

        for (i = 0; ret == 0 && i < table.u.tab.size; i++)
                ret = toml_toplevel(table.u.tab.value[i], table.u.tab.key[i]);

        return ret;
}

static int toml_cfg(FILE * fp)
{
        toml_result_t res;

        assert(fp != NULL);

        res = toml_parse_file(fp);
        if (!res.ok) {
                log_err("Failed to parse config file: %s.", res.errmsg);
                goto fail;
        }

        if (toml_load(res.toptab) < 0) {
                log_err("Failed to load configuration.");
                goto fail;
        }

        toml_free(res);

        return 0;
 fail:
        toml_free(res);
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
                log_err("Failed to check path for %s: %s.",
                        path, strerror(errno));
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
