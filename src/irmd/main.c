/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * The IPC Resource Manager
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#define _GNU_SOURCE
#else
#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#endif

#include "config.h"

#define OUROBOROS_PREFIX "irmd"

#include <ouroboros/bitmap.h>
#include <ouroboros/crypt.h>
#include <ouroboros/errno.h>
#include <ouroboros/flow.h>
#include <ouroboros/fqueue.h>
#include <ouroboros/hash.h>
#include <ouroboros/irm.h>
#include <ouroboros/list.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/logs.h>
#include <ouroboros/protobuf.h>
#include <ouroboros/pthread.h>
#include <ouroboros/random.h>
#include <ouroboros/rib.h>
#include <ouroboros/ssm_pool.h>
#include <ouroboros/sockets.h>
#include <ouroboros/time.h>
#include <ouroboros/tpm.h>
#include <ouroboros/utils.h>
#include <ouroboros/version.h>

#include "irmd.h"
#include "ipcp.h"
#include "oap.h"
#include "reg/reg.h"
#include "configfile.h"

#include <dirent.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/un.h>
#ifdef __APPLE__
#include <sys/types.h>
#include <unistd.h>
#endif

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#define IRMD_CLEANUP_TIMER ((IRMD_FLOW_TIMEOUT / 20) * MILLION) /* ns */
#define SHM_SAN_HOLDOFF    1000 /* ms */
#define IPCP_HASH_LEN(p)   hash_len((p)->dir_hash_algo)
#define BIND_TIMEOUT       10   /* ms */
#define TIMESYNC_SLACK     100  /* ms */
#define OAP_SEEN_TIMER     20   /*  s */
#define DEALLOC_TIME       300  /*  s */
#define REKEY_BATCH        64   /* flows re-keyed per timer pass */
#define REKEY_RESP_TIMEO   20   /* s; give-up on a re-key RESPONSE */
#define DIRECT_MPL         20   /* ms */
/* bytes; in-process, bounded only by PUP/GSPP. */
#define DIRECT_MTU         65000

enum irm_state {
        IRMD_NULL = 0,
        IRMD_INIT,
        IRMD_RUNNING,
        IRMD_SHUTDOWN
};

struct cmd {
        struct list_head next;

        uint8_t          cbuf[SOCK_BUF_SIZE];
        size_t           len;
        int              fd;
};

/* In-flight Tier-2 re-key, owned solely by the re-key worker thread. */
struct rekey_ctx {
        struct list_head next;

        int              flow_id;
        void *           ctx;       /* OAP client ctx (opaque)        */
        struct timespec  deadline;  /* reap if no RESPONSE by then    */
};

enum rekey_evt_type {
        REKEY_INIT = 0,             /* start an exchange for flow_id  */
        REKEY_REQ,                  /* a REQUEST arrived for flow_id  */
        REKEY_RESP,                 /* a RESPONSE arrived for flow_id */
        REKEY_DIRECT                /* in-process re-key, direct flow */
};

struct rekey_evt {
        struct list_head    next;

        enum rekey_evt_type type;
        int                 flow_id;
        pid_t               n_1_pid;  /* INIT: flow's lower IPCP      */
        buffer_t            buf;      /* RESP: owned RESPONSE payload  */
};

struct {
        bool                 log_stdout;   /* log to stdout              */
#ifdef HAVE_TOML
        char *               cfg_file;     /* configuration file path    */
#endif
        struct lockfile *    lf;           /* single irmd per system     */
        struct ssm_pool * gspp;            /* pool for packets           */

        int                  sockfd;       /* UNIX socket                */

        struct list_head     cmds;         /* pending commands           */
        pthread_cond_t       cmd_cond;     /* cmd signal condvar         */
        pthread_mutex_t      cmd_lock;     /* cmd signal lock            */

        enum irm_state       state;        /* state of the irmd          */
        pthread_rwlock_t     state_lock;   /* lock for the entire irmd   */

        struct tpm *         tpm;          /* thread pool manager        */

        pthread_t            irm_sanitize; /* clean up irmd resources    */
        pthread_t            acceptor;     /* accept new commands        */

        struct {
                pthread_t        worker;  /* Tier-2 re-key orchestrator  */
                struct list_head inbox;   /* re-key events for worker    */
                pthread_cond_t   cond;    /* inbox signal condvar        */
                pthread_mutex_t  mtx;     /* inbox lock                  */
        } rk;
} irmd;

static enum irm_state irmd_get_state(void)
{
        enum irm_state state;

        pthread_rwlock_rdlock(&irmd.state_lock);

        state = irmd.state;

        pthread_rwlock_unlock(&irmd.state_lock);

        return state;
}

static void irmd_set_state(enum irm_state state)
{
        pthread_rwlock_wrlock(&irmd.state_lock);

        irmd.state = state;

        pthread_rwlock_unlock(&irmd.state_lock);
}

static pid_t spawn_program(char ** argv)
{
        pid_t       pid;
        struct stat s;

        if (stat(argv[0], &s) != 0) {
                log_warn("Program %s does not exist.", argv[0]);
                return -1;
        }

        if (!(s.st_mode & S_IXUSR)) {
                log_warn("Program %s is not executable.", argv[0]);
                return -1;
        }

        if (posix_spawn(&pid, argv[0], NULL, NULL, argv, NULL)) {
                log_err("Failed to spawn new process for %s.", argv[0]);
                return -1;
        }

        log_info("Instantiated %s as process %d.", argv[0], pid);

        return pid;
}

static pid_t spawn_ipcp(struct ipcp_info * info)
{
        char * exec_name = NULL;
        char   irmd_pid[10];
        char   full_name[256];
        char * argv[5];
        pid_t  pid;

        switch(info->type) {
        case IPCP_UNICAST:
                exec_name = IPCP_UNICAST_EXEC;
                break;
        case IPCP_BROADCAST:
                exec_name = IPCP_BROADCAST_EXEC;
                break;
        case IPCP_LOCAL:
                exec_name = IPCP_LOCAL_EXEC;
                break;
        default:
                assert(false);
        }

        if (exec_name == NULL) {
                log_err("IPCP type not installed.");
                return -1;
        }

        sprintf(irmd_pid, "%u", getpid());

        strcpy(full_name, INSTALL_PREFIX"/"INSTALL_SBINDIR"/");
        strcat(full_name, exec_name);

        /* log_file to be placed at the end */
        argv[0] = full_name;
        argv[1] = irmd_pid;
        argv[2] = (char *) info->name;

        if (log_syslog)
                argv[3] = "1";
        else
                argv[3] = NULL;

        argv[4] = NULL;

        pid = spawn_program(argv);
        if (pid < 0) {
                log_err("Failed to spawn IPCP %s.", info->name);
                return -1;
        }

        info->pid   = pid;
        info->state = IPCP_INIT;

        return 0;
}

static int kill_ipcp(pid_t pid)
{
        int  status;

        if (kill(pid, SIGTERM) < 0) {
                log_err("Failed to destroy IPCP: %s.", strerror(errno));
                return -1;
        }

        waitpid(pid, &status, 0);

        return 0;
}

/* A local IPCP only loops back, so it always carries transit. */
static int check_ipcp_flags(enum ipcp_type type,
                            uint32_t       flags)
{
        if (flags & ~IPCP_FLAGS_ALL) {
                log_err("Invalid IPCP flags 0x%08x.", flags);
                return -EINVAL;
        }

        if (!(flags & IPCP_FLAG_TRANSIT) && type == IPCP_LOCAL) {
                log_err("Cannot disable transit on a local IPCP.");
                return -EPERM;
        }

        return 0;
}

static int set_ipcp_flags(pid_t    pid,
                          uint32_t flags,
                          uint32_t mask)
{
        struct ipcp_info info;
        int              ret;

        info.pid = pid;
        if (reg_get_ipcp(&info, NULL) < 0) {
                log_err("Failed to get IPCP %d.", pid);
                return -EIPCP;
        }

        flags = (info.flags & ~mask) | (flags & mask);

        ret = check_ipcp_flags(info.type, flags);
        if (ret < 0)
                return ret;

        if (ipcp_set_flags(pid, flags, mask) < 0) {
                log_err("Failed to set flags on IPCP %d.", pid);
                return -EIPCP;
        }

        if (reg_set_flags_for_ipcp(pid, flags) < 0) {
                log_err("Failed to record flags for IPCP %d.", pid);
                return -EIPCP;
        }

        return 0;
}

/* The boot wait returns the IPCP's own report, so the request is kept. */
int create_ipcp(struct ipcp_info * info)
{
        struct timespec abstime;
        struct timespec timeo = TIMESPEC_INIT_MS(SOCKET_TIMEOUT);
        uint32_t        flags = info->flags;
        int             status;
        int             ret;

        assert(info->pid == 0);

        ret = check_ipcp_flags(info->type, flags);
        if (ret < 0)
                return ret;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        if (spawn_ipcp(info) < 0) {
                log_err("Failed to create IPCP.");
                goto fail_ipcp;
        }

        if (reg_create_ipcp(info) < 0) {
                log_err("Failed to create IPCP entry.");
                goto fail_reg_ipcp;
        }

        if (reg_wait_ipcp_boot(info, &abstime)) {
                log_err("IPCP %d failed to boot.", info->pid);
                goto fail_boot;
        }

        if (set_ipcp_flags(info->pid, flags, IPCP_FLAGS_ALL) < 0)
                goto fail_flags;

        log_info("Created IPCP %d.", info->pid);

        return 0;

 fail_flags:
        kill_ipcp(info->pid);
        reg_destroy_proc(info->pid);
        return -1;

 fail_boot:
        waitpid(info->pid, &status, 0);
        reg_destroy_proc(info->pid);
        return -1;

 fail_reg_ipcp:
        kill_ipcp(info->pid);
 fail_ipcp:
        return -1;
}

static int create_ipcp_r(struct ipcp_info * info)
{
        return reg_respond_ipcp(info);
}

static int destroy_ipcp(pid_t pid)
{
        if (kill_ipcp(pid)) {
                log_err("Could not destroy IPCP.");
                goto fail;
        }

        if (reg_destroy_proc(pid)) {
                log_err("Failed to remove IPCP from registry.");
                goto fail;
        }

        return 0;
 fail:
        return -1;
}

int bootstrap_ipcp(pid_t                pid,
                   struct ipcp_config * conf)
{
        struct ipcp_info  info;
        struct layer_info layer;

        info.pid = pid;

        if (reg_get_ipcp(&info, NULL) < 0) {
                log_err("Could not find IPCP %d.", pid);
                goto fail;
        }

        if (ipcp_bootstrap(pid, conf, &layer)) {
                log_err("Could not bootstrap IPCP.");
                goto fail;
        }

        info.state = IPCP_BOOT;

        if (reg_set_layer_for_ipcp(&info, &layer) < 0) {
                log_err("Failed to set layer info for IPCP.");
                goto fail;
        }

        log_info("Bootstrapped IPCP %d.", pid);

        return 0;
 fail:
        return -1;
}

ssize_t list_poas(pid_t              pid,
                  struct poa_spec ** eps)
{
        struct ipcp_info info;

        info.pid = pid;
        if (reg_get_ipcp(&info, NULL) < 0) {
                log_err("Could not find IPCP %d.", pid);
                return -1;
        }

        if (info.type != IPCP_UNICAST && info.type != IPCP_BROADCAST)
                return 0; /* nothing it could be attached to */

        return ipcp_list_poas(pid, eps);
}

/* Only the types that can carry a PoA may take one. */
int attach_ipcp(pid_t                   pid,
                const struct poa_spec * poa,
                bool                    attach)
{
        struct ipcp_info info;

        info.pid = pid;
        if (reg_get_ipcp(&info, NULL) < 0) {
                log_err("Could not find IPCP %d.", pid);
                return -1;
        }

        if (info.type != IPCP_UNICAST && info.type != IPCP_BROADCAST) {
                log_err("IPCP %d does not support PoAs.", pid);
                return -1;
        }

        if (ipcp_attach(pid, poa, attach) < 0) {
                log_err("Could not %s IPCP %d.",
                        attach ? "attach" : "detach", pid);
                return -1;
        }

        log_info("%s IPCP %d.", attach ? "Attached" : "Detached", pid);

        return 0;
}

int enroll_ipcp(pid_t                   pid,
                const char *            dst,
                const struct poa_addr * addr)
{
        struct layer_info layer;
        struct ipcp_info  info;

        info.pid = pid;

        if (reg_get_ipcp(&info, NULL) < 0) {
                log_err("Could not find IPCP.");
                goto fail;
        }

        if (ipcp_enroll(pid, dst, addr, &layer) < 0) {
                log_err("Could not enroll IPCP %d.", pid);
                goto fail;
        }

        info.state = IPCP_BOOT;

        if (reg_set_layer_for_ipcp(&info, &layer) < 0) {
                log_err("Failed to set layer info for IPCP.");
                goto fail;
        }

        log_info("Enrolled IPCP %d in layer %s.", pid, layer.name);

        return 0;
 fail:
        return -1;
}

int connect_ipcp(pid_t                   pid,
                 const char *            dst,
                 const char *            component,
                 qosspec_t               qs,
                 const struct poa_addr * addr)
{
        struct ipcp_info info;

        info.pid = pid;

        if (reg_get_ipcp(&info, NULL) < 0) {
                log_err("No such IPCP.");
                return -EIPCP;
        }

        if (info.type != IPCP_UNICAST && info.type != IPCP_BROADCAST) {
                log_err("Cannot establish connections for this IPCP type.");
                return -EIPCP;
        }

        log_dbg("Connecting %s to %s.", component, dst);

        if (ipcp_connect(pid, dst, component, qs, addr) < 0) {
                log_err("Could not connect IPCP %d to %s.", pid, dst);
                return -EPERM;
        }

        log_info("Established %s connection between IPCP %d and %s.",
                 component, pid, dst);

        return 0;
}

/* Resolve the dial name, if any, and fill in one record. */
static int poa_addr_resolve(struct poa_addr *  addr,
                            struct addrinfo ** res)
{
        struct addrinfo hints;

        *res = NULL;

        if (addr == NULL)
                return 0;

        if (addr->hostname[0] == '\0')
                return addr->type == POA_UDP ? -EINVAL : 0;

        if (addr->type != POA_UDP)
                return -EINVAL;

        memset(&hints, 0, sizeof(hints));

        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(addr->hostname, NULL, &hints, res) != 0) {
                log_err("Failed to resolve %s.", addr->hostname);
                return -EADDRNOTAVAIL;
        }

        return 0;
}

static void poa_addr_from_ai(struct poa_addr *       addr,
                             const struct addrinfo * ai,
                             uint16_t                port)
{
        struct sockaddr_in *  in;
        struct sockaddr_in6 * in6;

        if (ai->ai_family == AF_INET) {
                in = (struct sockaddr_in *) ai->ai_addr;
                addr->type         = POA_UDP4;
                addr->udp4.ip_addr = in->sin_addr;
                addr->udp4.port    = port;
        } else {
                in6 = (struct sockaddr_in6 *) ai->ai_addr;
                addr->type         = POA_UDP6;
                addr->udp6.ip_addr = in6->sin6_addr;
                addr->udp6.port    = port;
        }
}

/* Skip families without an attached PoA; keep all if none reported. */
static void poa_families(pid_t  pid,
                         bool * v4,
                         bool * v6)
{
        struct poa_spec * eps;
        ssize_t           n;
        ssize_t           i;

        eps = NULL;

        *v4 = false;
        *v6 = false;

        n = list_poas(pid, &eps);
        for (i = 0; i < n; i++) {
                if (eps[i].type == POA_UDP4)
                        *v4 = true;

                if (eps[i].type == POA_UDP6)
                        *v6 = true;
        }

        free(eps);

        if (!*v4 && !*v6) {
                *v4 = true;
                *v6 = true;
        }
}

/* Try each resolved record in order until an enrolment succeeds. */
int enroll_ipcp_resolve(pid_t             pid,
                        const char *      dst,
                        struct poa_addr * addr)
{
        struct addrinfo * res;
        struct addrinfo * ai;
        uint16_t          port;
        bool              v4;
        bool              v6;
        int               ret;

        ret = poa_addr_resolve(addr, &res);
        if (ret < 0)
                return ret;

        if (res == NULL)
                return enroll_ipcp(pid, dst, addr);

        port = addr->udp4.port; /* POA_UDP parks it there */

        poa_families(pid, &v4, &v6);

        ret = -EADDRNOTAVAIL;

        for (ai = res; ai != NULL; ai = ai->ai_next) {
                if ((ai->ai_family == AF_INET && !v4)
                    || (ai->ai_family == AF_INET6 && !v6))
                        continue;

                poa_addr_from_ai(addr, ai, port);

                ret = enroll_ipcp(pid, dst, addr);
                if (ret == 0)
                        break;
        }

        freeaddrinfo(res);

        return ret;
}

/* Try each resolved record in order until a connect succeeds. */
int connect_ipcp_resolve(pid_t             pid,
                         const char *      dst,
                         const char *      component,
                         qosspec_t         qs,
                         struct poa_addr * addr)
{
        struct addrinfo * res;
        struct addrinfo * ai;
        uint16_t          port;
        bool              v4;
        bool              v6;
        int               ret;

        ret = poa_addr_resolve(addr, &res);
        if (ret < 0)
                return ret;

        if (res == NULL)
                return connect_ipcp(pid, dst, component, qs, addr);

        port = addr->udp4.port; /* POA_UDP parks it there */

        poa_families(pid, &v4, &v6);

        ret = -EADDRNOTAVAIL;

        for (ai = res; ai != NULL; ai = ai->ai_next) {
                if ((ai->ai_family == AF_INET && !v4)
                    || (ai->ai_family == AF_INET6 && !v6))
                        continue;

                poa_addr_from_ai(addr, ai, port);

                ret = connect_ipcp(pid, dst, component, qs, addr);
                if (ret == 0)
                        break;
        }

        freeaddrinfo(res);

        return ret;
}

static int disconnect_ipcp(pid_t        pid,
                           const char * dst,
                           const char * component)
{
        struct ipcp_info info;

        info.pid = pid;

        if (reg_get_ipcp(&info, NULL) < 0) {
                log_err("No such IPCP.");
                return -EIPCP;
        }

        if (info.type != IPCP_UNICAST && info.type != IPCP_BROADCAST) {
                log_err("Cannot tear down connections for this IPCP type.");
                return -EIPCP;
        }

        if (ipcp_disconnect(pid, dst, component)) {
                log_err("Could not disconnect IPCP.");
                return -EPERM;
        }

        log_info("%s connection between IPCP %d and %s torn down.",
                 component, pid, dst);

        return 0;
}

static void name_update_sec_paths(struct name_info * info)
{
        char * srv_dir = OUROBOROS_SRV_CRT_DIR;
        char * cli_dir = OUROBOROS_CLI_CRT_DIR;

        assert(info != NULL);

        if (strlen(info->s.sec) == 0)
                sprintf(info->s.sec, "%s/%s/sec.conf", srv_dir, info->name);

        if (strlen(info->s.crt) == 0)
                sprintf(info->s.crt, "%s/%s/crt.pem", srv_dir, info->name);

        if (strlen(info->s.key) == 0)
                sprintf(info->s.key, "%s/%s/key.pem", srv_dir, info->name);

        if (strlen(info->c.sec) == 0)
                sprintf(info->c.sec, "%s/%s/sec.conf", cli_dir, info->name);

        if (strlen(info->c.crt) == 0)
                sprintf(info->c.crt, "%s/%s/crt.pem", cli_dir, info->name);

        if (strlen(info->c.key) == 0)
                sprintf(info->c.key, "%s/%s/key.pem", cli_dir, info->name);
}

int name_create(struct name_info * info)
{
        int ret;

        assert(info != NULL);

        name_update_sec_paths(info);

        ret = reg_create_name(info);
        if (ret == -EEXIST) {
                log_info("Name %s already exists.", info->name);
                return 0;
        }

        if (ret < 0) {
                log_err("Failed to create name %s.", info->name);
                return -1;
        }

        log_info("Created new name: %s.", info->name);

        return 0;
}

static int name_destroy(const char * name)
{

        assert(name != NULL);

        if (reg_destroy_name(name) < 0) {
                log_err("Failed to destroy name %s.", name);
                return -1;
        }

        log_info("Destroyed name: %s.", name);

        return 0;
}

int bind_program(char **      exec,
                 const char * name,
                 uint8_t      flags)
{
        struct prog_info prog;
        struct name_info ni;

        if (name == NULL || exec == NULL || exec[0] == NULL)
                return -EINVAL;

        memset(&prog, 0, sizeof(prog));
        memset(&ni, 0, sizeof(ni));

        if (!reg_has_prog(exec[0])) {
                strcpy(prog.name, path_strip(exec[0]));
                strcpy(prog.path, exec[0]);
                if (reg_create_prog(&prog) < 0)
                        goto fail_prog;
        }

        if (!reg_has_name(name)) {
                ni.pol_lb = LB_SPILL;
                strcpy(ni.name, name);
                if (name_create(&ni) < 0)
                        goto fail_name;
        }

        if (reg_bind_prog(name, exec, flags) < 0) {
                log_err("Failed to bind program %s to name %s", exec[0], name);
                goto fail_bind;
        }

        log_info("Bound program %s to name %s.", exec[0], name);

        return 0;

 fail_bind:
        if (strlen(ni.name) > 0)
                reg_destroy_name(name);
 fail_name:
        if (strlen(prog.name) > 0)
                reg_destroy_prog(exec[0]);
 fail_prog:
        return -1;
}

int bind_process(pid_t        pid,
                 const char * name)
{
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_MS(10);
        struct name_info ni;

        if (name == NULL)
                return -EINVAL;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        if (reg_wait_proc(pid, &abstime) < 0) {
                log_err("Process %d does not %s.", pid,
                        kill(pid, 0) ? "exist" : "respond");
                goto fail;
        }

        memset(&ni, 0, sizeof(ni));

        if (!reg_has_name(name)) {
                ni.pol_lb = LB_SPILL;
                strcpy(ni.name, name);
                if (name_create(&ni) < 0)
                        goto fail;
        }

        if (reg_bind_proc(name, pid) < 0) {
                log_err("Failed to add name %s to process %d.", name, pid);
                goto fail_bind;
        }

        log_info("Bound process %d to name %s.", pid, name);

        return 0;

 fail_bind:
        if (strlen(ni.name) > 0)
                reg_destroy_name(name);
 fail:
        return -1;

}

static int unbind_program(const char * prog,
                          const char * name)
{
        if (prog == NULL)
                return -EINVAL;

        if (name == NULL) {
                if (reg_destroy_prog(prog) < 0) {
                        log_err("Failed to unbind %s.", prog);
                        goto fail;
                }
                log_info("Program %s unbound.", prog);
        } else {
                if (reg_unbind_prog(name, prog) < 0) {
                        log_err("Failed to unbind %s from %s", prog, name);
                        goto fail;
                }
                log_info("Name %s unbound for %s.", name, prog);
        }

        return 0;

 fail:
        return -1;
}

static int unbind_process(pid_t        pid,
                          const char * name)
{
        if (name == NULL) {
                if (reg_destroy_proc(pid) < 0) {
                        log_err("Failed to unbind %d.", pid);
                        goto fail;
                }
                log_info("Process %d unbound.", pid);
        } else {
                if (reg_unbind_proc(name, pid) < 0) {
                        log_err("Failed to unbind %d from %s", pid, name);
                        goto fail;
                }
                log_info("Name %s unbound for process %d.", name, pid);
        }

        return 0;

 fail:
        return -1;
}

static int list_ipcps(ipcp_list_msg_t *** ipcps,
                      size_t *            n_ipcps)
{
        int n;

        n = reg_list_ipcps(ipcps);
        if (n < 0)
                goto fail;

        *n_ipcps = (size_t) n;

        return 0;
 fail:
        *ipcps = NULL;
        *n_ipcps = 0;
        return -1;
}

static int list_names(name_info_msg_t *** names,
                      size_t *            n_names)
{
        int n;

        n = reg_list_names(names);
        if (n < 0)
                goto fail;

        *n_names = (size_t) n;

        return 0;
 fail:
        *names = NULL;
        *n_names = 0;
        return -1;
}

int name_reg(const char * name,
             pid_t        pid)
{
        struct ipcp_info  info;
        struct layer_info layer;
        buffer_t          hash;

        assert(name);

        info.pid = pid;

        if (!reg_has_name(name)) {
                log_err("Failed to get name %s.", name);
                return -ENAME;
        }

        if (reg_get_ipcp(&info, &layer) < 0) {
                log_err("Failed to get IPCP %d.", pid);
                return -EIPCP;
        }

        hash.len = hash_len((enum hash_algo) layer.dir_hash_algo);
        hash.data = malloc(hash.len);
        if (hash.data == NULL) {
                log_err("Failed to malloc hash.");
                return -ENOMEM;
        }

        str_hash((enum hash_algo) layer.dir_hash_algo, hash.data, name);

        if (ipcp_reg(pid, hash)) {
                log_err("Could not register " HASH_FMT32 " with IPCP %d.",
                        HASH_VAL32(hash.data), pid);
                goto fail_hash;
        }

        log_info("Registered %s with IPCP %d as " HASH_FMT32 ".",
                 name, pid, HASH_VAL32(hash.data));

        freebuf(hash);

        return 0;

 fail_hash:
        freebuf(hash);
        return -1;
}

static int name_unreg(const char * name,
                      pid_t        pid)
{
        struct ipcp_info  info;
        struct layer_info layer;
        buffer_t          hash;

        assert(name);

        info.pid = pid;

        if (!reg_has_name(name)) {
                log_err("Failed to get name %s.", name);
                return -ENAME;
        }

        if (reg_get_ipcp(&info, &layer) < 0) {
                log_err("Failed to get IPCP %d.", pid);
                return -EIPCP;
        }

        hash.len  = hash_len((enum hash_algo) layer.dir_hash_algo);
        hash.data = malloc(hash.len);
        if (hash.data == NULL) {
                log_err("Failed to malloc hash.");
                return -ENOMEM;
        }

        str_hash((enum hash_algo) layer.dir_hash_algo, hash.data, name);

        if (ipcp_unreg(pid, hash)) {
                log_err("Could not unregister %s with IPCP %d.", name, pid);
                goto fail_hash;
        }

        log_info("Unregistered %s from %d.", name, pid);

        freebuf(hash);

        return 0;

 fail_hash:
        freebuf(hash);
        return -1;
}

static int get_peer_ids(int     fd,
                        uid_t * uid,
                        gid_t * gid,
                        pid_t * pid)
{
#if defined(__linux__)
        struct ucred ucred;
        socklen_t    len;

        len = sizeof(ucred);

        if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len) < 0)
                goto fail;

        *uid = ucred.uid;
        *gid = ucred.gid;
        if (pid != NULL)
                *pid = ucred.pid;
#else
        if (getpeereid(fd, uid, gid) < 0)
                goto fail;

        if (pid != NULL)
                *pid = -1; /* no portable SO_PEERCRED.pid equivalent */
#endif
        return 0;
 fail:
        return -1;
}

static int proc_announce(const struct proc_info * info)
{
        if (reg_prepare_pool(info->uid, info->gid) < 0) {
                log_err("Failed to prepare pool for uid %d.", info->uid);
                goto fail;
        }

        if (reg_create_proc(info) < 0) {
                log_err("Failed to add process %d.", info->pid);
                goto fail;
        }

        log_info("Process added: %d (%s).", info->pid, info->prog);

        return 0;

 fail:
        return -1;
}

static int proc_exit(pid_t pid)
{
        if (reg_destroy_proc(pid) < 0)
                log_err("Failed to remove process %d.", pid);

        log_info("Process removed: %d.", pid);

        return 0;
}

static void __cleanup_flow(void * flow)
{
        reg_destroy_flow(((struct flow_info *) flow)->id);
}

/*
 * A PoA flow is secured as the IPCP that owns it: trust is in the
 * peer itself. Without a security config for that name the flow
 * stays in the clear.
 */
static void poa_name_info(const char *       name,
                          struct name_info * info)
{
        if (reg_get_name_info(name, info) == 0)
                return;

        memset(info, 0, sizeof(*info));

        strcpy(info->name, name);
}

static int flow_accept(struct flow_info * flow,
                       buffer_t *         data,
                       struct timespec *  abstime,
                       struct crypt_sk *  sk)
{
        buffer_t         req_hdr;
        buffer_t         resp_hdr;
        buffer_t         peer_crt = BUF_INIT;
        char             name[NAME_SIZE + 1];
        struct name_info info;
        int              err;

        assert(data != NULL && BUF_IS_EMPTY(data));

        clrbuf(req_hdr);
        clrbuf(resp_hdr);

        if (!reg_has_proc(flow->n_pid)) {
                log_err("Unknown process %d calling accept.", flow->n_pid);
                err = -EINVAL;
                goto fail_flow;
        }

        if (reg_create_flow(flow) < 0) {
                log_err("Failed to create flow.");
                err = -EBADF;
                goto fail_flow;
        }

        if (reg_prepare_flow_accept(flow) < 0) {
                log_err("Failed to prepare accept.");
                err = -EBADF;
                goto fail_wait;
        }

        pthread_cleanup_push(__cleanup_flow, flow);

        err = reg_wait_flow_accepted(flow, &req_hdr, abstime);

        pthread_cleanup_pop(false);

        if (err == -ETIMEDOUT) {
                log_err("Flow accept timed out.");
                goto fail_wait;
        }

        if (err == -1) {
                log_dbg("Flow accept terminated.");
                err = -EPIPE;
                goto fail_wait;
        }

        assert(err == 0);

        if (reg_get_name_for_flow_id(name, flow->id) < 0) {
                log_err("Failed to get name for flow %d.", flow->id);
                err = -EIPCP;
                goto fail_oap;
        }

        if (reg_flow_is_poa(flow->id)) {
                poa_name_info(name, &info);
        } else if (reg_get_name_info(name, &info) < 0) {
                log_err("Failed to get name info for %s.", name);
                err = -ENAME;
                goto fail_oap;
        }

        log_dbg("IPCP %d accepting flow %d for %s.",
                 flow->n_pid, flow->id, name);

        flow->uid = reg_get_proc_uid(flow->n_pid);

        err = oap_srv_process(&info, req_hdr, &resp_hdr, data, sk,
                              false, NULL, &peer_crt);
        if (err < 0) {
                if (err == -EREPLAY)
                        log_warn("Replayed OAP request for %s.", name);
                else
                        log_err("OAP processing failed for %s.", name);

                goto fail_oap;
        }

        if (reg_flow_is_direct(flow->id)) {
                if (reg_respond_flow_direct(flow->id, &resp_hdr) < 0) {
                        log_err("Failed to respond to direct flow.");
                        goto fail_resp;
                }
                if (sk->nid != NID_undef)
                        reg_flow_set_rekey(flow->id, false, peer_crt);
                log_info("Flow %d accepted (direct) by %d for %s.",
                         flow->id, flow->n_pid, name);
        } else if (ipcp_flow_alloc_resp(flow, 0, resp_hdr) < 0) {
                log_err("Failed to respond to flow allocation.");
                goto fail_resp;
        } else {
                if (sk->nid != NID_undef)
                        reg_flow_set_rekey(flow->id, false, peer_crt);
                log_info("Flow %d accepted by %d for %s (uid %d).",
                         flow->id, flow->n_pid, name, flow->uid);
        }

        freebuf(peer_crt);
        freebuf(req_hdr);
        freebuf(resp_hdr);

        return 0;

 fail_oap:
        if (!reg_flow_is_direct(flow->id))
                ipcp_flow_alloc_resp(flow, err, resp_hdr);
        freebuf(peer_crt);
        freebuf(req_hdr);
        freebuf(resp_hdr);
 fail_wait:
        reg_destroy_flow(flow->id);
 fail_flow:
        return err;

 fail_resp:
        flow->state = FLOW_NULL;
        freebuf(peer_crt);
        freebuf(req_hdr);
        freebuf(resp_hdr);
        reg_destroy_flow(flow->id);
        return -EIPCP;
}

static int flow_join(struct flow_info * flow,
                     const char *       dst,
                     struct timespec *  abstime)
{
        struct ipcp_info  ipcp;
        struct layer_info layer;
        buffer_t          hash;
        buffer_t          pbuf = BUF_INIT; /* nothing to piggyback */
        int               err;

        if (reg_create_flow(flow) < 0) {
                log_err("Failed to create flow.");
                err = -EBADF;
                goto fail_flow;
        }

        flow->uid = reg_get_proc_uid(flow->n_pid);

        log_info("Allocating flow for %d to %s (uid %d).",
                 flow->n_pid, dst, flow->uid);

        strcpy(layer.name, dst);
        if (reg_get_ipcp_by_layer(&ipcp, &layer) < 0) {
                log_err("Failed to get IPCP for layer %s.", dst);
                err = -EIPCP;
                goto fail_ipcp;
        }

        flow->n_1_pid = ipcp.pid;

        hash.len = hash_len((enum hash_algo) layer.dir_hash_algo);
        hash.data = malloc(hash.len);
        if (hash.data == NULL) {
                log_err("Failed to malloc hash buffer.");
                err = -ENOMEM;
                goto fail_ipcp;
        }

        str_hash((enum hash_algo) layer.dir_hash_algo, hash.data, dst);

        reg_prepare_flow_alloc(flow);

        if (ipcp_flow_join(flow, hash)) {
                log_err("Flow join with layer %s failed.", dst);
                err = -ENOTALLOC;
                goto fail_alloc;
        }

        pthread_cleanup_push(__cleanup_flow, flow);
        pthread_cleanup_push(free, hash.data);

        err = reg_wait_flow_allocated(flow, &pbuf, abstime);

        pthread_cleanup_pop(false);
        pthread_cleanup_pop(false);

        if (err == -ETIMEDOUT) {
                log_err("Flow join timed out.");
                goto fail_alloc;
        }

        if (err == -1) {
                log_dbg("Flow join terminated.");
                err = -EPIPE;
                goto fail_alloc;
        }

        assert(pbuf.data == NULL && pbuf.len == 0);
        assert(err == 0);

        freebuf(hash);

        return 0;

 fail_alloc:
        freebuf(hash);
 fail_ipcp:
        reg_destroy_flow(flow->id);
 fail_flow:
        return err;
}

static int get_ipcp_by_dst(const char *     dst,
                           pid_t *          pid,
                           buffer_t *       hash)
{
        ipcp_list_msg_t ** ipcps = NULL;
        int                n;
        int                i;
        int                err = -EIPCP;

        n = reg_list_ipcps(&ipcps);

        /* Clean up the ipcp_msgs in this loop */
        for (i = 0; i < n; ++i) {
                enum hash_algo algo;
                enum ipcp_type type;
                pid_t          tmp;
                bool           enrolled;

                type = ipcps[i]->type;
                algo = ipcps[i]->hash_algo;
                tmp  = ipcps[i]->pid;

                enrolled = strcmp(ipcps[i]->layer, "Not enrolled.") != 0;

                ipcp_list_msg__free_unpacked(ipcps[i], NULL);

                if (type == IPCP_BROADCAST)
                        continue;

                if (err == 0 /* solution found */ || !enrolled)
                        continue;

                hash->len  = hash_len(algo);
                hash->data = malloc(hash->len);
                if (hash->data == NULL) {
                        log_warn("Failed to malloc hash for query.");
                        err = -ENOMEM;
                        continue;
                }

                str_hash(algo, hash->data, dst);

                if (ipcp_query(tmp, *hash) < 0) {
                        freebuf(*hash);
                        continue;
                }

                *pid = tmp;

                err = 0;
        }

        free(ipcps);

        return err;
}

static int wait_for_accept(const char * name)
{
        struct timespec   timeo = TIMESPEC_INIT_MS(IRMD_REQ_ARR_TIMEOUT);
        struct timespec   abstime;
        char **           exec;
        int               ret;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        ret = reg_wait_flow_accepting(name, &abstime);
        if (ret == -ETIMEDOUT) {
                if (reg_get_exec(name, &exec) < 0) {
                        log_dbg("No program bound for %s.", name);
                        goto fail;
                }

                if (spawn_program(exec) < 0) {
                        log_err("Failed to start %s for %s.", exec[0], name);
                        goto fail_spawn;
                }

                log_info("Starting %s for %s.", exec[0], name);

                ts_add(&abstime, &timeo, &abstime);

                ret = reg_wait_flow_accepting(name, &abstime);
                if (ret == -ETIMEDOUT)
                        goto fail_spawn;

                argvfree(exec);
        }

        return ret;

 fail_spawn:
        argvfree(exec);
 fail:
        return -1;
}

static int flow_req_arr(struct flow_info * flow,
                        const uint8_t *    hash,
                        buffer_t *         data)
{
        struct ipcp_info  info;
        struct layer_info layer;
        enum hash_algo    algo;
        int               ret;
        char              name[NAME_SIZE + 1];

        info.pid = flow->n_1_pid;

        log_dbg("Flow req arrived from IPCP %d for " HASH_FMT32 ".",
                 info.pid, HASH_VAL32(hash));

        if (reg_get_ipcp(&info, &layer) < 0) {
                log_err("No IPCP with pid %d.", info.pid);
                ret = -EIPCP;
                goto fail;
        }

        algo = (enum hash_algo) layer.dir_hash_algo;

        if (reg_get_name_for_hash(name, algo, hash) < 0) {
                log_warn("No name for " HASH_FMT32 ".", HASH_VAL32(hash));
                ret = -ENAME;
                goto fail;
        }

        log_info("Flow request arrived for %s.", name);

        ret = wait_for_accept(name);
        if (ret < 0) {
                log_err("No active process for %s.", name);
                goto fail;
        }

        flow->id    = ret;
        flow->state = FLOW_ALLOCATED;

        ret = reg_respond_accept(flow, data);
        if (ret < 0) {
                log_err("Failed to respond to flow %d.", flow->id);
                goto fail;
        }

        return 0;
 fail:
        return ret;
}

#ifndef DISABLE_DIRECT_IPC
static int flow_alloc_direct(const char *       dst,
                             struct flow_info * flow,
                             buffer_t *         data,
                             struct timespec *  abstime,
                             struct crypt_sk *  sk,
                             struct name_info * info)
{
        struct flow_info acc; /* server side flow */
        buffer_t         req_hdr = BUF_INIT;
        buffer_t         resp_hdr = BUF_INIT;
        buffer_t         no_crt = BUF_INIT;
        void *           ctx;
        int              err;

        acc.id = wait_for_accept(dst);
        if (acc.id < 0) {
                log_dbg("No accepting process for %s.", dst);
                return -EAGAIN;
        }

        if (oap_cli_prepare(&ctx, info, NULL, &req_hdr, *data, false) < 0) {
                log_err("Failed to prepare OAP for %s.", dst);
                return -EBADF;
        }

        acc.n_1_pid = flow->n_pid;
        acc.mpl     = DIRECT_MPL;
        acc.mtu     = DIRECT_MTU;
        acc.qs      = flow->qs;
        acc.state   = FLOW_ALLOCATED;

        err = reg_prepare_flow_direct(&acc, &req_hdr, flow->uid);
        if (err == -EPERM) {
                log_dbg("UID mismatch, falling back.");
                oap_ctx_free(ctx);
                freebuf(req_hdr);
                return -EPERM;
        }

        if (err < 0) {
                log_err("Failed to prepare direct flow.");
                oap_ctx_free(ctx);
                freebuf(req_hdr);
                return -EBADF;
        }

        err = reg_wait_flow_direct(acc.id, &resp_hdr, abstime);
        if (err < 0) {
                log_err("Timeout waiting for OAP response.");
                oap_ctx_free(ctx);
                return -ETIMEDOUT;
        }

        err = oap_cli_complete(ctx, resp_hdr, data, sk, NULL, NULL);
        if (err < 0) {
                log_err("OAP completion failed for %s.", dst);
                freebuf(resp_hdr);
                return err;
        }

        flow->id      = acc.id;
        flow->n_1_pid = acc.n_pid;
        flow->mpl     = DIRECT_MPL;
        flow->mtu     = DIRECT_MTU;
        flow->state   = FLOW_ALLOCATED;

        /* Mark encrypted for re-key; the acceptor caches the cert. */
        if (sk->nid != NID_undef)
                reg_flow_set_rekey(acc.id, true, no_crt);

        log_info("Flow %d allocated (direct) for %d to %s.",
                 flow->id, flow->n_pid, dst);

        freebuf(resp_hdr);

        return 0;
}
#endif /* DISABLE_DIRECT_IPC */

static int flow_alloc(const char *       dst,
                      struct flow_info * flow,
                      buffer_t *         data,
                      struct timespec *  abstime,
                      struct crypt_sk *  sk)
{
        buffer_t         req_hdr = BUF_INIT;
        buffer_t         resp_hdr = BUF_INIT;
        buffer_t         hash = BUF_INIT;
        buffer_t         peer_crt = BUF_INIT;
        struct name_info info;
        void *           ctx;
        int              err;

        /* piggyback of user data not yet implemented */
        assert(data != NULL && BUF_IS_EMPTY(data));

        /* Look up name_info for dst */
        if (reg_get_name_info(dst, &info) < 0) {
                log_err("Failed to get name info for %s.", dst);
                err = -ENAME;
                goto fail_flow;
        }

        flow->uid = reg_get_proc_uid(flow->n_pid);

        log_info("Allocating flow for %d to %s (uid %d).",
                 flow->n_pid, dst, flow->uid);

#ifndef DISABLE_DIRECT_IPC
        err = flow_alloc_direct(dst, flow, data, abstime, sk, &info);
        if (err == 0)
                return 0;

        if (err != -EPERM && err != -EAGAIN)
                goto fail_flow;
#endif
        if (reg_create_flow(flow) < 0) {
                log_err("Failed to create flow.");
                err = -EBADF;
                goto fail_flow;
        }

        reg_set_name_for_flow_id(dst, flow->id);

        if (get_ipcp_by_dst(dst, &flow->n_1_pid, &hash) < 0) {
                log_err("Failed to find IPCP for %s.", dst);
                err = -EIPCP;
                goto fail_ipcp;
        }

        if (reg_prepare_flow_alloc(flow) < 0) {
                log_err("Failed to prepare flow allocation.");
                err = -EBADF;
                goto fail_prepare;
        }

        if (oap_cli_prepare(&ctx, &info, NULL, &req_hdr, *data, false) < 0) {
                log_err("Failed to prepare OAP request for %s.", dst);
                err = -EBADF;
                goto fail_prepare;
        }

        if (ipcp_flow_alloc(flow, hash, req_hdr)) {
                log_err("Flow allocation %d failed.", flow->id);
                err = -EIPCP;
                goto fail_alloc;
        }

        pthread_cleanup_push(__cleanup_flow, flow);
        pthread_cleanup_push(free, hash.data);

        err = reg_wait_flow_allocated(flow, &resp_hdr, abstime);

        pthread_cleanup_pop(false);
        pthread_cleanup_pop(false);

        if (err == -ETIMEDOUT) {
                log_err("Flow allocation timed out.");
                goto fail_wait;
        }

        log_dbg("Response for flow %d to %s.", flow->id, dst);

        if (err < 0) {
                log_warn("Allocation rejected: %s (%d).", dst, err);
                goto fail_peer;
        }

        err = oap_cli_complete(ctx, resp_hdr, data, sk, NULL, &peer_crt);
        if (err < 0) {
                log_err("OAP completion failed for %s.", dst);
                goto fail_complete;
        }

        if (sk->nid != NID_undef)
                reg_flow_set_rekey(flow->id, true, peer_crt);

        freebuf(peer_crt);
        freebuf(req_hdr);
        freebuf(resp_hdr);
        freebuf(hash);

        return 0;

 fail_complete:
        freebuf(peer_crt);
        ctx = NULL; /* free'd on complete */
 fail_peer:
        flow->state = FLOW_DEALLOCATED;
 fail_wait:
        freebuf(resp_hdr);
 fail_alloc:
        freebuf(req_hdr);
        oap_ctx_free(ctx);
 fail_prepare:
        freebuf(hash);
 fail_ipcp:
        reg_destroy_flow(flow->id);
 fail_flow:
        return err;
}

/* Creates the flow and prepares the key exchange the IPCP will carry. */
/* The N-1 is only known once the flow exists. */
static int poa_alloc(struct flow_info * flow,
                     const char *       dst,
                     buffer_t *         data)
{
        struct ipcp_info  ipcp;
        struct layer_info layer;
        struct name_info  info;
        buffer_t          req_hdr = BUF_INIT;
        void *            ctx;
        int               err;

        ipcp.pid = flow->n_pid;
        if (reg_get_ipcp(&ipcp, &layer) < 0) {
                log_err("No IPCP with pid %d.", flow->n_pid);

                err = -EIPCP;
                goto fail_flow;
        }

        flow->n_1_pid = 0;
        if (reg_create_flow(flow) < 0) {
                log_err("Failed to create PoA flow.");

                err = -EBADF;
                goto fail_flow;
        }

        reg_set_name_for_flow_id(ipcp.name, flow->id);

        if (reg_flow_set_poa(flow->id) < 0) {
                err = -EBADF;
                goto fail_prepare;
        }

        flow->uid     = reg_get_proc_uid(flow->n_pid);
        flow->n_1_pid = flow->n_pid; /* the IPCP is its own N-1 */
        if (reg_prepare_flow_alloc(flow) < 0) {
                log_err("Failed to prepare PoA flow allocation.");

                err = -EBADF;
                goto fail_prepare;
        }

        poa_name_info(ipcp.name, &info);

        if (oap_cli_prepare(&ctx, &info, dst, &req_hdr, *data, false) < 0) {
                log_err("Failed to prepare OAP request for %s.", ipcp.name);

                err = -EBADF;
                goto fail_prepare;
        }

        if (reg_flow_set_oap_ctx(flow->id, ctx) < 0) {
                err = -EBADF;
                goto fail_ctx;
        }

        log_info("Allocating PoA flow %d for %d as %s.",
                 flow->id, flow->n_pid, ipcp.name);

        *data = req_hdr;

        return 0;

 fail_ctx:
        freebuf(req_hdr);
        oap_ctx_free(ctx);
 fail_prepare:
        reg_destroy_flow(flow->id);
 fail_flow:
        return err;
}

/* Completes the key exchange once the IPCP has the peer's response. */
/*
 * We present the PoA's own credentials and expect the peer to present
 * dst's: the address only says how to reach it. oap_cli_complete
 * frees the ctx on every path.
 */
static int poa_complete(struct flow_info * flow,
                        int                response,
                        buffer_t *         data,
                        struct crypt_sk *  sk)
{
        struct name_info info;
        buffer_t         peer_crt = BUF_INIT;
        buffer_t         out = BUF_INIT;
        buffer_t         empty = BUF_INIT;
        char             name[NAME_SIZE + 1];
        void *           ctx;
        int              err;

        ctx = reg_flow_take_oap_ctx(flow->id);
        if (ctx == NULL) {
                log_err("No pending PoA flow %d.", flow->id);
                return -EBADF;
        }

        if (response < 0) {
                log_dbg("PoA flow %d refused: %d.", flow->id, response);

                err = response;
                goto fail;
        }

        if (reg_get_name_for_flow_id(name, flow->id) < 0) {
                err = -EBADF;
                goto fail;
        }

        poa_name_info(name, &info);

        err = oap_cli_complete(ctx, *data, &out, sk, NULL, &peer_crt);
        if (err < 0) {
                log_err("OAP completion failed for %s.", name);

                ctx = NULL;
                goto fail;
        }

        if (sk->nid != NID_undef)
                reg_flow_set_rekey(flow->id, true, peer_crt);

        flow->state = FLOW_ALLOCATED;
        if (reg_respond_alloc(flow, &empty, 0) < 0) {
                log_err("Failed to update PoA flow %d.", flow->id);

                err = -EBADF;
                goto fail_crt;
        }

        log_info("PoA flow %d allocated to %s.", flow->id, name);

        freebuf(peer_crt);
        freebuf(out);

        return 0;

 fail_crt:
        freebuf(peer_crt);
        freebuf(out);
 fail:
        oap_ctx_free(ctx);
        reg_destroy_flow(flow->id);
        return err;
}

/* A peer requested a flow on a PoA of this IPCP. */
static int poa_req_arr(struct flow_info * flow,
                       buffer_t *         data)
{
        struct ipcp_info  ipcp;
        struct layer_info layer;
        int               ret;

        ipcp.pid = flow->n_1_pid;
        if (reg_get_ipcp(&ipcp, &layer) < 0) {
                log_err("No IPCP with pid %d.", flow->n_1_pid);

                ret = -EIPCP;
                goto fail;
        }

        log_info("PoA flow request arrived for %s.", ipcp.name);

        ret = wait_for_accept(ipcp.name);
        if (ret < 0) {
                log_err("No active process for %s.", ipcp.name);
                goto fail;
        }

        flow->id    = ret;
        flow->state = FLOW_ALLOCATED;
        if (reg_flow_set_poa(flow->id) < 0) {
                ret = -EBADF;
                goto fail;
        }

        reg_set_name_for_flow_id(ipcp.name, flow->id);

        ret = reg_respond_accept(flow, data);
        if (ret < 0) {
                log_err("Failed to respond to PoA flow %d.", flow->id);
                goto fail;
        }

        return 0;
 fail:
        return ret;
}

static int flow_alloc_reply(struct flow_info * flow,
                            int                response,
                            buffer_t *         data)
{
        flow->state = response != 0 ? FLOW_DEALLOCATED : FLOW_ALLOCATED;

        if (reg_respond_alloc(flow, data, response) < 0) {
                log_err("Failed to reply to flow %d.", flow->id);
                flow->state = FLOW_DEALLOCATED;
                return -EBADF;
        }

        return 0;
}

static int flow_dealloc(struct flow_info * flow,
                        struct timespec *  ts)
{
        log_info("Deallocating flow %d for process %d (timeout: %ld s).",
                 flow->id, flow->n_pid, ts->tv_sec);

        reg_dealloc_flow(flow);

        if (reg_flow_is_direct(flow->id)) {
                if (flow->state == FLOW_DEALLOCATED)
                        reg_destroy_flow(flow->id);
                return 0;
        }

        if (ipcp_flow_dealloc(flow->n_1_pid, flow->id, ts->tv_sec) < 0) {
                log_err("Failed to request dealloc from %d.", flow->n_1_pid);
                return -EIPCP;
        }

        return 0;
}

static int flow_dealloc_resp(struct flow_info * flow)
{
        reg_dealloc_flow_resp(flow);

        assert(flow->state == FLOW_DEALLOCATED);

        reg_destroy_flow(flow->id);

        log_info("Completed deallocation of flow_id %d by process %d.",
                 flow->id, flow->n_1_pid);

        return 0;
}

/*
 * Inbox producers. Any thread may post; the worker drains. INIT carries
 * the flow's lower IPCP pid; RESP transfers ownership of buf.
 */
static void rekey_post(enum rekey_evt_type type,
                       int                 flow_id,
                       pid_t               n_1_pid,
                       buffer_t *          buf)
{
        struct rekey_evt * evt;

        evt = malloc(sizeof(*evt));
        if (evt == NULL) {
                log_err("Failed to malloc re-key event for flow %d.", flow_id);
                if (type == REKEY_INIT || type == REKEY_DIRECT)
                        reg_flow_clear_in_flight(flow_id);
                else
                        reg_flow_rekey_arr_done(flow_id, type == REKEY_REQ);

                if (buf != NULL)
                        freebuf(*buf);

                return;
        }

        list_head_init(&evt->next);
        evt->type    = type;
        evt->flow_id = flow_id;
        evt->n_1_pid = n_1_pid;
        clrbuf(evt->buf);
        if (buf != NULL) {
                evt->buf = *buf;
                clrbuf(*buf);
        }

        pthread_mutex_lock(&irmd.rk.mtx);

        list_add_tail(&evt->next, &irmd.rk.inbox);
        pthread_cond_signal(&irmd.rk.cond);

        pthread_mutex_unlock(&irmd.rk.mtx);
}

static void rekey_post_init(int   flow_id,
                            pid_t n_1_pid)
{
        rekey_post(REKEY_INIT, flow_id, n_1_pid, NULL);
}

static void rekey_post_resp(int        flow_id,
                            buffer_t * buf)
{
        rekey_post(REKEY_RESP, flow_id, 0, buf);
}

static void rekey_post_req(int        flow_id,
                           pid_t      n_1_pid,
                           buffer_t * buf)
{
        rekey_post(REKEY_REQ, flow_id, n_1_pid, buf);
}

static void rekey_post_direct(int flow_id)
{
        rekey_post(REKEY_DIRECT, flow_id, 0, NULL);
}

/* Worker-only: find an in-flight entry by flow_id. */
static struct rekey_ctx * rekey_find(struct list_head * tbl,
                                     int                flow_id)
{
        struct list_head * p;

        list_for_each(p, tbl) {
                struct rekey_ctx * e = list_entry(p, struct rekey_ctx, next);
                if (e->flow_id == flow_id)
                        return e;
        }

        return NULL;
}

/* Worker-only: drop an entry, freeing its OAP ctx. */
static void rekey_drop(struct rekey_ctx * e)
{
        if (e->ctx != NULL)
                oap_ctx_free(e->ctx);

        list_del(&e->next);
        free(e);
}

/* Resolve a flow's registered name info; < 0 if the flow or name is gone. */
static int rekey_name_info(int                flow_id,
                           struct name_info * info)
{
        char name[NAME_SIZE + 1];

        if (reg_get_name_for_flow_id(name, flow_id) < 0)
                return -1;

        if (reg_flow_is_poa(flow_id)) {
                poa_name_info(name, info);
                return 0;
        }

        return reg_get_name_info(name, info);
}

/* Flow-update relay payload: a 1-byte type prefix on an opaque body. */
enum flow_upd_type {
        FLOW_UPD_REKEY_REQ  = 0,
        FLOW_UPD_REKEY_RESP = 1,
};

/* Prepend the update type to body; caller frees out on success. */
static int flow_upd_wrap(buffer_t *       out,
                         uint8_t          type,
                         const buffer_t * body)
{
        out->len  = body->len + 1;
        out->data = malloc(out->len);
        if (out->data == NULL)
                return -ENOMEM;

        out->data[0] = type;
        memcpy(out->data + 1, body->data, body->len);

        return 0;
}

/* Cleanup handlers — the re-key worker is cancelled at shutdown. */
static void rk_free_evt(void * o)
{
        struct rekey_evt * evt = o;

        freebuf(evt->buf);
        free(evt);
}

static void rk_freebuf(void * o)
{
        freebuf(*(buffer_t *) o);
}

static void rk_clear_in_flight(void * o)
{
        reg_flow_clear_in_flight(*(int *) o);
}

static void rk_clear_key(void * o)
{
        crypt_secure_clear(o, SYMMKEYSZ);
}

static void rekey_do_initiate(struct list_head * tbl,
                              int                flow_id,
                              pid_t              n_1_pid)
{
        struct rekey_ctx * e;
        struct flow_info   info;
        struct name_info   name;
        buffer_t           req  = BUF_INIT;
        buffer_t           upd  = BUF_INIT;
        buffer_t           data = BUF_INIT;
        void *             ctx  = NULL;
        int                ret;

        e = rekey_find(tbl, flow_id);
        if (e != NULL)
                rekey_drop(e); /* Replace in-flight entries */

        if (rekey_name_info(flow_id, &name) < 0) {
                log_err("Failed to get name info to re-key flow %d.", flow_id);
                goto fail;
        }

        if (oap_cli_prepare(&ctx, &name, NULL, &req, data, true) < 0) {
                log_err("Failed to prepare re-key for flow %d.", flow_id);
                goto fail;
        }

        memset(&info, 0, sizeof(info));
        info.id      = flow_id;
        info.n_1_pid = n_1_pid;

        if (flow_upd_wrap(&upd, FLOW_UPD_REKEY_REQ, &req) < 0) {
                log_err("Failed to wrap re-key request for flow %d.", flow_id);
                goto fail_ctx;
        }

        pthread_cleanup_push(rk_clear_in_flight, &flow_id);
        pthread_cleanup_push(oap_ctx_free, ctx);
        pthread_cleanup_push(rk_freebuf, &req);
        pthread_cleanup_push(rk_freebuf, &upd);
        ret = ipcp_flow_update(&info, upd);
        pthread_cleanup_pop(false);
        pthread_cleanup_pop(false);
        pthread_cleanup_pop(false);
        pthread_cleanup_pop(false);
        freebuf(upd);
        if (ret < 0) {
                log_err("Failed to send re-key request for flow %d.", flow_id);
                goto fail_ctx;
        }

        e = malloc(sizeof(*e));
        if (e == NULL) {
                log_err("Failed to malloc re-key ctx for flow %d.", flow_id);
                goto fail_ctx;
        }

        list_head_init(&e->next);
        e->flow_id = flow_id;
        e->ctx     = ctx;
        clock_gettime(PTHREAD_COND_CLOCK, &e->deadline);
        e->deadline.tv_sec += REKEY_RESP_TIMEO;

        list_add(&e->next, tbl);

        log_dbg("Re-key request sent for flow %d.", flow_id);

        freebuf(req);

        return;

 fail_ctx:
        oap_ctx_free(ctx);
        freebuf(req);
 fail:
        reg_flow_clear_in_flight(flow_id);
}

/* Worker-only: complete the exchange, install the pending seed. */
static void rekey_do_complete(struct list_head * tbl,
                              int                flow_id,
                              buffer_t           buf)
{
        struct rekey_ctx * e;
        struct name_info   info;
        struct crypt_sk    sk;
        uint8_t            kbuf[SYMMKEYSZ];
        buffer_t           data = BUF_INIT;
        buffer_t           crt = BUF_INIT;
        uint8_t            newgen;

        e = rekey_find(tbl, flow_id);
        if (e == NULL) {
                log_dbg("Stale re-key RESPONSE for flow %d.", flow_id);
                return;
        }

        /* A concurrent responder already parked a seed; don't overwrite. */
        if (reg_flow_rekey_pending(flow_id)) {
                log_dbg("Re-key already pending for flow %d.", flow_id);
                goto finish;
        }

        if (rekey_name_info(flow_id, &info) < 0) {
                log_err("Failed to get name info to re-key flow %d.", flow_id);
                goto finish;
        }

        sk.key = kbuf;

        reg_flow_get_peer_crt(flow_id, &crt);

        /* oap_cli_complete frees the ctx on every path. */
        if (oap_cli_complete(e->ctx, buf, &data, &sk, &crt, NULL) < 0) {
                log_warn("Failed to complete re-key for flow %d.", flow_id);
                e->ctx = NULL;
                goto finish_clear;
        }

        e->ctx = NULL;

        if (data.len != 1) {
                log_warn("Re-key reply malformed for flow %d.", flow_id);
                goto finish_clear;
        }

        newgen = *(uint8_t *) data.data;

        if (newgen >= 16) {
                log_warn("Re-key gen %u out of range for flow %d.",
                         newgen, flow_id);
                goto finish_clear;
        }

        if (reg_flow_store_pending(flow_id, kbuf, newgen, true) < 0)
                log_warn("Flow %d gone during re-key.", flow_id);
        else
                reg_notify_flow(flow_id, FLOW_UPD);

        log_dbg("Re-key completed for flow %d (gen %u).", flow_id, newgen);

 finish_clear:
        crypt_secure_clear(kbuf, SYMMKEYSZ);
        freebuf(data);
 finish:
        freebuf(crt);
        rekey_drop(e);
        reg_flow_clear_in_flight(flow_id);
}

/* Worker-only: reap entries whose RESPONSE never arrived. */
static void rekey_reap_expired(struct list_head * tbl)
{
        struct list_head * p;
        struct list_head * h;
        struct timespec    now;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        list_for_each_safe(p, h, tbl) {
                struct rekey_ctx * e = list_entry(p, struct rekey_ctx, next);
                if (ts_diff_ns(&e->deadline, &now) > 0)
                        continue;

                log_warn("Re-key timed out for flow %d.", e->flow_id);
                reg_flow_clear_in_flight(e->flow_id);
                rekey_drop(e);
        }
}

/* Responder side: process request, install pending seed, send response. */
static int rekey_respond(struct flow_info * flow,
                         buffer_t *         pk)
{
        struct name_info info;
        struct crypt_sk  sk;
        uint8_t          kbuf[SYMMKEYSZ];
        buffer_t         rsp  = BUF_INIT;
        buffer_t         upd  = BUF_INIT;
        buffer_t         data = BUF_INIT;
        buffer_t         crt  = BUF_INIT;
        uint8_t          newgen;
        int              epoch;
        int              err;

        epoch = reg_flow_get_epoch(flow->id);
        if (epoch < 0) {
                log_warn("Re-key for unknown flow %d.", flow->id);
                return -EBADF;
        }

        /* Collision: we are driving our own exchange; let it win. */
        if (reg_flow_rekey_should_yield(flow->id)) {
                log_dbg("Yielding to own re-key for flow %d.", flow->id);
                return 0;
        }

        if (rekey_name_info(flow->id, &info) < 0) {
                log_err("Failed to get name info to re-key flow %d.", flow->id);
                return -ENAME;
        }

        if (reg_flow_rekey_pending(flow->id)) {
                log_dbg("Duplicate re-key request for flow %d.", flow->id);
                return 0;
        }

        newgen     = (uint8_t) ((epoch + 1) & 0x0F);
        data.data  = &newgen;
        data.len   = 1;

        sk.key = kbuf;

        reg_flow_get_peer_crt(flow->id, &crt);

        err = oap_srv_process(&info, *pk, &rsp, &data, &sk, true, &crt, NULL);
        if (err < 0) {
                /* data still points to stack newgen; don't free it. */
                log_err("Failed to process re-key OAP for flow %d.", flow->id);
                goto finish;
        }

        /* On success oap_srv_process repointed data to client output. */
        freebuf(data);

        if (reg_flow_store_pending(flow->id, kbuf, newgen, false) < 0) {
                log_warn("Flow %d gone during re-key.", flow->id);
                err = -EBADF;
                goto finish;
        }

        reg_notify_flow(flow->id, FLOW_UPD);

        if (flow_upd_wrap(&upd, FLOW_UPD_REKEY_RESP, &rsp) == 0) {
                pthread_cleanup_push(rk_clear_key, kbuf);
                pthread_cleanup_push(rk_freebuf, &rsp);
                pthread_cleanup_push(rk_freebuf, &crt);
                pthread_cleanup_push(rk_freebuf, &upd);
                if (ipcp_flow_update(flow, upd) < 0)
                        log_err("Failed to send re-key response for flow %d.",
                                flow->id);
                pthread_cleanup_pop(false);
                pthread_cleanup_pop(false);
                pthread_cleanup_pop(false);
                pthread_cleanup_pop(false);
                freebuf(upd);
        }

        err = 0;
 finish:
        crypt_secure_clear(kbuf, SYMMKEYSZ);
        freebuf(rsp);
        freebuf(crt);

        return err;
}

/*
 * Worker-only: re-key a direct (loopback) flow, the exchange runs in-process:
 * build a client request, then derive the shared seed, and hand the one seed
 * to both apps with RB_REKEY.
 */
static void rekey_do_direct(int flow_id)
{
        struct name_info info;
        struct crypt_sk  sk;
        uint8_t          kbuf[SYMMKEYSZ];
        buffer_t         req  = BUF_INIT;
        buffer_t         rsp  = BUF_INIT;
        buffer_t         data = BUF_INIT;
        buffer_t         crt  = BUF_INIT;
        void *           ctx  = NULL;
        uint8_t          newgen;
        int              epoch;

        epoch = reg_flow_get_epoch(flow_id);
        if (epoch < 0) {
                log_warn("Re-key for unknown flow %d.", flow_id);
                reg_flow_clear_in_flight(flow_id);
                return;
        }

        if (rekey_name_info(flow_id, &info) < 0) {
                log_err("Failed to get name info to re-key flow %d.", flow_id);
                reg_flow_clear_in_flight(flow_id);
                return;
        }

        if (oap_cli_prepare(&ctx, &info, NULL, &req, data, true) < 0) {
                log_err("Failed to prepare re-key for flow %d.", flow_id);
                reg_flow_clear_in_flight(flow_id);
                return;
        }

        newgen    = (uint8_t) ((epoch + 1) & 0x0F);
        data.data = &newgen;
        data.len  = 1;

        sk.key = kbuf;

        reg_flow_get_peer_crt(flow_id, &crt);

        if (oap_srv_process(&info, req, &rsp, &data, &sk, true,
                            &crt, NULL) < 0) {
                /* data still points to stack newgen; don't free it. */
                log_err("Failed to process re-key OAP for flow %d.", flow_id);
                reg_flow_clear_in_flight(flow_id);
                goto out;
        }

        /* On success oap_srv_process repointed data to its output. */
        freebuf(data);

        if (reg_flow_store_pending_direct(flow_id, kbuf, newgen) < 0) {
                log_warn("Flow %d gone during re-key.", flow_id);
                reg_flow_clear_in_flight(flow_id);
                goto out;
        }

        reg_notify_flow_peers(flow_id, FLOW_UPD);

        log_dbg("Re-key completed (direct) for flow %d (gen %u).",
                flow_id, newgen);
 out:
        crypt_secure_clear(kbuf, SYMMKEYSZ);
        oap_ctx_free(ctx);
        freebuf(req);
        freebuf(rsp);
        freebuf(crt);
}

/* Route one snapshot entry to the wire or in-process re-key path. */
static void rekey_dispatch(struct list_head *        tbl,
                           const struct rekey_info * ri)
{
        if (ri->direct)
                rekey_do_direct(ri->flow_id);
        else
                rekey_do_initiate(tbl, ri->flow_id, ri->n_1_pid);
}

static int flow_update_arr(struct flow_info * flow,
                           buffer_t *         pk)
{
        uint8_t type;
        bool    is_req;

        if (pk->len < 1)
                return -EINVAL;

        type = pk->data[0];

        switch (type) {
        case FLOW_UPD_REKEY_REQ:
                is_req = true;
                break;
        case FLOW_UPD_REKEY_RESP:
                is_req = false;
                break;
        default:
                log_warn("Unknown flow update type %u.", type);
                return -EINVAL;
        }

        /* Drop floods/spoofs before allocating a worker event. */
        if (!reg_flow_rekey_arr_admit(flow->id, flow->n_1_pid, is_req))
                return 0;

        /* Strip the type byte, keeping the malloc base for hand-off. */
        memmove(pk->data, pk->data + 1, pk->len - 1);
        pk->len -= 1;

        /* Defer to worker; an inline RESP send deadlocks loopback. */
        if (is_req)
                rekey_post_req(flow->id, flow->n_1_pid, pk);
        else
                rekey_post_resp(flow->id, pk);

        return 0;
}

static int flow_update(struct flow_info * flow,
                       uid_t              uid,
                       pid_t              cpid,
                       bool               rekey,
                       struct crypt_sk *  sk,
                       bool *             has_key,
                       bool *             initiator)
{
        uint8_t seed[SYMMKEYSZ];
        uint8_t epoch;
        int     rc;

        *has_key   = false;
        *initiator = false;

        if (rekey) {
                pid_t n_1_pid;

                if (!reg_flow_owned_by(flow->id, uid))
                        return -EPERM;

                /* Direct flows re-key in-process; no lower IPCP carrier. */
                if (reg_flow_is_direct(flow->id)) {
                        if (reg_flow_rekey_begin(flow->id))
                                rekey_post_direct(flow->id);

                        return 0;
                }

                /* Watermark re-key: the app can't know its lower IPCP. */
                n_1_pid = reg_flow_get_n_1_pid(flow->id);
                if (n_1_pid <= 0)
                        return 0;

                /* One exchange per flow; the latch arbitrates collisions. */
                if (reg_flow_rekey_begin(flow->id))
                        rekey_post_init(flow->id, n_1_pid);

                return 0;
        }

        rc = reg_flow_take_pending(flow->id, uid, cpid, seed, &epoch,
                                   initiator);
        if (rc == -EPERM)
                return -EPERM;

        if (rc != 0)
                return 0;

        memcpy(sk->key, seed, SYMMKEYSZ);
        sk->epoch = epoch;
        *has_key  = true;

        crypt_secure_clear(seed, SYMMKEYSZ);

        log_dbg("Delivered re-key seed for flow %d (gen %u).",
                flow->id, epoch);

        return 0;
}

static void rekey_table_cleanup(void * o)
{
        struct list_head * tbl = o;
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, tbl) {
                struct rekey_ctx * e = list_entry(p, struct rekey_ctx, next);
                rekey_drop(e);
        }
}

static struct rekey_evt * rekey_event_wait(const struct timespec * dl)
{
        struct rekey_evt * evt = NULL;
        int                ret = 0;

        pthread_mutex_lock(&irmd.rk.mtx);
        pthread_cleanup_push(__cleanup_mutex_unlock, &irmd.rk.mtx);

        while (list_is_empty(&irmd.rk.inbox) && ret != -ETIMEDOUT)
                ret = -pthread_cond_timedwait(&irmd.rk.cond, &irmd.rk.mtx, dl);

        if (!list_is_empty(&irmd.rk.inbox)) {
                evt = list_first_entry(&irmd.rk.inbox, struct rekey_evt, next);
                list_del(&evt->next);
        }

        pthread_cleanup_pop(true);

        return evt;
}

static struct timespec rekey_deadline(struct list_head * tbl,
                                      struct timespec    next)
{
        struct timespec    deadline = next;
        struct list_head * p;

        list_for_each(p, tbl) {
                struct rekey_ctx * e;
                e = list_entry(p, struct rekey_ctx, next);
                if (ts_diff_ns(&e->deadline, &deadline) < 0)
                        deadline = e->deadline;
        }

        return deadline;
}

static void rekey_handle_evt(struct list_head * tbl,
                             struct rekey_evt * evt)
{
        struct flow_info rinfo;

        pthread_cleanup_push(rk_free_evt, evt);

        switch (evt->type) {
        case REKEY_INIT:
                rekey_do_initiate(tbl, evt->flow_id, evt->n_1_pid);
                break;
        case REKEY_REQ:
                memset(&rinfo, 0, sizeof(rinfo));
                rinfo.id      = evt->flow_id;
                rinfo.n_1_pid = evt->n_1_pid;
                rekey_respond(&rinfo, &evt->buf);
                reg_flow_rekey_arr_done(evt->flow_id, true);
                break;
        case REKEY_RESP:
                rekey_do_complete(tbl, evt->flow_id, evt->buf);
                reg_flow_rekey_arr_done(evt->flow_id, false);
                break;
        case REKEY_DIRECT:
                rekey_do_direct(evt->flow_id);
                break;
        default:
                break;
        }

        pthread_cleanup_pop(true);
}

/* On the periodic tick, dispatch all flows due for re-keying. */
static void rekey_run_periodic(struct list_head * tbl,
                               struct timespec *  next)
{
        struct rekey_info snap[REKEY_BATCH];
        struct timespec   now;
        int               n;
        int               i;

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        if (ts_diff_ns(next, &now) > 0)
                return;

        n = reg_flow_snapshot_rekey_due(snap, REKEY_BATCH);
        for (i = 0; i < n; ++i)
                rekey_dispatch(tbl, &snap[i]);

        clock_gettime(PTHREAD_COND_CLOCK, next);
        next->tv_sec += OAP_REKEY_TIMER;
}

/*
 * Single worker owning all in-flight Tier-2 re-keys. It drains the
 * inbox, runs the periodic snapshot, and reaps timed-out exchanges.
 * The table is touched only here, so it needs no lock.
 */
static void * rekey_worker(void * o)
{
        struct list_head table;
        struct timespec  next;

        (void) o;

        list_head_init(&table);

        clock_gettime(PTHREAD_COND_CLOCK, &next);
        next.tv_sec += OAP_REKEY_TIMER;

        pthread_cleanup_push(rekey_table_cleanup, &table);

        while (true) {
                struct rekey_evt * evt;
                struct timespec    deadline;

                deadline = rekey_deadline(&table, next);

                evt = rekey_event_wait(&deadline);

                if (evt != NULL)
                        rekey_handle_evt(&table, evt);

                rekey_run_periodic(&table, &next);

                rekey_reap_expired(&table);
        }

        pthread_cleanup_pop(true);

        return (void *) 0;
}

static void * acceptloop(void * o)
{
        int            csockfd;

        (void) o;

        while (true) {
                struct cmd * cmd;

                csockfd = accept(irmd.sockfd, 0, 0);
                if (csockfd < 0)
                        continue;

                cmd = malloc(sizeof(*cmd));
                if (cmd == NULL) {
                        log_err("Out of memory.");
                        close(csockfd);
                        break;
                }

                pthread_cleanup_push(__cleanup_close_ptr, &csockfd);
                pthread_cleanup_push(free, cmd);

                cmd->len = read(csockfd, cmd->cbuf, SOCK_BUF_SIZE);

                pthread_cleanup_pop(false);
                pthread_cleanup_pop(false);

                if (cmd->len <= 0) {
                        log_err("Failed to read from socket.");
                        close(csockfd);
                        free(cmd);
                        continue;
                }

                cmd->fd  = csockfd;

                pthread_mutex_lock(&irmd.cmd_lock);

                list_add(&cmd->next, &irmd.cmds);

                pthread_cond_signal(&irmd.cmd_cond);

                pthread_mutex_unlock(&irmd.cmd_lock);
        }

        return (void *) 0;
}

static void __cleanup_irm_msg(void * o)
{
        irm_msg__free_unpacked((irm_msg_t *) o, NULL);
}

static irm_msg_t * do_command_msg(irm_msg_t * msg,
                                   int         fd)
{
        struct ipcp_config  conf;
        struct ipcp_info    ipcp;
        struct flow_info    flow;
        struct proc_info    proc;
        struct name_info    name;
        struct crypt_sk     sk;
        uint8_t             kbuf[SYMMKEYSZ]; /* stack buffer for OAP */
        uint8_t *           hbuf = NULL;     /* heap copy for response */
        struct timespec *   abstime;
        struct timespec     max = TIMESPEC_INIT_MS(FLOW_ALLOC_TIMEOUT);
        struct timespec     now;
        struct timespec     ts = TIMESPEC_INIT_S(0); /* static analysis */
        int                 res;
        bool                has_key = false;
        bool                initiator = false;
        uid_t               uid;
        gid_t               gid;
        pid_t               cpid;
        irm_msg_t *         ret_msg;
        buffer_t            data;
        struct poa_addr      poa_addr;
        struct poa_addr *    pa;
        struct poa_spec      poa_spec;
        struct poa_spec *    eps = NULL;

        memset(&flow, 0, sizeof(flow));

        clock_gettime(PTHREAD_COND_CLOCK, &now);

        if (msg->timeo != NULL) {
                ts = timespec_msg_to_s(msg->timeo);
                ts_add(&ts, &now, &ts);
                abstime = &ts;
        } else {
                ts_add(&max, &now, &max);
                abstime = NULL;
        }

        ret_msg = malloc(sizeof(*ret_msg));
        if (ret_msg == NULL) {
                log_err("Failed to malloc return msg.");
                return NULL;
        }

        irm_msg__init(ret_msg);

        ret_msg->code = IRM_MSG_CODE__IRM_REPLY;

        pthread_cleanup_push(__cleanup_irm_msg, ret_msg);

        switch (msg->code) {
        case IRM_MSG_CODE__IRM_CREATE_IPCP:
                ipcp = ipcp_info_msg_to_s(msg->ipcp_info);
                res = create_ipcp(&ipcp);
                break;
        case IRM_MSG_CODE__IPCP_CREATE_R:
                ipcp = ipcp_info_msg_to_s(msg->ipcp_info);
                res = create_ipcp_r(&ipcp);
                break;
        case IRM_MSG_CODE__IRM_DESTROY_IPCP:
                res = destroy_ipcp(msg->pid);
                break;
        case IRM_MSG_CODE__IRM_BOOTSTRAP_IPCP:
                conf = ipcp_config_msg_to_s(msg->conf);
                res = bootstrap_ipcp(msg->pid, &conf);
                break;
        case IRM_MSG_CODE__IRM_ENROLL_IPCP:
                if (msg->peer != NULL) {
                        poa_addr = poa_addr_msg_to_s(msg->peer);
                        if (poa_addr.type == POA_INVALID) {
                                res = -EINVAL;
                                break;
                        }
                }

                if (msg->conf != NULL)
                        conf = ipcp_config_msg_to_s(msg->conf);
                res = enroll_ipcp_resolve(msg->pid, msg->dst,
                                          msg->peer != NULL ? &poa_addr : NULL);
                break;
        case IRM_MSG_CODE__IRM_ATTACH_IPCP:
                poa_spec = poa_spec_msg_to_s(msg->poa);
                if (poa_spec.type == POA_INVALID) {
                        res = -EINVAL;
                        break;
                }

                res = attach_ipcp(msg->pid, &poa_spec, true);
                break;
        case IRM_MSG_CODE__IRM_DETACH_IPCP:
                poa_spec = poa_spec_msg_to_s(msg->poa);
                if (poa_spec.type == POA_INVALID) {
                        res = -EINVAL;
                        break;
                }

                res = attach_ipcp(msg->pid, &poa_spec, false);
                break;
        case IRM_MSG_CODE__IRM_LIST_POAS:
                res = list_poas(msg->pid, &eps);
                if (res > 0) {
                        ssize_t i;
                        ret_msg->poas = malloc(res * sizeof(*ret_msg->poas));
                        if (ret_msg->poas == NULL) {
                                free(eps);

                                res = -ENOMEM;
                                break;
                        }
                        for (i = 0; i < res; i++) {
                                ret_msg->poas[i] = poa_spec_s_to_msg(&eps[i]);
                                if (ret_msg->poas[i] == NULL)
                                        break;
                                ret_msg->n_poas++;
                        }
                        res = i == res ? 0 : -ENOMEM;
                }
                free(eps);
                break;
        case IRM_MSG_CODE__IRM_SET_IPCP_FLAGS:
                res = set_ipcp_flags(msg->pid, msg->flags, msg->mask);
                break;
        case IRM_MSG_CODE__IRM_CONNECT_IPCP:
                flow.qs = qos_spec_msg_to_s(msg->qosspec);

                pa = NULL;

                if (msg->peer != NULL) {
                        poa_addr = poa_addr_msg_to_s(msg->peer);
                        if (poa_addr.type == POA_INVALID) {
                                res = -EINVAL;
                                break;
                        }
                        pa       = &poa_addr;
                }

                res = connect_ipcp_resolve(msg->pid, msg->dst, msg->comp,
                                           flow.qs, pa);
                break;
        case IRM_MSG_CODE__IRM_DISCONNECT_IPCP:
                res = disconnect_ipcp(msg->pid, msg->dst, msg->comp);
                break;
        case IRM_MSG_CODE__IRM_BIND_PROGRAM:
                /* Terminate with NULL instead of "" */
                free(msg->exec[msg->n_exec - 1]);
                msg->exec[msg->n_exec - 1] = NULL;
                res = bind_program(msg->exec, msg->name, msg->opts);
                break;
        case IRM_MSG_CODE__IRM_UNBIND_PROGRAM:
                res = unbind_program(msg->prog, msg->name);
                break;
        case IRM_MSG_CODE__IRM_PROC_ANNOUNCE:
                proc.pid  = msg->pid;
                strcpy(proc.prog, msg->prog);
                res = get_peer_ids(fd, &proc.uid, &proc.gid, NULL);
                if (res < 0)
                        log_err("Failed to get UID/GID for pid %d.", msg->pid);
                else
                        res = proc_announce(&proc);
                break;
        case IRM_MSG_CODE__IRM_PROC_EXIT:
                res = proc_exit(msg->pid);
                break;
        case IRM_MSG_CODE__IRM_BIND_PROCESS:
                res = bind_process(msg->pid, msg->name);
                break;
        case IRM_MSG_CODE__IRM_UNBIND_PROCESS:
                res = unbind_process(msg->pid, msg->name);
                break;
        case IRM_MSG_CODE__IRM_LIST_IPCPS:
                res = list_ipcps(&ret_msg->ipcps, &ret_msg->n_ipcps);
                break;
        case IRM_MSG_CODE__IRM_CREATE_NAME:
                name = name_info_msg_to_s(msg->name_info);
                res = name_create(&name);
                break;
        case IRM_MSG_CODE__IRM_DESTROY_NAME:
                res = name_destroy(msg->name);
                break;
        case IRM_MSG_CODE__IRM_LIST_NAMES:
                res = list_names(&ret_msg->names, &ret_msg->n_names);
                break;
        case IRM_MSG_CODE__IRM_REG_NAME:
                res = name_reg(msg->name, msg->pid);
                break;
        case IRM_MSG_CODE__IRM_UNREG_NAME:
                res = name_unreg(msg->name, msg->pid);
                break;
        case IRM_MSG_CODE__IRM_FLOW_ACCEPT:
                tpm_wait_work(irmd.tpm);
                data.len  = msg->pk.len;
                data.data = msg->pk.data;
                msg->has_pk = false;
                assert(data.len > 0 ? data.data != NULL : data.data == NULL);
                flow = flow_info_msg_to_s(msg->flow_info);
                sk.key = kbuf;
                res = flow_accept(&flow, &data, abstime, &sk);
                if (res != 0)
                        break;

                ret_msg->flow_info      = flow_info_s_to_msg(&flow);
                ret_msg->has_pk         = data.len != 0;
                ret_msg->pk.data        = data.data;
                ret_msg->pk.len         = data.len;
                ret_msg->has_cipher_nid = true;
                ret_msg->cipher_nid     = sk.nid;
                if (sk.nid == NID_undef)
                        break;

                hbuf = malloc(SYMMKEYSZ);
                if (hbuf == NULL) {
                        log_err("Failed to malloc key buf");
                        res = -ENOMEM;
                        break;
                }

                memcpy(hbuf, kbuf, SYMMKEYSZ);
                ret_msg->sym_key.data = hbuf;
                ret_msg->sym_key.len  = SYMMKEYSZ;
                ret_msg->has_sym_key  = true;
                break;
        case IRM_MSG_CODE__IRM_FLOW_ALLOC:
                data.len  = msg->pk.len;
                data.data = msg->pk.data;
                msg->has_pk = false;
                assert(data.len > 0 ? data.data != NULL : data.data == NULL);
                flow = flow_info_msg_to_s(msg->flow_info);
                abstime = abstime == NULL ? &max : abstime;
                sk.key = kbuf;
                res = flow_alloc(msg->dst, &flow, &data, abstime, &sk);
                if (res != 0)
                        break;

                ret_msg->flow_info      = flow_info_s_to_msg(&flow);
                ret_msg->has_pk         = data.len != 0;
                ret_msg->pk.data        = data.data;
                ret_msg->pk.len         = data.len;
                ret_msg->has_cipher_nid = true;
                ret_msg->cipher_nid     = sk.nid;
                if (sk.nid == NID_undef)
                        break;

                hbuf = malloc(SYMMKEYSZ);
                if (hbuf == NULL) {
                        log_err("Failed to malloc key buf");
                        res = -ENOMEM;
                        break;
                }

                memcpy(hbuf, kbuf, SYMMKEYSZ);
                ret_msg->sym_key.data = hbuf;
                ret_msg->sym_key.len  = SYMMKEYSZ;
                ret_msg->has_sym_key  = true;
                break;
        case IRM_MSG_CODE__IRM_FLOW_JOIN:
                assert(msg->pk.len == 0 && msg->pk.data == NULL);
                flow = flow_info_msg_to_s(msg->flow_info);
                abstime = abstime == NULL ? &max : abstime;
                res = flow_join(&flow, msg->dst, abstime);
                if (res == 0)
                        ret_msg->flow_info = flow_info_s_to_msg(&flow);
                break;
        case IRM_MSG_CODE__IRM_FLOW_DEALLOC:
                flow = flow_info_msg_to_s(msg->flow_info);
                ts = timespec_msg_to_s(msg->timeo);
                res = flow_dealloc(&flow, &ts);
                break;
        case IRM_MSG_CODE__IPCP_FLOW_DEALLOC:
                flow = flow_info_msg_to_s(msg->flow_info);
                res = flow_dealloc_resp(&flow);
                break;
        case IRM_MSG_CODE__IPCP_FLOW_REQ_ARR:
                data.len  = msg->pk.len;
                data.data = msg->pk.data;
                msg->pk.data = NULL; /* pass data */
                msg->pk.len  = 0;
                assert(data.len > 0 ? data.data != NULL : data.data == NULL);
                flow = flow_info_msg_to_s(msg->flow_info);
                res = flow_req_arr(&flow, msg->hash.data, &data);
                if (res == 0)
                        ret_msg->flow_info = flow_info_s_to_msg(&flow);
                break;
        case IRM_MSG_CODE__IRM_POA_FLOW_ALLOC:
                flow = flow_info_msg_to_s(msg->flow_info);

                clrbuf(data);

                res = poa_alloc(&flow, msg->dst, &data);
                if (res == 0) {
                        ret_msg->flow_info = flow_info_s_to_msg(&flow);
                        ret_msg->has_pk    = true;
                        ret_msg->pk.len    = data.len;
                        ret_msg->pk.data   = data.data;

                        clrbuf(data);
                }
                break;
        case IRM_MSG_CODE__IRM_POA_FLOW_ALLOC_R:
                data.len     = msg->pk.len;
                data.data    = msg->pk.data;
                msg->pk.data = NULL; /* pass data */
                msg->pk.len  = 0;
                flow = flow_info_msg_to_s(msg->flow_info);
                sk.key = kbuf;
                res = poa_complete(&flow, msg->response, &data, &sk);

                freebuf(data);

                if (res != 0)
                        break;

                ret_msg->flow_info      = flow_info_s_to_msg(&flow);
                ret_msg->has_cipher_nid = true;
                ret_msg->cipher_nid     = sk.nid;

                if (sk.nid == NID_undef)
                        break;

                hbuf = malloc(SYMMKEYSZ);
                if (hbuf == NULL) {
                        log_err("Failed to malloc key buf");

                        res = -ENOMEM;
                        break;
                }

                memcpy(hbuf, kbuf, SYMMKEYSZ);

                ret_msg->sym_key.data = hbuf;
                ret_msg->sym_key.len  = SYMMKEYSZ;
                ret_msg->has_sym_key  = true;
                break;
        case IRM_MSG_CODE__IPCP_POA_FLOW_REQ_ARR:
                data.len     = msg->pk.len;
                data.data    = msg->pk.data;
                msg->pk.data = NULL; /* pass data */
                msg->pk.len  = 0;
                flow = flow_info_msg_to_s(msg->flow_info);

                res = poa_req_arr(&flow, &data);
                if (res == 0)
                        ret_msg->flow_info = flow_info_s_to_msg(&flow);
                break;
        case IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY:
                data.len  = msg->pk.len;
                data.data = msg->pk.data;
                msg->pk.data = NULL; /* pass data */
                msg->pk.len  = 0;
                assert(data.len > 0 ? data.data != NULL : data.data == NULL);
                flow = flow_info_msg_to_s(msg->flow_info);
                res = flow_alloc_reply(&flow, msg->response, &data);
                break;
        case IRM_MSG_CODE__IPCP_FLOW_UPDATE_ARR:
                data.len  = msg->pk.len;
                data.data = msg->pk.data;
                msg->pk.data = NULL; /* pass data */
                msg->pk.len  = 0;
                flow = flow_info_msg_to_s(msg->flow_info);
                res = flow_update_arr(&flow, &data);
                freebuf(data);
                break;
        case IRM_MSG_CODE__IRM_FLOW_UPDATE:
                flow = flow_info_msg_to_s(msg->flow_info);
                if (get_peer_ids(fd, &uid, &gid, &cpid) < 0) {
                        res = -EPERM;
                        break;
                }

                if (cpid <= 0) /* non-Linux: fall back to asserted pid */
                        cpid = flow.n_pid;

                sk.key = kbuf;
                res = flow_update(&flow, uid, cpid, msg->rekey, &sk, &has_key,
                                  &initiator);
                if (res != 0)
                        break;

                ret_msg->flow_info = flow_info_s_to_msg(&flow);
                if (!has_key)
                        break;

                hbuf = malloc(SYMMKEYSZ);
                if (hbuf == NULL) {
                        log_err("Failed to malloc key buf");
                        res = -ENOMEM;
                        break;
                }

                memcpy(hbuf, kbuf, SYMMKEYSZ);
                ret_msg->sym_key.data   = hbuf;
                ret_msg->sym_key.len    = SYMMKEYSZ;
                ret_msg->has_sym_key    = true;
                ret_msg->has_generation = true;
                ret_msg->generation     = sk.epoch;
                ret_msg->has_rk_initiator = true;
                ret_msg->rk_initiator     = initiator;
                break;
        default:
                log_err("Don't know that message code.");
                res = -1;
                break;
        }

        pthread_cleanup_pop(false);

        ret_msg->has_result = true;
        if (abstime == &max && res == -ETIMEDOUT)
                ret_msg->result = -EPERM; /* No timeout requested */
        else
                ret_msg->result = res;

        crypt_secure_clear(kbuf, SYMMKEYSZ);

        return ret_msg;
}

/* Wipe the session key from a reply before its buffers are freed. */
static void clear_msg_key(irm_msg_t * msg)
{
        if (msg != NULL && msg->has_sym_key)
                crypt_secure_clear(msg->sym_key.data, msg->sym_key.len);
}

static void * mainloop(void * o)
{
        int         sfd;
        irm_msg_t * msg;
        buffer_t    buffer;

        (void) o;

        while (true) {
                irm_msg_t *  ret_msg;
                struct cmd * cmd;
                bool         had_key;

                pthread_mutex_lock(&irmd.cmd_lock);

                pthread_cleanup_push(__cleanup_mutex_unlock, &irmd.cmd_lock);

                while (list_is_empty(&irmd.cmds))
                        pthread_cond_wait(&irmd.cmd_cond, &irmd.cmd_lock);

                cmd = list_last_entry(&irmd.cmds, struct cmd, next);
                list_del(&cmd->next);

                pthread_cleanup_pop(true);

                msg = irm_msg__unpack(NULL, cmd->len, cmd->cbuf);
                sfd = cmd->fd;

                free(cmd);

                if (msg == NULL) {
                        log_err("Failed to unpack command message.");
                        close(sfd);
                        continue;
                }

                tpm_begin_work(irmd.tpm);

                pthread_cleanup_push(__cleanup_close_ptr, &sfd);
                pthread_cleanup_push(__cleanup_irm_msg, msg);

                ret_msg = do_command_msg(msg, sfd);

                pthread_cleanup_pop(true);
                pthread_cleanup_pop(false);

                if (ret_msg == NULL) {
                        log_err("Failed to create return message.");
                        goto fail_msg;
                }

                if (ret_msg->result == -EPIPE) {
                        log_dbg("Terminated command: remote closed socket.");
                        goto fail;
                }

                if (ret_msg->result == -EIRMD) {
                        log_dbg("Terminated command: IRMd not running.");
                        goto fail;
                }

                buffer.len = irm_msg__get_packed_size(ret_msg);
                if (buffer.len == 0) {
                        log_err("Failed to calculate length of reply message.");
                        goto fail;
                }

                buffer.data = malloc(buffer.len);
                if (buffer.data == NULL) {
                        log_err("Failed to malloc buffer.");
                        goto fail;
                }

                irm_msg__pack(ret_msg, buffer.data);

                had_key = ret_msg->has_sym_key;
                clear_msg_key(ret_msg);

                irm_msg__free_unpacked(ret_msg, NULL);

                pthread_cleanup_push(__cleanup_close_ptr, &sfd);
                pthread_cleanup_push(free, buffer.data);

                if (write(sfd, buffer.data, buffer.len) == -1) {
                        if (errno != EPIPE)
                                log_warn("Failed to send reply message: %s.",
                                         strerror(errno));
                        else
                                log_dbg("Failed to send reply message: %s.",
                                        strerror(errno));
                }

                if (had_key)
                        crypt_secure_clear(buffer.data, buffer.len);

                pthread_cleanup_pop(true);
                pthread_cleanup_pop(true);

                tpm_end_work(irmd.tpm);

                continue;
 fail:
                clear_msg_key(ret_msg);
                irm_msg__free_unpacked(ret_msg, NULL);
 fail_msg:
                close(sfd);
                tpm_end_work(irmd.tpm);
                continue;
        }

        return (void *) 0;
}

#ifdef HAVE_FUSE
static void destroy_mount(char * mnt)
{
        struct stat st;

        if (stat(mnt, &st) == -1){
                switch(errno) {
                case ENOENT:
                        log_dbg("Fuse mountpoint %s not found: %s",
                                mnt, strerror(errno));
                        break;
                case ENOTCONN:
                        /* FALLTHRU */
                case ECONNABORTED:
                        log_dbg("Cleaning up fuse mountpoint %s.",
                                mnt);
                        rib_cleanup(mnt);
                        break;
                default:
                        log_err("Unhandled fuse error on mnt %s: %s.",
                                mnt, strerror(errno));
                }
        }
}
#endif

static int ouroboros_reset(void)
{
        ssm_pool_gspp_purge();
        lockfile_destroy(irmd.lf);

        return 0;
}

static void cleanup_pid(pid_t pid)
{
#ifdef HAVE_FUSE
        char mnt[RIB_PATH_LEN + 1];

        if (reg_has_ipcp(pid)) {
                struct ipcp_info info;
                info.pid = pid;
                reg_get_ipcp(&info, NULL);
                sprintf(mnt, FUSE_PREFIX "/%s", info.name);
        } else {
                sprintf(mnt, FUSE_PREFIX "/proc.%d", pid);
        }

        destroy_mount(mnt);
#endif
        ssm_pool_reclaim_orphans(irmd.gspp, pid);
}

void * irm_sanitize(void * o)
{
        pid_t           pid;
        struct timespec ts = TIMESPEC_INIT_MS(FLOW_ALLOC_TIMEOUT / 20);

        (void) o;

        while (true) {
                while((pid = reg_get_dead_proc()) != -1) {
                        log_info("Process %d died.", pid);
                        cleanup_pid(pid);
                        reg_destroy_proc(pid);
                }

                nanosleep(&ts, NULL);
        }

        return (void *) 0;
}

static int irm_load_store(char * dpath,
                          bool   anchor)
{
        struct stat     st;
        struct dirent * dent;
        DIR *           dir;
        void *          crt;
        int             ret;

        if (stat(dpath, &st) == -1) {
                log_dbg("Store directory %s not found.", dpath);
                return 0;
        }

        if (!S_ISDIR(st.st_mode)) {
                log_err("%s is not a directory.", dpath);
                goto fail_dir;
        }

        /* loop through files in directory and load certificates */
        dir = opendir(dpath);
        if (dir == NULL) {
                log_err("Failed to open %s.", dpath);
                goto fail_dir;
        }

        while ((dent = readdir(dir)) != NULL) {
                char   path[NAME_PATH_SIZE + 1];

                if (strcmp(dent->d_name, ".") == 0 ||
                    strcmp(dent->d_name, "..") == 0)
                        continue;

                snprintf(path, sizeof(path), "%s/%s", dpath,
                         dent->d_name);

                if (stat(path, &st) == -1) {
                        log_dbg("Failed to stat %s.", path);
                        continue;
                }

                if (!S_ISREG(st.st_mode)) {
                        log_dbg("%s is not a regular file.", path);
                        goto fail_file;
                }

                if (crypt_load_crt_file(path, &crt) < 0) {
                        log_err("Failed to load certificate from %s.", path);
                        goto fail_file;
                }

                ret = anchor ? oap_auth_add_ca_crt(crt)
                             : oap_auth_add_chain_crt(crt);
                if (ret < 0) {
                        log_err("Failed to add certificate from %s to store.",
                                path);
                        goto fail_crt_add;
                }

                log_dbg("Loaded certificate: %s.", path);

                crypt_free_crt(crt);
        }

        closedir(dir);

        log_info("Loaded certificates from %s.", dpath);

        return 0;

 fail_crt_add:
        crypt_free_crt(crt);
 fail_file:
        closedir(dir);
 fail_dir:
        return -1;
}

static int irm_init(void)
{
        struct stat        st;
        struct group *     grp;
        gid_t              gid;
        pthread_condattr_t cattr;
#ifdef HAVE_FUSE
        mode_t             mask;
#endif
        memset(&st, 0, sizeof(st));

        log_init(!irmd.log_stdout);

        irmd.lf = lockfile_create();
        if (irmd.lf == NULL) {
                irmd.lf = lockfile_open();
                if (irmd.lf == NULL) {
                        log_err("Lockfile error.");
                        goto fail_lockfile;
                }

                if (kill(lockfile_owner(irmd.lf), 0) < 0) {
                        log_warn("IRMd didn't properly shut down last time.");
                        if (ouroboros_reset() < 0) {
                                log_err("Failed to clean stale resources.");
                                lockfile_close(irmd.lf);
                                goto fail_lockfile;
                        }

                        log_warn("Stale resources cleaned.");
                        irmd.lf = lockfile_create();
                } else {
                        log_warn("IRMd already running (%d), exiting.",
                                 lockfile_owner(irmd.lf));
                        lockfile_close(irmd.lf);
                        goto fail_lockfile;
                }
        }

        if (irmd.lf == NULL) {
                log_err("Failed to create lockfile.");
                goto fail_lockfile;
        }

        if (pthread_rwlock_init(&irmd.state_lock, NULL)) {
                log_err("Failed to initialize rwlock.");
                goto fail_state_lock;
        }

        if (pthread_mutex_init(&irmd.cmd_lock, NULL)) {
                log_err("Failed to initialize mutex.");
                goto fail_cmd_lock;
        }

        if (pthread_condattr_init(&cattr)) {
                log_err("Failed to initialize mutex.");
                goto fail_cmd_lock;
        }

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&irmd.cmd_cond, &cattr)) {
                log_err("Failed to initialize condvar.");
                pthread_condattr_destroy(&cattr);
                goto fail_cmd_cond;
        }

        pthread_condattr_destroy(&cattr);

        list_head_init(&irmd.cmds);

        if (pthread_mutex_init(&irmd.rk.mtx, NULL)) {
                log_err("Failed to initialize mutex.");
                goto fail_rk_mtx;
        }

        if (pthread_condattr_init(&cattr)) {
                log_err("Failed to initialize condattr.");
                goto fail_rk_mtx;
        }

#ifndef __APPLE__
        pthread_condattr_setclock(&cattr, PTHREAD_COND_CLOCK);
#endif
        if (pthread_cond_init(&irmd.rk.cond, &cattr)) {
                log_err("Failed to initialize condvar.");
                pthread_condattr_destroy(&cattr);
                goto fail_rk_cond;
        }

        pthread_condattr_destroy(&cattr);

        list_head_init(&irmd.rk.inbox);

        if (stat(SOCK_PATH, &st) == -1) {
                if (mkdir(SOCK_PATH, 0777)) {
                        log_err("Failed to create sockets directory.");
                        goto fail_stat;
                }
        }

        irmd.sockfd = server_socket_open(IRM_SOCK_PATH);
        if (irmd.sockfd < 0) {
                log_err("Failed to open server socket.");
                goto fail_sock_path;
        }

        if (chmod(IRM_SOCK_PATH, 0666)) {
                log_err("Failed to chmod socket.");
                goto fail_sock_path;
        }

        grp = getgrnam("ouroboros");
        if (grp == NULL) {
                log_warn("ouroboros group not found, using gid %d.", getgid());
                gid = getgid();
        } else {
                gid = grp->gr_gid;
        }

        irmd.gspp = ssm_pool_create(getuid(), gid);
        if (irmd.gspp == NULL) {
                log_err("Failed to create GSPP.");
                goto fail_pool;
        }

        if (ssm_pool_mlock(irmd.gspp) < 0)
                log_warn("Failed to mlock pool.");

        irmd.tpm = tpm_create(IRMD_MIN_THREADS, IRMD_ADD_THREADS,
                              mainloop, NULL);
        if (irmd.tpm == NULL) {
                log_err("Failed to greate thread pool.");
                goto fail_tpm_create;
        }

        if (oap_auth_init() < 0) {
                log_err("Failed to initialize OAP module.");
                goto fail_oap;
        }

        if (irm_load_store(OUROBOROS_CA_CRT_DIR, true) < 0) {
                log_err("Failed to load CA certificates.");
                goto fail_load_store;
        }

        if (irm_load_store(OUROBOROS_CHAIN_DIR, false) < 0) {
                log_err("Failed to load intermediate certificates.");
                goto fail_load_store;
        }

#ifdef HAVE_FUSE
        mask = umask(0);

        if (stat(FUSE_PREFIX, &st) != -1)
                log_warn(FUSE_PREFIX " already exists...");
        else
                mkdir(FUSE_PREFIX, 0777);

        umask(mask);
#endif

#ifdef HAVE_LIBGCRYPT
        if (!gcry_check_version(GCRYPT_VERSION)) {
                log_err("Error checking libgcrypt version.");
                goto fail_gcry_version;
        }

        if (!gcry_control(GCRYCTL_ANY_INITIALIZATION_P)) {
                log_err("Libgcrypt was not initialized.");
                goto fail_gcry_version;
        }

        gcry_control(GCRYCTL_INITIALIZATION_FINISHED);
#endif

        irmd_set_state(IRMD_INIT);

        return 0;

#ifdef HAVE_LIBGCRYPT
 fail_gcry_version:
 #ifdef HAVE_FUSE
        rmdir(FUSE_PREFIX);
 #endif
#endif
 fail_load_store:
        oap_auth_fini();
 fail_oap:
        tpm_destroy(irmd.tpm);
 fail_tpm_create:
        ssm_pool_destroy(irmd.gspp);
 fail_pool:
        close(irmd.sockfd);
 fail_sock_path:
        unlink(IRM_SOCK_PATH);
 fail_stat:
        pthread_cond_destroy(&irmd.rk.cond);
 fail_rk_cond:
        pthread_mutex_destroy(&irmd.rk.mtx);
 fail_rk_mtx:
        pthread_cond_destroy(&irmd.cmd_cond);
 fail_cmd_cond:
        pthread_mutex_destroy(&irmd.cmd_lock);
 fail_cmd_lock:
        pthread_rwlock_destroy(&irmd.state_lock);
 fail_state_lock:
        lockfile_destroy(irmd.lf);
 fail_lockfile:
        log_fini();
        return -1;
}

static void irm_fini(void)
{
        struct list_head * p;
        struct list_head * h;
#ifdef HAVE_FUSE
        struct timespec wait = TIMESPEC_INIT_MS(1);
        int    retries = 5;
#endif
        if (irmd_get_state() != IRMD_INIT)
                log_warn("Unsafe destroy.");

        oap_auth_fini();

        tpm_destroy(irmd.tpm);

        close(irmd.sockfd);

        if (unlink(IRM_SOCK_PATH))
                log_dbg("Failed to unlink %s.", IRM_SOCK_PATH);

        ssm_pool_destroy(irmd.gspp);

        if (irmd.lf != NULL)
                lockfile_destroy(irmd.lf);

        pthread_mutex_lock(&irmd.cmd_lock);

        list_for_each_safe(p, h, &irmd.cmds) {
                struct cmd * cmd = list_entry(p, struct cmd, next);
                list_del(&cmd->next);
                close(cmd->fd);
                free(cmd);
        }

        pthread_mutex_unlock(&irmd.cmd_lock);

        pthread_mutex_lock(&irmd.rk.mtx);

        list_for_each_safe(p, h, &irmd.rk.inbox) {
                struct rekey_evt * evt;
                evt = list_entry(p, struct rekey_evt, next);
                list_del(&evt->next);
                freebuf(evt->buf);
                free(evt);
        }

        pthread_mutex_unlock(&irmd.rk.mtx);

        pthread_mutex_destroy(&irmd.cmd_lock);
        pthread_cond_destroy(&irmd.cmd_cond);
        pthread_mutex_destroy(&irmd.rk.mtx);
        pthread_cond_destroy(&irmd.rk.cond);
        pthread_rwlock_destroy(&irmd.state_lock);

#ifdef HAVE_FUSE
        while (rmdir(FUSE_PREFIX) < 0 && retries-- > 0)
                nanosleep(&wait, NULL);

        if (retries < 0)
                log_err("Failed to remove " FUSE_PREFIX);
#endif
        assert(list_is_empty(&irmd.cmds));

        irmd.state = IRMD_NULL;
}

static void usage(void)
{
        printf("Usage: irmd \n"
#ifdef HAVE_TOML
               "         [--config <path> (Path to configuration file)]\n"
#endif
               "         [--stdout  (Log to stdout instead of system log)]\n"
               "         [--version (Print version number and exit)]\n"
               "\n");
}

static int irm_start(void)
{
        irmd_set_state(IRMD_RUNNING);

        if (tpm_start(irmd.tpm))
                goto fail_tpm_start;

        if (pthread_create(&irmd.irm_sanitize, NULL, irm_sanitize, NULL))
                goto fail_irm_sanitize;

        if (pthread_create(&irmd.acceptor, NULL, acceptloop, NULL))
                goto fail_acceptor;

        if (OAP_REKEY_TIMER > 0) {
                if (pthread_create(&irmd.rk.worker, NULL, rekey_worker, NULL))
                        goto fail_rekey_worker;
        }

        log_info("Ouroboros IPC Resource Manager daemon started...");

        return 0;

 fail_rekey_worker:
        pthread_cancel(irmd.acceptor);
        pthread_join(irmd.acceptor, NULL);
 fail_acceptor:
        pthread_cancel(irmd.irm_sanitize);
        pthread_join(irmd.irm_sanitize, NULL);
 fail_irm_sanitize:
        tpm_stop(irmd.tpm);
 fail_tpm_start:
        irmd_set_state(IRMD_INIT);
        return -1;
}

static void irm_sigwait(sigset_t sigset)
{
        int sig;

        while (irmd_get_state() != IRMD_SHUTDOWN) {
                if (sigwait(&sigset, &sig) != 0) {
                        log_warn("Bad signal.");
                        continue;
                }

                switch(sig) {
                case SIGINT:
                case SIGQUIT:
                case SIGTERM:
                case SIGHUP:
                        log_info("IRMd shutting down...");
                        irmd_set_state(IRMD_SHUTDOWN);
                        break;
                case SIGPIPE:
                        log_dbg("Ignored SIGPIPE.");
                        break;
                default:
                        break;
                }
        }
}

static void irm_stop(void)
{
        if (OAP_REKEY_TIMER > 0) {
                pthread_cancel(irmd.rk.worker);
                pthread_join(irmd.rk.worker, NULL);
        }

        pthread_cancel(irmd.acceptor);
        pthread_cancel(irmd.irm_sanitize);

        pthread_join(irmd.acceptor, NULL);
        pthread_join(irmd.irm_sanitize, NULL);

        tpm_stop(irmd.tpm);

        irmd_set_state(IRMD_INIT);
}

static void irm_argparse(int     argc,
                         char ** argv)
{
#ifdef HAVE_TOML
        irmd.cfg_file = NULL;
#endif
        argc--;
        argv++;
        while (argc > 0) {
                if (strcmp(*argv, "--stdout") == 0) {
                        irmd.log_stdout = true;
                        argc--;
                        argv++;
                } else if (strcmp(*argv, "--version") == 0) {
                        printf("Ouroboros version %s\n",
                               OUROBOROS_VERSION_STRING);
                        exit(EXIT_SUCCESS);
#ifdef HAVE_TOML
                } else if (strcmp (*argv, "--config") == 0) {
                        irmd.cfg_file = *(argv + 1);
                        argc -= 2;
                        argv += 2;
#endif
                } else {
                        usage();
                        exit(EXIT_FAILURE);
                }
        }
}

static void * kill_dash_nine(void * o)
{
        time_t slept = 0;
#ifdef IRMD_KILL_ALL_PROCESSES
        struct timespec ts = TIMESPEC_INIT_MS(FLOW_ALLOC_TIMEOUT / 19);
#endif
        (void) o;

        while (slept < IRMD_PKILL_TIMEOUT) {
                time_t intv = 1;
                if (reg_first_spawned() == -1)
                        goto finish;
                sleep(intv);
                slept += intv;
        }

        log_dbg("I guess I’ll have to shut you down for good this time,");
        log_dbg("already tried a SIGQUIT, so now it’s KILL DASH 9.");
#ifdef IRMD_KILL_ALL_PROCESSES
        reg_kill_all_proc(SIGKILL);
        nanosleep(&ts, NULL);
#else
        reg_kill_all_spawned(SIGKILL);
#endif
 finish:
        return (void *) 0;
}

static void kill_all_spawned(void)
{
        pid_t     pid;
        pthread_t grimreaper;

#ifdef IRMD_KILL_ALL_PROCESSES
        reg_kill_all_proc(SIGTERM);
#else
        reg_kill_all_spawned(SIGTERM);
#endif
        pthread_create(&grimreaper, NULL, kill_dash_nine, NULL);

        pid = reg_first_spawned();
        while (pid != -1) {
                int s;
                if (kill(pid, 0) == 0)
                        waitpid(pid, &s, 0);
                else {
                        log_warn("Child process %d died.", pid);
                        cleanup_pid(pid);
                        reg_destroy_proc(pid);
                }
                pid = reg_first_spawned();
        }

        pthread_join(grimreaper, NULL);
}

int main(int     argc,
         char ** argv)
{
        sigset_t sigset;
        int      ret = EXIT_SUCCESS;

        sigemptyset(&sigset);
        sigaddset(&sigset, SIGINT);
        sigaddset(&sigset, SIGQUIT);
        sigaddset(&sigset, SIGHUP);
        sigaddset(&sigset, SIGTERM);
        sigaddset(&sigset, SIGPIPE);

        irm_argparse(argc, argv);

        if (irmd.log_stdout)
                printf(O7S_ASCII_ART);

        if (geteuid() != 0) {
                printf("IPC Resource Manager must be run as root.\n");
                goto fail_irm_init;
        }

        if (crypt_secure_malloc_init(IRMD_SECMEM_MAX) < 0) {
                log_err("Failed to initialize secure memory allocation.");
                goto fail_secmem;
        }

        if (irm_init() < 0) {
                log_err("Failed to initialize IRMd.");
                goto fail_irm_init;
        }

        if (reg_init() < 0) {
                log_err("Failed to initialize registry.");
                goto fail_reg;
        }

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (irm_start() < 0) {
                log_err("Failed to start IRMd.");
                goto fail_irm_start;
        }

#ifdef HAVE_TOML
        if (irm_configure(irmd.cfg_file) < 0) {
                log_err("Failed to load IRMd configuration.");
                irmd_set_state(IRMD_SHUTDOWN);
                ret = EXIT_FAILURE;
        }
#endif
        irm_sigwait(sigset);

        kill_all_spawned();

        irm_stop();

        pthread_sigmask(SIG_UNBLOCK, &sigset, NULL);

        reg_clear();

        reg_fini();

        irm_fini();

        crypt_secure_malloc_fini();

        crypt_cleanup();

        log_info("Ouroboros IPC Resource Manager daemon exited. Bye.");

        log_fini();

        exit(ret);

 fail_irm_start:
        reg_fini();
 fail_reg:
        irm_fini();
 fail_irm_init:
        crypt_secure_malloc_fini();
        crypt_cleanup();
 fail_secmem:
        exit(EXIT_FAILURE);
}
