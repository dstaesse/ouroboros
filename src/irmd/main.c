/*
 * Ouroboros - Copyright (C) 2016 - 2024
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
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include "config.h"

#define OUROBOROS_PREFIX "irmd"

#include <ouroboros/bitmap.h>
#include <ouroboros/crypt.h>
#include <ouroboros/errno.h>
#include <ouroboros/flow.h>
#include <ouroboros/hash.h>
#include <ouroboros/irm.h>
#include <ouroboros/list.h>
#include <ouroboros/lockfile.h>
#include <ouroboros/logs.h>
#include <ouroboros/pthread.h>
#include <ouroboros/random.h>
#include <ouroboros/rib.h>
#include <ouroboros/shm_rdrbuff.h>
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

#include <sys/socket.h>
#include <sys/un.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <spawn.h>

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif

#define IRMD_CLEANUP_TIMER ((IRMD_FLOW_TIMEOUT / 20) * MILLION) /* ns */
#define SHM_SAN_HOLDOFF    1000 /* ms */
#define IPCP_HASH_LEN(p)   hash_len((p)->dir_hash_algo)
#define BIND_TIMEOUT       10   /* ms */
#define TIMESYNC_SLACK     100  /* ms */
#define DEALLOC_TIME       300  /*  s */

enum irm_state {
        IRMD_NULL = 0,
        IRMD_RUNNING,
        IRMD_SHUTDOWN
};

struct cmd {
        struct list_head next;

        uint8_t          cbuf[SOCK_BUF_SIZE];
        size_t           len;
        int              fd;
};

struct {
        bool                 log_stdout;   /* log to stdout              */
#ifdef HAVE_TOML
        char *               cfg_file;     /* configuration file path    */
#endif
        struct lockfile *    lf;           /* single irmd per system     */
        struct shm_rdrbuff * rdrb;         /* rdrbuff for packets        */

        int                  sockfd;       /* UNIX socket                */

        struct list_head     cmds;         /* pending commands           */
        pthread_cond_t       cmd_cond;     /* cmd signal condvar         */
        pthread_mutex_t      cmd_lock;     /* cmd signal lock            */

        enum irm_state       state;        /* state of the irmd          */
        pthread_rwlock_t     state_lock;   /* lock for the entire irmd   */

        struct tpm *         tpm;          /* thread pool manager        */

        pthread_t            irm_sanitize; /* clean up irmd resources    */
        pthread_t            acceptor;     /* accept new commands        */
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
        case IPCP_UDP:
                exec_name = IPCP_UDP_EXEC;
                break;
        case IPCP_ETH_LLC:
                exec_name = IPCP_ETH_LLC_EXEC;
                break;
        case IPCP_ETH_DIX:
                exec_name = IPCP_ETH_DIX_EXEC;
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
        info->state = IPCP_BOOT;

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

int create_ipcp(struct ipcp_info * info)
{
        struct timespec abstime;
        struct timespec timeo = TIMESPEC_INIT_MS(SOCKET_TIMEOUT);
        int             status;

        assert(info->pid == 0);

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

        log_info("Created IPCP %d.", info->pid);

        return 0;

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

        if (conf->type == IPCP_UDP)
                conf->layer_info.dir_hash_algo = (enum pol_dir_hash) HASH_MD5;

        if (ipcp_bootstrap(pid, conf, &layer)) {
                log_err("Could not bootstrap IPCP.");
                goto fail;
        }

        info.state = IPCP_BOOTSTRAPPED;

        if (reg_set_layer_for_ipcp(&info, &layer) < 0) {
                log_err("Failed to set layer info for IPCP.");
                goto fail;
        }

        log_info("Bootstrapped IPCP %d.", pid);

        return 0;
 fail:
        return -1;
}

int enroll_ipcp(pid_t        pid,
                const char * dst)
{
        struct layer_info layer;
        struct ipcp_info  info;

        info.pid = pid;

        if (reg_get_ipcp(&info, NULL) < 0) {
                log_err("Could not find IPCP.");
                goto fail;
        }

        if (ipcp_enroll(pid, dst, &layer) < 0) {
                log_err("Could not enroll IPCP %d.", pid);
                goto fail;
        }

        if (reg_set_layer_for_ipcp(&info, &layer) < 0) {
                log_err("Failed to set layer info for IPCP.");
                goto fail;
        }

        log_info("Enrolled IPCP %d in layer %s.", pid, layer.name);

        return 0;
 fail:
        return -1;
}

int connect_ipcp(pid_t        pid,
                 const char * dst,
                 const char * component,
                 qosspec_t    qs)
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

        if (ipcp_connect(pid, dst, component, qs)) {
                log_err("Could not connect IPCP %d to %s.", pid, dst);
                return -EPERM;
        }

        log_info("Established %s connection between IPCP %d and %s.",
                 component, pid, dst);

        return 0;
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
                if (reg_create_name(&ni) < 0) {
                        log_err("Failed to create name %s.", name);
                        goto fail_name;
                }
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
                if (reg_create_name(&ni) < 0) {
                        log_err("Failed to create name %s.", name);
                        goto fail;
                }
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
                        return -1;
                }
                log_info("Program %s unbound.", prog);
        } else {
                if (reg_unbind_prog(name, prog) < 0) {
                        log_err("Failed to unbind %s from %s", prog, name);
                        return -1;
                }
                log_info("Name %s unbound for %s.", name, prog);
        }

        return 0;
}

static int unbind_process(pid_t        pid,
                          const char * name)
{
        if (name == NULL) {
                if (reg_destroy_proc(pid) < 0) {
                        log_err("Failed to unbind %d.", pid);
                        return -1;
                }
                log_info("Process %d unbound.", pid);
        } else {
                if (reg_unbind_proc(name, pid) < 0) {
                        log_err("Failed to unbind %d from %s", pid, name);
                        return -1;
                }
                log_info("Name %s unbound for process %d.", name, pid);
        }

        return 0;
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

int name_create(const struct name_info * info)
{
        int ret;

        assert(info != NULL);

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
                freebuf(hash);
                return -1;
        }

        log_info("Registered %s with IPCP %d as " HASH_FMT32 ".",
                 name, pid, HASH_VAL32(hash.data));

        freebuf(hash);

        return 0;
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
                freebuf(hash);
                return -1;
        }

        log_info("Unregistered %s from %d.", name, pid);

        freebuf(hash);

        return 0;
}

static int proc_announce(const struct proc_info * info)
{
        if (reg_create_proc(info) < 0) {
                log_err("Failed to add process %d.", info->pid);
                goto fail_proc;
        }

        log_info("Process added: %d (%s).", info->pid, info->prog);

        return 0;

 fail_proc:
        return -1;
}

static int proc_exit(pid_t pid)
{
        if (reg_destroy_proc(pid) < 0)
                log_err("Failed to remove process %d.", pid);

        log_info("Process removed: %d.", pid);

        return 0;
}

static void __cleanup_pkp(void * pkp)
{
        if (pkp != NULL)
                crypt_dh_pkp_destroy(pkp);
}

static void __cleanup_flow(void * flow)
{
        reg_destroy_flow(((struct flow_info *) flow)->id);
}

static int flow_accept(struct flow_info * flow,
                       buffer_t *         symmkey,
                       buffer_t *         data,
                       struct timespec *  abstime)
{
        struct oap_hdr  oap_hdr;        /* incoming request           */
        struct oap_hdr  r_oap_hdr;      /* outgoing response          */
        uint8_t         buf[MSGBUFSZ];  /* buffer for local ephkey    */
        buffer_t        lpk = BUF_INIT; /* local ephemeral pubkey     */
        ssize_t         delta;          /* allocation time difference */
        int             err;
        struct timespec now;

        /* piggyback of user data not yet implemented */
        assert(data != NULL && data->len == 0 && data->data == NULL);
        assert(symmkey != NULL && symmkey->len == 0 && symmkey->data == NULL);

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

        err = reg_wait_flow_accepted(flow, &oap_hdr.hdr, abstime);

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

        if (oap_hdr_decode(oap_hdr.hdr, &oap_hdr) < 0) {
                log_err("Failed to decode OAP header.");
                err = -EIPCP;
                goto fail_oap_hdr;
        }

        clock_gettime(CLOCK_REALTIME, &now);

        delta = (ssize_t)(TS_TO_UINT64(now) - oap_hdr.timestamp) / MILLION;
        if (delta > flow->mpl)
                log_warn("Flow alloc time exceeds MPL (%zd ms).", delta);

        if (delta < -TIMESYNC_SLACK)
                log_warn("Flow alloc sent from the future (%zd ms).", -delta);

        if (flow->qs.cypher_s != 0) {     /* crypto requested           */
                uint8_t * s;              /* symmetric encryption key   */
                ssize_t   key_len;        /* length of local pubkey     */
                void *    pkp = NULL;     /* ephemeral private key pair */

                s = malloc(SYMMKEYSZ);
                if (s == NULL) {
                        log_err("Failed to malloc symmkey.");
                        err = -ENOMEM;
                        goto fail_keys;
                }

                key_len = crypt_dh_pkp_create(&pkp, buf);
                if (key_len < 0) {
                        free(s);
                        log_err("Failed to generate key pair.");
                        err = -ECRYPT;
                        goto fail_keys;
                }

                lpk.data = buf;
                lpk.len  = (size_t) key_len;

                log_dbg("Generated ephemeral keys for %d.", flow->n_pid);

                if (crypt_dh_derive(pkp, oap_hdr.eph, s) < 0) {
                        log_err("Failed to derive secret for %d.", flow->id);
                        crypt_dh_pkp_destroy(pkp);
                        free(s);
                        err = -ECRYPT;
                        goto fail_derive;
                }

                symmkey->data = s;
                symmkey->len  = SYMMKEYSZ;

                crypt_dh_pkp_destroy(pkp);
        }

        if (oap_hdr_init(oap_hdr.id, NULL, NULL, lpk, *data, &r_oap_hdr) < 0) {
                log_err("Failed to create OAP header.");
                err = -ENOMEM;
                goto fail_r_oap_hdr;
        }

        if (ipcp_flow_alloc_resp(flow, 0, r_oap_hdr.hdr) < 0) {
                log_err("Failed to respond to flow allocation.");
                goto fail_resp;
        }

        oap_hdr_fini(&oap_hdr);
        oap_hdr_fini(&r_oap_hdr);

        return 0;

 fail_r_oap_hdr:
        freebuf(*symmkey);
 fail_derive:
        clrbuf(lpk);
 fail_keys:
        oap_hdr_fini(&oap_hdr);
 fail_oap_hdr:
        assert(lpk.data == NULL && lpk.len == 0);
        ipcp_flow_alloc_resp(flow, err, lpk);
 fail_wait:
        reg_destroy_flow(flow->id);
 fail_flow:
        return err;

 fail_resp:
        flow->state = FLOW_NULL;
        oap_hdr_fini(&r_oap_hdr);
        freebuf(*symmkey);
        clrbuf(lpk);
        oap_hdr_fini(&oap_hdr);
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

        log_info("Allocating flow for %d to %s.", flow->n_pid, dst);

        if (reg_create_flow(flow) < 0) {
                log_err("Failed to create flow.");
                err = -EBADF;
                goto fail_flow;
        }

        strcpy(layer.name, dst);
        if (reg_get_ipcp_by_layer(&ipcp, &layer) < 0) {
                log_err("Failed to get IPCP for layer %s.", dst);
                err = -EIPCP;
                goto fail_ipcp;
        }

        hash.len = hash_len((enum hash_algo) layer.dir_hash_algo);
        hash.data = malloc(hash.len);
        if (hash.data == NULL) {
                log_err("Failed to malloc hash buffer.");
                err = -ENOMEM;
                goto fail_ipcp;
        }

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
        ipcp_list_msg_t ** ipcps;
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

static int flow_alloc(struct flow_info * flow,
                      const char *       dst,
                      buffer_t *         symmkey,
                      buffer_t *         data,
                      struct timespec *  abstime)
{
        struct oap_hdr oap_hdr;        /* outgoing request           */
        struct oap_hdr r_oap_hdr;      /* incoming response          */
        uint8_t        buf[MSGBUFSZ];  /* buffer for local ephkey    */
        buffer_t       lpk = BUF_INIT; /* local ephemeral pubkey     */
        void *         pkp = NULL;     /* ephemeral private key pair */
        uint8_t *      s = NULL;       /* symmetric key              */
        buffer_t       hash;
        uint8_t        idbuf[OAP_ID_SIZE];
        buffer_t       id;
        int            err;

        /* piggyback of user data not yet implemented */
        assert(data != NULL && data->len == 0 && data->data == NULL);
        assert(symmkey != NULL && symmkey->len == 0 && symmkey->data == NULL);

        if (random_buffer(idbuf, OAP_ID_SIZE) < 0) {
                log_err("Failed to generate ID.");
                err = -EIRMD;
                goto fail_id;
        }

        id.data = idbuf;
        id.len  = OAP_ID_SIZE;

        if (flow->qs.cypher_s > 0) {
                ssize_t key_len;

                s = malloc(SYMMKEYSZ);
                if (s == NULL) {
                        log_err("Failed to malloc symmetric key");
                        err = -ENOMEM;
                        goto fail_malloc;
                }

                key_len = crypt_dh_pkp_create(&pkp, buf);
                if (key_len < 0) {
                        log_err("Failed to generate key pair.");
                        err = -ECRYPT;
                        goto fail_pkp;
                }

                lpk.data = buf;
                lpk.len = (size_t) key_len;

                log_dbg("Generated ephemeral keys for %d.", flow->n_pid);
        }

        if (oap_hdr_init(id, NULL, NULL, lpk, *data, &oap_hdr) < 0) {
                log_err("Failed to create OAP header.");
                err = -ENOMEM;
                goto fail_oap_hdr;
        }

        log_info("Allocating flow for %d to %s.", flow->n_pid, dst);

        if (reg_create_flow(flow) < 0) {
                log_err("Failed to create flow.");
                err = -EBADF;
                goto fail_flow;
        }

        if (get_ipcp_by_dst(dst, &flow->n_1_pid, &hash) < 0) {
                log_err("Failed to find IPCP for %s.", dst);
                err = -EIPCP;
                goto fail_ipcp;
        }

        reg_prepare_flow_alloc(flow);

        if (ipcp_flow_alloc(flow, hash, oap_hdr.hdr)) {
                log_err("Flow allocation %d failed.", flow->id);
                err = -ENOTALLOC;
                goto fail_alloc;
        }

        pthread_cleanup_push(__cleanup_flow, flow);
        pthread_cleanup_push(__cleanup_pkp, pkp);
        pthread_cleanup_push(free, hash.data);
        pthread_cleanup_push(free, s);

        err = reg_wait_flow_allocated(flow, &r_oap_hdr.hdr, abstime);

        pthread_cleanup_pop(false);
        pthread_cleanup_pop(false);
        pthread_cleanup_pop(false);
        pthread_cleanup_pop(false);

        if (err == -ETIMEDOUT) {
                log_err("Flow allocation timed out.");
                goto fail_alloc;
        }

        if (err == -1) {
                log_dbg("Flow allocation terminated.");
                err = -EPIPE;
                goto fail_alloc;
        }

        assert(err == 0);

        if (oap_hdr_decode(r_oap_hdr.hdr, &r_oap_hdr) < 0) {
                log_err("Failed to decode OAP header.");
                err = -EIPCP;
                goto fail_r_oap_hdr;
        }

        if (memcmp(r_oap_hdr.id.data, oap_hdr.id.data, r_oap_hdr.id.len) != 0) {
                log_err("OAP ID mismatch in flow allocation.");
                err = -EIPCP;
                goto fail_r_oap_hdr;
        }

        if (flow->qs.cypher_s != 0) { /* crypto requested */
                if (crypt_dh_derive(pkp, r_oap_hdr.eph, s) < 0) {
                        log_err("Failed to derive secret for %d.", flow->id);
                        err = -ECRYPT;
                        goto fail_r_oap_hdr;
                }
                crypt_dh_pkp_destroy(pkp);

                symmkey->data = s;
                symmkey->len  = SYMMKEYSZ;
                s = NULL;
        }

        oap_hdr_fini(&r_oap_hdr);
        oap_hdr_fini(&oap_hdr);

        /* TODO: piggyback user data if needed */

        freebuf(hash);
        free(s);

        return 0;

 fail_r_oap_hdr:
        flow->state = FLOW_DEALLOCATED;
        oap_hdr_fini(&r_oap_hdr);
 fail_alloc:
        freebuf(hash);
 fail_ipcp:
        reg_destroy_flow(flow->id);
 fail_flow:
        oap_hdr_fini(&oap_hdr);
 fail_oap_hdr:
        crypt_dh_pkp_destroy(pkp);
 fail_pkp:
        free(s);
 fail_malloc:
        clrbuf(id);
 fail_id:
        return err;
}

static int wait_for_accept(enum hash_algo    algo,
                           const uint8_t *   hash)
{
        struct timespec   timeo = TIMESPEC_INIT_MS(IRMD_REQ_ARR_TIMEOUT);
        struct timespec   abstime;
        char **           exec;
        int               ret;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        ret = reg_wait_flow_accepting(algo, hash, &abstime);
        if (ret == -ETIMEDOUT) {
                if (reg_get_exec(algo, hash, &exec) < 0) {
                        log_dbg("No program bound to " HASH_FMT32 ".",
                                HASH_VAL32(hash));
                        goto fail;
                }

                log_info("Autostarting %s.", exec[0]);

                if (spawn_program(exec) < 0) {
                        log_dbg("Failed to autostart " HASH_FMT32 ".",
                                HASH_VAL32(hash));
                        goto fail_spawn;
                }

                ts_add(&abstime, &timeo, &abstime);

                ret = reg_wait_flow_accepting(algo, hash, &abstime);
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

        info.pid = flow->n_1_pid;

        log_info("Flow req arrived from IPCP %d for " HASH_FMT32 ".",
                 info.pid, HASH_VAL32(hash));

        if (reg_get_ipcp(&info, &layer) < 0) {
                log_err("No IPCP with pid %d.", info.pid);
                ret = -EIPCP;
                goto fail;
        }

        algo = (enum hash_algo) layer.dir_hash_algo;

        ret = wait_for_accept(algo, hash);
        if (ret < 0) {
                log_err("No activeprocess for " HASH_FMT32 ".",
                       HASH_VAL32(hash));
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

static int flow_alloc_reply(struct flow_info * flow,
                            int                response,
                            buffer_t *         data)
{
        flow->state = response ? FLOW_DEALLOCATED : FLOW_ALLOCATED;

        if (reg_respond_alloc(flow, data) < 0) {
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

static void free_msg(void * o)
{
        irm_msg__free_unpacked((irm_msg_t *) o, NULL);
}

static irm_msg_t * do_command_msg(irm_msg_t * msg)
{
        struct ipcp_config conf;
        struct ipcp_info   ipcp;
        struct flow_info   flow;
        struct proc_info   proc;
        struct name_info   name;
        struct timespec *  abstime;
        struct timespec    max = TIMESPEC_INIT_MS(FLOW_ALLOC_TIMEOUT);
        struct timespec    now;
        struct timespec    ts = TIMESPEC_INIT_S(0); /* static analysis */
        int                res;
        irm_msg_t *        ret_msg;
        buffer_t           data;
        buffer_t           symmkey = BUF_INIT;;

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

        pthread_cleanup_push(free_msg, ret_msg);

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
                res = enroll_ipcp(msg->pid, msg->dst);
                break;
        case IRM_MSG_CODE__IRM_CONNECT_IPCP:
                flow.qs = qos_spec_msg_to_s(msg->qosspec);
                res = connect_ipcp(msg->pid, msg->dst, msg->comp, flow.qs);
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
                strcpy(name.name, msg->names[0]->name);
                name.pol_lb = msg->names[0]->pol_lb;
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
                res = flow_accept(&flow, &symmkey, &data, abstime);
                if (res == 0) {
                        ret_msg->flow_info    = flow_info_s_to_msg(&flow);
                        ret_msg->has_symmkey  = symmkey.len != 0;
                        ret_msg->symmkey.data = symmkey.data;
                        ret_msg->symmkey.len  = symmkey.len;
                        ret_msg->has_pk       = data.len != 0;
                        ret_msg->pk.data      = data.data;
                        ret_msg->pk.len       = data.len;
                }
                break;
        case IRM_MSG_CODE__IRM_FLOW_ALLOC:
                data.len  = msg->pk.len;
                data.data = msg->pk.data;
                msg->has_pk = false;
                assert(data.len > 0 ? data.data != NULL : data.data == NULL);
                flow = flow_info_msg_to_s(msg->flow_info);
                abstime = abstime == NULL ? &max : abstime;
                res = flow_alloc(&flow, msg->dst, &symmkey, &data, abstime);
                if (res == 0) {
                        ret_msg->flow_info    = flow_info_s_to_msg(&flow);
                        ret_msg->has_symmkey  = symmkey.len != 0;
                        ret_msg->symmkey.data = symmkey.data;
                        ret_msg->symmkey.len  = symmkey.len;
                        ret_msg->has_pk       = data.len != 0;
                        ret_msg->pk.data      = data.data;
                        ret_msg->pk.len       = data.len;
                }
                break;
        case IRM_MSG_CODE__IRM_FLOW_JOIN:
                assert(msg->pk.len == 0 && msg->pk.data == NULL);
                flow = flow_info_msg_to_s(msg->flow_info);
                abstime = abstime == NULL ? &max : abstime;
                res = flow_join(&flow, msg->dst, abstime);
                if (res == 0)
                        ret_msg->flow_info    = flow_info_s_to_msg(&flow);
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
        case IRM_MSG_CODE__IPCP_FLOW_ALLOC_REPLY:
                data.len  = msg->pk.len;
                data.data = msg->pk.data;
                msg->pk.data = NULL; /* pass data */
                msg->pk.len  = 0;
                assert(data.len > 0 ? data.data != NULL : data.data == NULL);
                flow = flow_info_msg_to_s(msg->flow_info);
                res = flow_alloc_reply(&flow, msg->response, &data);
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

        return ret_msg;
}

static void * mainloop(void * o)
{
        int             sfd;
        irm_msg_t *     msg;
        buffer_t        buffer;

        (void) o;

        while (true) {
                irm_msg_t *  ret_msg;
                struct cmd * cmd;

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
                pthread_cleanup_push(free_msg, msg);

                ret_msg = do_command_msg(msg);

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

                pthread_cleanup_pop(true);
                pthread_cleanup_pop(true);

                tpm_end_work(irmd.tpm);

                continue;
 fail:
                irm_msg__free_unpacked(ret_msg, NULL);
 fail_msg:
                close(sfd);
                tpm_end_work(irmd.tpm);
                continue;
        }

        return (void *) 0;
}

static void irm_fini(void)
{
#ifdef HAVE_FUSE
        struct timespec wait = TIMESPEC_INIT_MS(1);
        int    retries = 5;
#endif
        if (irmd_get_state() != IRMD_NULL)
                log_warn("Unsafe destroy.");

        tpm_destroy(irmd.tpm);

        close(irmd.sockfd);

        if (unlink(IRM_SOCK_PATH))
                log_dbg("Failed to unlink %s.", IRM_SOCK_PATH);

        if (irmd.rdrb != NULL)
                shm_rdrbuff_destroy(irmd.rdrb);

        if (irmd.lf != NULL)
                lockfile_destroy(irmd.lf);

        pthread_mutex_destroy(&irmd.cmd_lock);
        pthread_cond_destroy(&irmd.cmd_cond);
        pthread_rwlock_destroy(&irmd.state_lock);

#ifdef HAVE_FUSE
        while (rmdir(FUSE_PREFIX) < 0 && retries-- > 0)
                nanosleep(&wait, NULL);
        if (retries < 0)
                log_err("Failed to remove " FUSE_PREFIX);
#endif
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
        shm_rdrbuff_purge();
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

#else
        (void) pid;
#endif
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


static int irm_init(void)
{
        struct stat        st;
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

        if ((irmd.rdrb = shm_rdrbuff_create()) == NULL) {
                log_err("Failed to create rdrbuff.");
                goto fail_rdrbuff;
        }

        irmd.tpm = tpm_create(IRMD_MIN_THREADS, IRMD_ADD_THREADS,
                              mainloop, NULL);
        if (irmd.tpm == NULL) {
                log_err("Failed to greate thread pool.");
                goto fail_tpm_create;
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

        return 0;

#ifdef HAVE_LIBGCRYPT
 fail_gcry_version:
 #ifdef HAVE_FUSE
        rmdir(FUSE_PREFIX);
 #endif
        tpm_destroy(irmd.tpm);
#endif
 fail_tpm_create:
        shm_rdrbuff_destroy(irmd.rdrb);
 fail_rdrbuff:
        close(irmd.sockfd);
 fail_sock_path:
        unlink(IRM_SOCK_PATH);
 fail_stat:
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
        if (tpm_start(irmd.tpm))
                goto fail_tpm_start;

        irmd_set_state(IRMD_RUNNING);

        if (pthread_create(&irmd.irm_sanitize, NULL, irm_sanitize, NULL))
                goto fail_irm_sanitize;

        if (pthread_create(&irmd.acceptor, NULL, acceptloop, NULL))
                goto fail_acceptor;

        log_info("Ouroboros IPC Resource Manager daemon started...");

        return 0;

 fail_acceptor:
        pthread_cancel(irmd.irm_sanitize);
        pthread_join(irmd.irm_sanitize, NULL);
 fail_irm_sanitize:
        irmd_set_state(IRMD_NULL);
        tpm_stop(irmd.tpm);
 fail_tpm_start:
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
        pthread_cancel(irmd.acceptor);
        pthread_cancel(irmd.irm_sanitize);

        pthread_join(irmd.acceptor, NULL);
        pthread_join(irmd.irm_sanitize, NULL);

        tpm_stop(irmd.tpm);

        irmd_set_state(IRMD_NULL);
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
                        printf("Ouroboros version %d.%d.%d\n",
                               OUROBOROS_VERSION_MAJOR,
                               OUROBOROS_VERSION_MINOR,
                               OUROBOROS_VERSION_PATCH);
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

        log_dbg("I am become Death, destroyer of hung processes.");

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
                exit(EXIT_FAILURE);
        }

        if (irm_init() < 0)
                goto fail_irm_init;

        if (reg_init() < 0) {
                log_err("Failed to initialize registry.");
                goto fail_reg;
        }

        pthread_sigmask(SIG_BLOCK, &sigset, NULL);

        if (irm_start() < 0)
                goto fail_irm_start;

#ifdef HAVE_TOML
        if (irm_configure(irmd.cfg_file) < 0) {
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

        log_info("Ouroboros IPC Resource Manager daemon exited. Bye.");

        log_fini();

        exit(ret);

 fail_irm_start:
        reg_fini();
 fail_reg:
        irm_fini();
 fail_irm_init:
        exit(EXIT_FAILURE);
}
