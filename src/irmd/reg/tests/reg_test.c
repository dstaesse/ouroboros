/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - Unit Tests
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


#include "../reg.c"

#include <ouroboros/test.h>

#define TEST_PID      3666
#define TEST_N_1_PID  3999
#define TEST_FAKE_ID  9128349
#define TEST_MPL      5
#define TEST_PROG     "reg_test" /* own binary for binary check */
#define TEST_IPCP     "testipcp"
#define TEST_NAME     "testname"
#define TEST_DATA     "testpbufdata"
#define TEST_DATA2    "testpbufdata2"
#define TEST_LAYER    "testlayer"
#define REG_TEST_FAIL() \
        do { TEST_FAIL(); memset(&reg, 0, sizeof(reg)); } while(0)

static int test_reg_init(void)
{
        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_reg_create_flow(void)
{
        struct flow_info info = {
                .n_pid = TEST_PID,
                .qs    = qos_raw,
        };

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_flow(&info) < 0) {
                printf("Failed to create flow.\n");
                goto fail;
        }

        if (info.id == 0) {
                printf("Failed to update id.'n");
                goto fail;
        }

        if (reg.n_flows != 1) {
                printf("n_flows was not updated.\n");
                goto fail;
        }

        if (!reg_has_flow(info.id)) {
                printf("Failed to find flow.\n");
                goto fail;
        }

        if (reg_destroy_flow(info.id) < 0) {
                printf("Failed to destroy flow.\n");
                goto fail;
        }

        if (reg.n_flows != 0) {
                printf("n_flows was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_reg_allocate_flow_timeout(void)
{
        struct timespec abstime;
        struct timespec timeo = TIMESPEC_INIT_MS(1);
        buffer_t        pbuf;
        buffer_t        rbuf = {NULL, 0};

        struct flow_info info = {
                .n_pid = TEST_PID,
                .qs    = qos_raw
        };

        TEST_START();

        pbuf.data = (uint8_t *) strdup(TEST_DATA);;
        if (pbuf.data == NULL) {
                printf("Failed to strdup data.\n");
                goto fail;
        }

        pbuf.len  = strlen((char *) pbuf.data) + 1;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        ts_add(&abstime, &timeo, &abstime);

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_flow(&info) < 0) {
                printf("Failed to add flow.\n");
                goto fail;
        }

        if (reg_prepare_flow_accept(&info, &pbuf) < 0) {
                printf("Failed to prepare flow for accept.\n");
                goto fail;
        }

        if (reg_wait_flow_accepted(&info, &rbuf, &abstime) != -ETIMEDOUT) {
                printf("Wait allocated did not timeout.\n");
                goto fail;
        }

        if (info.state != FLOW_DEALLOCATED) {
                printf("Flow did not timeout in deallocated state.\n");
                goto fail;
        }

        if (pbuf.data == NULL) {
                printf("Flow data was updated on timeout.");
                goto fail;
        }

        freebuf(pbuf);
        reg_destroy_flow(info.id);

        if (reg.n_flows != 0) {
                printf("Flow did not destroy.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static void * test_flow_respond_alloc(void * o)
{
        struct flow_info * info = (struct flow_info *) o;
        buffer_t           pbuf = {NULL, 0};

        if (info->state == FLOW_ALLOCATED) {
                pbuf.data = (uint8_t *) strdup(TEST_DATA2);
                if (pbuf.data == NULL) {
                        printf("Failed to strdup data2.\n");
                        goto fail;
                }
                pbuf.len  = strlen((char *) pbuf.data) + 1;
        }

        reg_respond_alloc(info, &pbuf);

        return (void *) 0;
 fail:
        return (void *) -1;
}

static void * test_flow_respond_accept(void * o)
{
        struct flow_info * info = (struct flow_info *) o;
        buffer_t           pbuf;

        pbuf.data = (uint8_t *) strdup(TEST_DATA2);
        if (pbuf.data == NULL) {
                printf("Failed to strdup data2.\n");
                goto fail;
        }
        pbuf.len  = strlen((char *) pbuf.data) + 1;

        reg_respond_accept(info, &pbuf);

        if (info->qs.cypher_s == 0) {
                freebuf(pbuf);
        } else if (strcmp((char *) pbuf.data, TEST_DATA) != 0) {
                printf("Data was not passed correctly.\n");
                goto fail;
        }

        return (void *) 0;
 fail:
        return (void *) -1;
}

static int test_reg_accept_flow_success(void)
{
        pthread_t       thr;
        struct timespec abstime;
        struct timespec timeo = TIMESPEC_INIT_S(1);
        buffer_t        pbuf = {(uint8_t *) TEST_DATA, strlen(TEST_DATA)};
        buffer_t        rbuf  = {NULL, 0};

        struct flow_info info = {
                .n_pid = TEST_PID,
                .qs    = qos_raw
        };

        struct flow_info n_1_info = {
                .n_1_pid = TEST_N_1_PID,
                .qs      = qos_data_crypt,
                .state   = FLOW_ALLOCATED /* RESPONSE SUCCESS */
        };

        TEST_START();

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        ts_add(&abstime, &timeo, &abstime);

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_flow(&info) < 0) {
                printf("Failed to add flow.\n");
                goto fail;
        }

        if (reg_prepare_flow_accept(&info, &pbuf) < 0) {
                printf("Failed to prepare flow for accept.\n");
                goto fail;
        }

        n_1_info.id  = info.id;
        n_1_info.mpl = 1;

        pthread_create(&thr, NULL, test_flow_respond_accept, &n_1_info);

        if (reg_wait_flow_accepted(&info, &rbuf, &abstime) < 0 ) {
                printf("Flow allocation failed.\n");
                goto fail;
        }

        pthread_join(thr, NULL);

        if (info.state != FLOW_ALLOCATED) {
                printf("Flow succeeded but not in allocated state.\n");
                goto fail;
        }

        if (rbuf.data == NULL) {
                printf("rbuf data not returned.\n");
                goto fail;
        }

        if (strcmp((char *) rbuf.data, TEST_DATA2) != 0) {
                printf("Data2 was not passed correctly.\n");
                goto fail;
        }

        freebuf(rbuf);

        reg_dealloc_flow(&info);

        if (info.state != FLOW_DEALLOC_PENDING) {
                printf("Flow dealloc requested but not in pending state.\n");
                goto fail;
        }

        reg_dealloc_flow_resp(&info);

        if (info.state != FLOW_DEALLOCATED) {
                printf("Flow deallocated but not in deallocated state.\n");
                goto fail;
        }

        reg_destroy_flow(n_1_info.id);

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_reg_accept_flow_success_no_crypt(void)
{
        pthread_t       thr;
        struct timespec abstime;
        struct timespec timeo = TIMESPEC_INIT_S(1);
        buffer_t        pbuf = {(uint8_t *) TEST_DATA, strlen(TEST_DATA)};
        buffer_t        rbuf  = {NULL, 0};

        struct flow_info info = {
                .n_pid = TEST_PID,
                .qs    = qos_raw
        };

        struct flow_info n_1_info = {
                .n_1_pid = TEST_N_1_PID,
                .qs      = qos_data,
                .state   = FLOW_ALLOCATED /* RESPONSE SUCCESS */
        };

        TEST_START();

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        ts_add(&abstime, &timeo, &abstime);

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_flow(&info) < 0) {
                printf("Failed to add flow.\n");
                goto fail;
        }

        if (reg_prepare_flow_accept(&info, &pbuf) < 0) {
                printf("Failed to prepare flow for accept.\n");
                goto fail;
        }

        n_1_info.id  = info.id;
        n_1_info.mpl = 1;

        pthread_create(&thr, NULL, test_flow_respond_accept, &n_1_info);

        if (reg_wait_flow_accepted(&info, &rbuf, &abstime) < 0 ) {
                printf("Flow allocation failed.\n");
                goto fail;
        }

        pthread_join(thr, NULL);

        if (info.state != FLOW_ALLOCATED) {
                printf("Flow succeeded but not in allocated state.\n");
                goto fail;
        }

        if (rbuf.data == NULL) {
                printf("rbuf data was not returned.\n");
                goto fail;
        }

        if (strcmp((char *) rbuf.data, TEST_DATA) != 0) {
                printf("Data was updated.\n");
                goto fail;
        }

        n_1_info.state = FLOW_DEALLOCATED;

        reg_dealloc_flow(&info);

        if (info.state != FLOW_DEALLOC_PENDING) {
                printf("Flow dealloc requested but not in pending state.\n");
                goto fail;
        }

        reg_dealloc_flow_resp(&info);

        if (info.state != FLOW_DEALLOCATED) {
                printf("Flow deallocated but not in deallocated state.\n");
                goto fail;
        }

        reg_destroy_flow(n_1_info.id);

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}


static int test_reg_allocate_flow_fail(void)
{
        buffer_t        buf   = {NULL, 0};
        pthread_t       thr;
        struct timespec abstime;
        struct timespec timeo = TIMESPEC_INIT_S(1);

        struct flow_info info = {
                .n_pid = TEST_PID,
                .qs    = qos_raw
        };

        struct flow_info n_1_info = {
                .n_1_pid = TEST_N_1_PID,
                .qs      = qos_data,
                .state = FLOW_DEALLOCATED /* RESPONSE FAIL */
        };

        TEST_START();

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);

        ts_add(&abstime, &timeo, &abstime);

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_flow(&info) < 0) {
                printf("Failed to add flow.\n");
                goto fail;
        }

        info.n_1_pid = TEST_N_1_PID;

        if (reg_prepare_flow_alloc(&info) < 0) {
                printf("Failed to prepare flow for alloc.\n");
                goto fail;
        }

        n_1_info.id  = info.id;

        pthread_create(&thr, NULL, test_flow_respond_alloc, &n_1_info);

        if (reg_wait_flow_allocated(&info, &buf, &abstime) == 0 ) {
                printf("Flow allocation succeeded.\n");
                goto fail;
        }

        pthread_join(thr, NULL);

        if (info.state != FLOW_DEALLOCATED) {
                printf("Flow failed but not in deallocated state.\n");
                goto fail;
        }

        reg_destroy_flow(n_1_info.id);

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_reg_flow(void) {
        int ret = 0;

        ret |= test_reg_create_flow();

        ret |= test_reg_allocate_flow_timeout();

        ret |= test_reg_accept_flow_success();

        ret |= test_reg_accept_flow_success_no_crypt();

        ret |= test_reg_allocate_flow_fail();

        return ret;
}

static int test_reg_create_ipcp(void)
{
        struct ipcp_info info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_BOOT /* set by spawn_ipcp */
        };

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_ipcp(&info) < 0) {
                printf("Failed to create ipcp.\n");
                goto fail;
        }

        if (reg.n_ipcps != 1) {
                printf("n_ipcps was not updated.\n");
                goto fail;
        }

        if (!reg_has_ipcp(info.pid)) {
                printf("Failed to find ipcp.\n");
                goto fail;
        }

        if (reg_destroy_ipcp(info.pid) < 0) {
                printf("Failed to destroy ipcp.\n");
                goto fail;
        }

        if (reg.n_ipcps != 0) {
                printf("n_ipcps was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_set_layer(void)
{
        struct reg_ipcp * ipcp;
        struct ipcp_info info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_BOOT /* set by spawn_ipcp */
        };
        struct layer_info layer = {
                .name = TEST_LAYER,
        };

        struct ipcp_info  get_info = {
                .pid = TEST_PID
        };
        struct layer_info get_layer;

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_ipcp(&info) < 0) {
                printf("Failed to create ipcp.\n");
                goto fail;
        }

        ipcp = __reg_get_ipcp(info.pid);
        ipcp->info.state = IPCP_OPERATIONAL;
        info.state = IPCP_ENROLLED;

        reg_set_layer_for_ipcp(&info, &layer);

        reg_get_ipcp(&get_info, &get_layer);

        if (memcmp(&get_info, &info, sizeof(ipcp)) != 0) {
                printf("Failed to set ipcp info.\n");
                goto fail;
        }

        if (memcmp(&get_layer, &layer, sizeof(layer)) != 0) {
                printf("Failed to set layer info.\n");
                goto fail;
        }

        if (reg_destroy_ipcp(info.pid) < 0) {
                printf("Failed to destroy ipcp.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_reg_ipcp(void)
{
        int ret = 0;

        ret |= test_reg_create_ipcp();

        ret |= test_set_layer();

        return ret;
}

static int test_reg_create_name(void)
{
        struct name_info info = {
                .name   = TEST_NAME,
                .pol_lb = LB_RR
        };

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_name(&info) < 0) {
                printf("Failed to create name.\n");
                goto fail;
        }

        if (reg.n_names != 1) {
                printf("n_names was not updated.\n");
                goto fail;
        }

        if (!reg_has_name(info.name)) {
                printf("Failed to find name.\n");
                goto fail;
        }

        if (reg_destroy_name(info.name) < 0) {
                printf("Failed to destroy name.\n");
                goto fail;
        }

        if (reg.n_names != 0) {
                printf("n_names was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_reg_name(void)
{
        int ret = 0;

        ret |= test_reg_create_name();

        return ret;
}

static int test_reg_create_proc(void)
{
        struct proc_info info = {
                .pid =  TEST_PID,
                .prog = TEST_PROG
        };

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_proc(&info) < 0) {
                printf("Failed to create process.\n");
                goto fail;
        }

        if (reg.n_procs != 1) {
                printf("n_procs was not updated.\n");
                goto fail;
        }

        if (!reg_has_proc(info.pid)) {
                printf("Failed to find process.\n");
                goto fail;
        }

        if (reg_destroy_proc(info.pid) < 0) {
                printf("Failed to destroy process.\n");
                goto fail;
        }

        if (reg.n_procs != 0) {
                printf("n_procs was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_reg_proc(void)
{
        int ret = 0;

        ret |= test_reg_create_proc();

        return ret;
}

static int test_reg_spawned(void)
{
        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_spawned(TEST_PID) < 0) {
                printf("Failed to create process.\n");
                goto fail;
        }

        if (reg.n_spawned != 1) {
                printf("n_spawned was not updated.\n");
                goto fail;
        }

        if (!reg_has_spawned(TEST_PID)) {
                printf("Failed to find spawned.\n");
                goto fail;
        }

        if (reg_destroy_spawned(TEST_PID) < 0) {
                printf("Failed to destroy spawned.\n");
                goto fail;
        }

        if (reg.n_spawned != 0) {
                printf("n_spawned was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_reg_create_prog(void)
{
        struct prog_info info = {
                .name = TEST_PROG
        };

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_prog(&info) < 0) {
                printf("Failed to create program.\n");
                goto fail;
        }

        if (reg.n_progs != 1) {
                printf("n_progs was not updated.\n");
                goto fail;
        }

        if (!reg_has_prog(info.name)) {
                printf("Failed to find program.\n");
                goto fail;
        }

        if (reg_destroy_prog(info.name) < 0) {
                printf("Failed to destroy program.\n");
                goto fail;
        }

        if (reg.n_progs != 0) {
                printf("n_progs was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_reg_prog(void)
{
        int ret = 0;

        ret |= test_reg_create_prog();

        return ret;
}

static int test_bind_proc(void)
{
        struct proc_info pinfo = {
                .pid =  TEST_PID,
                .prog = TEST_PROG
        };

        struct name_info ninfo = {
                .name   = TEST_NAME,
                .pol_lb = LB_RR
        };

        TEST_START();

        if (reg_init()) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_name(&ninfo) < 0) {
                printf("Failed to create name.\n");
                goto fail;
        }

        if (reg_create_proc(&pinfo) < 0) {
                printf("Failed to create proc.\n");
                goto fail;
        }

        if (reg_bind_proc(TEST_NAME, TEST_PID) < 0) {
                printf("Failed to bind proc.\n");
                goto fail;
        }

        if (reg_unbind_proc(TEST_NAME, TEST_PID) < 0) {
                printf("Failed to unbind proc.\n");
                goto fail;
        }

        reg_destroy_proc(TEST_PID);

        if (reg_name_has_proc( __reg_get_name(TEST_NAME), TEST_PID)) {
                printf("Proc still in name after destroy.\n");
                goto fail;
        }

        reg_destroy_name(TEST_NAME);

        reg_fini();

        TEST_SUCCESS();

        return 0;
fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_bind_prog(void)
{
        struct prog_info pinfo = {
                .name = TEST_PROG
        };

        struct name_info ninfo = {
                .name   = TEST_NAME,
                .pol_lb = LB_RR
        };

        char * exec[] = { TEST_PROG, "--argswitch", "argvalue", NULL};

        TEST_START();

        if (reg_init()) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_name(&ninfo) < 0) {
                printf("Failed to create name.\n");
                goto fail;
        }

        if (reg_create_prog(&pinfo) < 0) {
                printf("Failed to create prog.\n");
                goto fail;
        }

        if (reg_bind_prog(TEST_NAME, exec, BIND_AUTO) < 0) {
                printf("Failed to bind prog.\n");
                goto fail;
        }

        if (!reg_name_has_prog( __reg_get_name(TEST_NAME), TEST_PROG)) {
                printf("Prog not found in name.\n");
                goto fail;
        }

        if (!reg_prog_has_name( __reg_get_prog(TEST_PROG), TEST_NAME)) {
                printf("Name not found in prog.\n");
                goto fail;
        }

        if (reg_unbind_prog(TEST_NAME, TEST_PROG) < 0) {
                printf("Failed to unbind prog.\n");
                goto fail;
        }

        if (reg_name_has_prog( __reg_get_name(TEST_NAME), TEST_PROG)) {
                printf("Prog still in name after unbind.\n");
                goto fail;
        }

        if (reg_prog_has_name( __reg_get_prog(TEST_PROG), TEST_NAME)) {
                printf("Name still in prog after unbind.\n");
                goto fail;
        }

        if (reg_bind_prog(TEST_NAME, exec, 0) < 0) {
                printf("Failed to bind prog.\n");
                goto fail;
        }

        if (reg_name_has_prog( __reg_get_name(TEST_NAME), TEST_PROG)) {
                printf("Non-auto prog found in name.\n");
                goto fail;
        }

        if (reg_unbind_prog(TEST_NAME, TEST_PROG) < 0) {
                printf("Failed to unbind prog.\n");
                goto fail;
        }

        reg_destroy_prog(TEST_PROG);

        reg_destroy_name(TEST_NAME);

        reg_fini();

        TEST_SUCCESS();

        return 0;
fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_inherit_prog(void)
{
        struct name_info nameinfo = {
                .name   = TEST_NAME,
                .pol_lb = LB_RR
        };

        struct prog_info proginfo = {
                .name = TEST_PROG
        };

        struct proc_info procinfo = {
                .pid  = TEST_PID,
                .prog = TEST_PROG
        };

        char * exec[] = { TEST_PROG, NULL};

        TEST_START();

        if (reg_init()) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_name(&nameinfo) < 0) {
                printf("Failed to create name.\n");
                goto fail;
        }

        if (reg_create_prog(&proginfo) < 0) {
                printf("Failed to create prog.\n");
                goto fail;
        }

        if (reg_bind_prog(TEST_NAME, exec, 0) < 0) {
                printf("Failed to bind prog.\n");
                goto fail;
        }

        if (reg_create_proc(&procinfo) < 0) {
                printf("Failed to create proc.\n");
                goto fail;
        }

        if (!reg_name_has_proc(__reg_get_name(TEST_NAME), TEST_PID)) {
                printf("Failed to update name from prog.\n");
                goto fail;
        }

        if (!reg_proc_has_name(__reg_get_proc(TEST_PID), TEST_NAME)) {
                printf("Failed to update proc from prog.\n");
                goto fail;
        }

        reg_destroy_proc(TEST_PID);

        reg_destroy_prog(TEST_PROG);

        reg_destroy_name(TEST_NAME);

        reg_fini();

        TEST_SUCCESS();

        return 0;
fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_wait_accepting_timeout(void)
{
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_MS(1);
        int              flow_id;
        uint8_t          hash[64];
        struct name_info ninfo = {
                .name   = TEST_NAME,
                .pol_lb = LB_RR
        };

        TEST_START();

        if (reg_init()) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_name(&ninfo) < 0) {
                printf("Failed to create name.\n");
                goto fail;
        }

        str_hash(HASH_SHA3_256, hash, ninfo.name);

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        flow_id = reg_wait_flow_accepting(HASH_SHA3_256, hash, &abstime);
        if (flow_id != -ETIMEDOUT) {
                printf("Wait accept did not time out: %d.\n", flow_id);
                goto fail;
        }

        reg_destroy_name(TEST_NAME);

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_wait_accepting_fail_name(void)
{
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_S(1);
        int              flow_id;
        uint8_t          hash[64];

        TEST_START();

        if (reg_init()) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);
        str_hash(HASH_SHA3_256, hash, "C0FF33");

        flow_id = reg_wait_flow_accepting(HASH_SHA3_256, hash, &abstime);
        if (flow_id != -ENAME) {
                printf("Wait accept did not fail on name: %d.\n", flow_id);
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static void * test_call_flow_accept(void * o)
{
        struct timespec abstime;
        struct timespec timeo = TIMESPEC_INIT_MS(1);
        buffer_t        pbuf = {NULL, 0};

        struct proc_info pinfo = {
                .pid =  TEST_PID,
                .prog = TEST_PROG
        };

        struct flow_info info = {
                .n_pid = pinfo.pid,
                .qs    = qos_raw,
        };

        if (reg_create_proc(&pinfo) < 0) {
                printf("Failed to create proc.\n");
                goto fail;
        }

        if (reg_bind_proc((char *) o, TEST_PID) < 0) {
                printf("Failed to bind proc.\n");
                goto fail;
        }

        if (reg_create_flow(&info) < 0) {
                printf("Failed to create flow.\n");
                goto fail;
        }

        info.state = FLOW_ACCEPT_PENDING;

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        reg_prepare_flow_accept(&info, &pbuf);

        if (reg_wait_flow_accepted(&info, &pbuf, &abstime) != -ETIMEDOUT) {
                printf("Wait allocated did not timeout.\n");
                goto fail;
        }

        reg_destroy_flow(info.id);
        reg_destroy_proc(pinfo.pid);

        return (void *) 0;
 fail:
        return (void *) -1;
}

static int test_wait_accepting_success(void)
{
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_S(1);
        int              flow_id;
        pthread_t        thr;
        uint8_t          hash[64];
        struct name_info ninfo = {
                .name   = TEST_NAME,
                .pol_lb = LB_RR
        };

        TEST_START();

        if (reg_init()) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_name(&ninfo) < 0) {
                printf("Failed to create name.\n");
                goto fail;
        }

        pthread_create(&thr, NULL, test_call_flow_accept, ninfo.name);

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        str_hash(HASH_SHA3_256, hash, ninfo.name);

        flow_id = reg_wait_flow_accepting(HASH_SHA3_256, hash, &abstime);
        if (flow_id < 0) {
                printf("Wait accept did not return a flow id: %d.", flow_id);
                goto fail;
        }

        pthread_join(thr, NULL);

        reg_destroy_name(TEST_NAME);

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_wait_accepting(void)
{
        int ret = 0;

        ret |= test_wait_accepting_timeout();

        ret |= test_wait_accepting_fail_name();

        ret |= test_wait_accepting_success();

        return ret;
}

static int test_wait_ipcp_boot_timeout(void)
{
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_MS(1);
        struct ipcp_info info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_BOOT  /* set by spawn_ipcp */
        };

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_ipcp(&info) < 0) {
                printf("Failed to create ipcp.\n");
                goto fail;
        }

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        if (reg_wait_ipcp_boot(&info, &abstime) != -ETIMEDOUT) {
                printf("Wait boot did not timeout.\n");
                goto fail;
        }

        if (reg_destroy_ipcp(info.pid) < 0) {
                printf("Failed to destroy ipcp.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static void * test_ipcp_respond(void * o)
{
        (void) o;

        reg_respond_ipcp((struct ipcp_info *) o);

        return (void *) 0;
}

static int test_wait_ipcp_boot_fail(void)
{
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_S(1);
        pthread_t        thr;
        struct ipcp_info info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_BOOT /* set by spawn_ipcp */
        };
        struct ipcp_info resp_info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_NULL
        };

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_ipcp(&info) < 0) {
                printf("Failed to create ipcp.\n");
                goto fail;
        }

        pthread_create(&thr, NULL, test_ipcp_respond, &resp_info);

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        info.state = IPCP_BOOT;

        if (reg_wait_ipcp_boot(&info, &abstime) == 0) {
                printf("IPCP boot reported success.\n");
                goto fail;
        }

        pthread_join(thr, NULL);

        if (reg_destroy_ipcp(info.pid) < 0) {
                printf("Failed to destroy ipcp.\n");
                goto fail;
        }

        if (reg.n_ipcps != 0) {
                printf("n_ipcps was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_wait_ipcp_boot_success(void)
{
        pthread_t        thr;
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_S(1);
        struct ipcp_info info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_BOOT /* set by spawn_ipcp */
        };
        struct ipcp_info resp_info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_OPERATIONAL
        };

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_ipcp(&info) < 0) {
                printf("Failed to create ipcp.\n");
                goto fail;
        }

        pthread_create(&thr, NULL, test_ipcp_respond, &resp_info);

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        info.state = IPCP_BOOT;

        if (reg_wait_ipcp_boot(&info, &abstime) < 0) {
                printf("IPCP boot failed.\n");
                goto fail;
        }

        pthread_join(thr, NULL);

        if (info.state != IPCP_OPERATIONAL) {
                printf("IPCP boot succeeded in non-operational state.\n");
                goto fail;
        }

        if (reg_destroy_ipcp(info.pid) < 0) {
                printf("Failed to destroy ipcp.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_wait_ipcp_boot(void)
{
        int ret = 0;

        ret |= test_wait_ipcp_boot_timeout();

        ret |= test_wait_ipcp_boot_fail();

        ret |= test_wait_ipcp_boot_success();

        return ret;
}

static int test_wait_proc_timeout(void)
{
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_MS(1);

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }


        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        if (reg_wait_proc(TEST_PID, &abstime) != -ETIMEDOUT) {
                printf("Wait proc did not timeout.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static void * test_proc(void * o)
{
        (void) o;

        reg_create_proc((struct proc_info *) o);

        return (void *) 0;
}

static int test_wait_proc_success(void)
{
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_S(1);
        pthread_t        thr;
        struct proc_info info = {
                .pid  = TEST_PID,
                .prog = TEST_PROG
        };

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        pthread_create(&thr, NULL, test_proc, &info);

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        if (reg_wait_proc(info.pid, &abstime) < 0) {
                printf("Waiting for proc failed.\n");
                goto fail;
        }

        pthread_join(thr, NULL);

        reg_destroy_proc(info.pid);

        reg_fini();

        TEST_SUCCESS();

        return 0;
 fail:
        REG_TEST_FAIL();
        return -1;
}

static int test_wait_proc(void)
{
        int ret = 0;

        ret |= test_wait_proc_timeout();

        ret |= test_wait_proc_success();

        return ret;
}


int reg_test(int     argc,
             char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_reg_init();

        ret |= test_reg_flow();

        ret |= test_reg_ipcp();

        ret |= test_reg_name();

        ret |= test_reg_proc();

        ret |= test_reg_prog();

        ret |= test_reg_spawned();

        ret |= test_bind_proc();

        ret |= test_bind_prog();

        ret |= test_inherit_prog();

        ret |= test_wait_accepting();

        ret |= test_wait_ipcp_boot();

        ret |= test_wait_proc();

        return ret;
}
