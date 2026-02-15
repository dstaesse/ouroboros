/*
 * Ouroboros - Copyright (C) 2016 - 2026
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


#include "../pool.c"
#undef OUROBOROS_PREFIX
#include "../reg.c"

#include <test/test.h>

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
#define TEST_PROC_INFO {      \
        .pid = TEST_PID,      \
        .prog = TEST_PROG,    \
        .uid = 0,             \
        .gid = 0              \
}
#define REG_TEST_FAIL() \
        do { TEST_FAIL(); reg_clear(); return TEST_RC_FAIL;} while(0)

static int test_reg_init(void)
{
        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
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

        if (reg.flows.len != 1) {
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

        if (!llist_is_empty(&reg.flows)) {
                printf("flows.len was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_allocate_flow_timeout(void)
{
        struct timespec abstime;
        struct timespec timeo = TIMESPEC_INIT_MS(1);
        buffer_t        rbuf = BUF_INIT;

        struct flow_info info = {
                .n_pid = TEST_PID,
                .qs    = qos_raw
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

        if (reg_prepare_flow_accept(&info) < 0) {
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

        reg_destroy_flow(info.id);

        if (!llist_is_empty(&reg.flows)) {
                printf("Flow did not destroy.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static void * test_flow_respond_alloc(void * o)
{
        struct flow_info * info = (struct flow_info *) o;
        buffer_t           pbuf = BUF_INIT;
        int                response;

        response = (info->state == FLOW_ALLOCATED) ? 0 : -1;

        if (info->state == FLOW_ALLOCATED) {
                pbuf.data = (uint8_t *) strdup(TEST_DATA2);
                if (pbuf.data == NULL) {
                        printf("Failed to strdup data2.\n");
                        goto fail;
                }
                pbuf.len  = strlen((char *) pbuf.data) + 1;
        }

        reg_respond_alloc(info, &pbuf, response);

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

        return (void *) 0;
 fail:
        return (void *) -1;
}

static int test_reg_accept_flow_success(void)
{
        pthread_t       thr;
        struct timespec abstime;
        struct timespec timeo = TIMESPEC_INIT_S(1);
        buffer_t        rbuf  = BUF_INIT;

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

        if (reg_prepare_flow_accept(&info) < 0) {
                printf("Failed to prepare flow for accept.\n");
                goto fail;
        }

        n_1_info.id  = info.id;
        n_1_info.mpl = 1;

        pthread_create(&thr, NULL, test_flow_respond_accept, &n_1_info);

        if (reg_wait_flow_accepted(&info, &rbuf, &abstime) < 0) {
                printf("Flow allocation failed.\n");
                pthread_join(thr, NULL);
                reg_destroy_flow(info.id);
                reg_fini();
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

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_accept_flow_success_no_crypt(void)
{
        pthread_t       thr;
        struct timespec abstime;
        struct timespec timeo = TIMESPEC_INIT_S(1);
        buffer_t        rbuf  = BUF_INIT;

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

        if (reg_prepare_flow_accept(&info) < 0) {
                printf("Failed to prepare flow for accept.\n");
                goto fail;
        }

        n_1_info.id  = info.id;
        n_1_info.mpl = 1;

        pthread_create(&thr, NULL, test_flow_respond_accept, &n_1_info);

        if (reg_wait_flow_accepted(&info, &rbuf, &abstime) < 0 ) {
                printf("Flow allocation failed.\n");
                pthread_join(thr, NULL);
                reg_destroy_flow(info.id);
                reg_fini();
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

        freebuf(rbuf);

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

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}


static int test_reg_allocate_flow_fail(void)
{
        buffer_t        buf   = BUF_INIT;
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
                pthread_join(thr, NULL);
                reg_destroy_flow(info.id);
                reg_fini();
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

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_flow(void) {
        int rc = 0;

        rc |= test_reg_create_flow();
        rc |= test_reg_allocate_flow_timeout();
        rc |= test_reg_accept_flow_success();
        rc |= test_reg_accept_flow_success_no_crypt();
        rc |= test_reg_allocate_flow_fail();

        return rc;
}

static int test_reg_create_ipcp(void)
{
        struct ipcp_info info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_INIT /* set by spawn_ipcp */
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

        if (reg.ipcps.len != 1) {
                printf("n_ipcps was not updated.\n");
                goto fail;
        }

        if (!reg_has_ipcp(info.pid)) {
                printf("Failed to find ipcp.\n");
                goto fail;
        }

        if (reg_destroy_proc(info.pid) < 0) {
                printf("Failed to destroy ipcp.\n");
                goto fail;
        }

        if (reg.ipcps.len != 0) {
                printf("ipcps.len was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_list_ipcps(void)
{
        ipcp_list_msg_t ** ipcps;
        int                i;
        ssize_t            len;

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        for (i = 0; i < 10; i++) {
                struct ipcp_info info = {
                        .pid   = TEST_PID + i,
                        .state = IPCP_INIT /* set by spawn_ipcp */
                };

                sprintf(info.name, "%s%d", TEST_IPCP, i);

                if (reg_create_ipcp(&info) < 0) {
                        printf("Failed to create ipcp %d.\n", i);
                        goto fail;
                }
        }

        len = reg_list_ipcps(&ipcps);
        if (len < 0) {
                printf("Failed to list ipcps.\n");
                goto fail;
        }

        if (len != 10) {
                printf("Failed to list all ipcps.\n");
                goto fail;
        }

        while (len-- > 0)
                ipcp_list_msg__free_unpacked(ipcps[len], NULL);
        free(ipcps);

        for (i = 0; i < 10; i++)
                reg_destroy_proc(TEST_PID + i);

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;

 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_insert_ipcps(void)
{
        ipcp_list_msg_t ** ipcps;
        struct ipcp_info   info;
        size_t             i;
        size_t             len;

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        for (i = 0; i < 100; i++) {
                sprintf(info.name, "%s-%zd", TEST_IPCP, i);
                info.pid   = TEST_PID + rand() % 10000;
                info.type  = rand() % IPCP_INVALID;
                info.state = IPCP_INIT; /* set by spawn_ipcp */

                if (reg_create_ipcp(&info) < 0) {
                        printf("Failed to create ipcp %s.\n", info.name);
                        goto fail;
                }
        }

        len = reg_list_ipcps(&ipcps);
        if (len != 100) {
                printf("Failed to list all ipcps.\n");
                goto fail;
        }

        for (i = 1; i < len; i++) {
                if (ipcps[i]->type < ipcps[i - 1]->type) {
                        printf("IPCPS not sorted by type.\n");
                        goto fail;
                }

                if (ipcps[i]->type != ipcps[i - 1]->type)
                        continue;

                /* allow occasional duplicate PID in test */
                if (ipcps[i]->pid < ipcps[i - 1]->pid) {
                        printf("IPCPS not sorted by pid.\n");
                        goto fail;
                }
        }

        while (len-- > 0)
                ipcp_list_msg__free_unpacked(ipcps[len], NULL);
        free(ipcps);

        reg_clear();

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_set_layer(void)
{
        struct reg_ipcp * ipcp;
        struct ipcp_info info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_INIT /* set by spawn_ipcp */
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

        ipcp->info.state = IPCP_BOOT;
        info.state = IPCP_BOOT;

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

        if (reg_destroy_proc(info.pid) < 0) {
                printf("Failed to destroy ipcp.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_ipcp(void)
{
        int rc = 0;

        rc |= test_reg_create_ipcp();
        rc |= test_reg_list_ipcps();
        rc |= test_insert_ipcps();
        rc |= test_set_layer();

        return rc;
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

        if (reg.names.len != 1) {
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

        if (!llist_is_empty(&reg.names)) {
                printf("n_names was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_list_names(void)
{
        name_info_msg_t ** names;
        int                i;
        ssize_t            len;

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        for (i = 0; i < 10; i++) {
                struct name_info info = {
                        .pol_lb = LB_RR
                };

                sprintf(info.name, "%s%d", TEST_NAME, i);

                if (reg_create_name(&info) < 0) {
                        printf("Failed to create name %d.\n", i);
                        goto fail;
                }
        }

        len = reg_list_names(&names);
        if (len < 0) {
                printf("Failed to list names.\n");
                goto fail;
        }

        if (len != 10) {
                printf("Failed to list all names.\n");
                goto fail;
        }

        for (i = 0; i < len; i++)
                name_info_msg__free_unpacked(names[i], NULL);
        free(names);

        for (i = 0; i < 10; i++) {
                char name[NAME_MAX];
                sprintf(name, "%s%d", TEST_NAME, i);
                reg_destroy_name(name);
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_name(void)
{
        int rc = 0;

        rc |= test_reg_create_name();
        rc |= test_reg_list_names();

        return rc;
}

static int test_reg_create_proc(void)
{
        struct proc_info info = TEST_PROC_INFO;

        TEST_START();

        if (reg_init() < 0) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        if (reg_create_proc(&info) < 0) {
                printf("Failed to create process.\n");
                goto fail;
        }

        if (reg.procs.len != 1) {
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

        if (!llist_is_empty(&reg.procs)) {
                printf("n_procs was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_proc(void)
{
        int rc = 0;

        rc |= test_reg_create_proc();

        return rc;
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

        if (reg.spawned.len != 1) {
                printf("n_spawned was not updated.\n");
                goto fail;
        }

        if (!reg_has_spawned(TEST_PID)) {
                printf("Failed to find spawned.\n");
                goto fail;
        }

        if (reg_destroy_proc(TEST_PID) < 0) {
                printf("Failed to destroy spawned.\n");
                goto fail;
        }

        if (!llist_is_empty(&reg.spawned)) {
                printf("n_spawned was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
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

        if (reg.progs.len != 1) {
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

        if (!llist_is_empty(&reg.progs)) {
                printf("n_progs was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_reg_prog(void)
{
        int rc = 0;

        rc |= test_reg_create_prog();

        return rc;
}

static int test_bind_proc(void)
{
        struct proc_info pinfo = TEST_PROC_INFO;

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

        return TEST_RC_SUCCESS;
fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
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

        return TEST_RC_SUCCESS;
fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
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

        struct proc_info procinfo = TEST_PROC_INFO;

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

        return TEST_RC_SUCCESS;
fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_wait_accepting_timeout(void)
{
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_MS(1);
        int              flow_id;
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

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        flow_id = reg_wait_flow_accepting(ninfo.name, &abstime);
        if (flow_id != -ETIMEDOUT) {
                printf("Wait accept did not time out: %d.\n", flow_id);
                goto fail;
        }

        reg_destroy_name(TEST_NAME);

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_wait_accepting_fail_name(void)
{
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_S(1);
        int              flow_id;

        TEST_START();

        if (reg_init()) {
                printf("Failed to init registry.\n");
                goto fail;
        }

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        flow_id = reg_wait_flow_accepting(TEST_NAME, &abstime);
        if (flow_id != -ENAME) {
                printf("Wait accept did not fail: %d.\n", flow_id);
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static void * test_call_flow_accept(void * o)
{
        struct timespec abstime;
        struct timespec timeo = TIMESPEC_INIT_MS(10);
        buffer_t        pbuf = BUF_INIT;

        struct proc_info pinfo = TEST_PROC_INFO;

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

        reg_prepare_flow_accept(&info);

        clock_gettime(PTHREAD_COND_CLOCK, &abstime);
        ts_add(&abstime, &timeo, &abstime);

        if (reg_wait_flow_accepted(&info, &pbuf, &abstime) != -ETIMEDOUT) {
                printf("Wait allocated did not timeout.\n");
                goto fail;
        }

        if (reg_unbind_proc((char *) o, pinfo.pid) < 0) {
                printf("Failed to unbind proc.\n");
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
        struct timespec  timeo = TIMESPEC_INIT_S(10);
        pthread_t        thr;
        int              flow_id;
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

        flow_id = reg_wait_flow_accepting(ninfo.name, &abstime);
        if (flow_id < 0) {
                printf("Wait accept did not return a flow id: %d.\n", flow_id);
                pthread_join(thr, NULL);
                reg_destroy_name(TEST_NAME);
                reg_fini();
                goto fail;
        }

        pthread_join(thr, NULL);

        reg_destroy_name(TEST_NAME);

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_wait_accepting(void)
{
        int rc = 0;

        rc |= test_wait_accepting_timeout();
        rc |= test_wait_accepting_fail_name();
        rc |= test_wait_accepting_success();

        return rc;
}

static int test_wait_ipcp_boot_timeout(void)
{
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_MS(1);
        struct ipcp_info info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_INIT  /* set by spawn_ipcp */
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

        if (reg_destroy_proc(info.pid) < 0) {
                printf("Failed to destroy ipcp.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
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
        struct timespec  timeo = TIMESPEC_INIT_S(10);
        pthread_t        thr;
        struct ipcp_info info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_INIT /* set by spawn_ipcp */
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

        info.state = IPCP_INIT;

        if (reg_wait_ipcp_boot(&info, &abstime) == 0) {
                printf("IPCP boot reported success.\n");
                pthread_join(thr, NULL);
                reg_destroy_proc(info.pid);
                reg_fini();
                goto fail;
        }

        pthread_join(thr, NULL);

        if (reg_destroy_proc(info.pid) < 0) {
                printf("Failed to destroy ipcp.\n");
                goto fail;
        }

        if (!llist_is_empty(&reg.ipcps)) {
                printf("ipcps.len was not updated.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_wait_ipcp_boot_success(void)
{
        pthread_t        thr;
        struct timespec  abstime;
        struct timespec  timeo = TIMESPEC_INIT_S(10);
        struct ipcp_info info = {
                .name  = TEST_IPCP,
                .pid   = TEST_PID,
                .state = IPCP_INIT /* set by spawn_ipcp */
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

        info.state = IPCP_INIT;

        if (reg_wait_ipcp_boot(&info, &abstime) < 0) {
                printf("IPCP boot failed.\n");
                pthread_join(thr, NULL);
                reg_destroy_proc(info.pid);
                reg_fini();
                goto fail;
        }

        pthread_join(thr, NULL);

        if (info.state != IPCP_OPERATIONAL) {
                printf("IPCP boot succeeded in non-operational state.\n");
                reg_destroy_proc(info.pid);
                reg_fini();
                goto fail;
        }

        if (reg_destroy_proc(info.pid) < 0) {
                printf("Failed to destroy ipcp.\n");
                goto fail;
        }

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_wait_ipcp_boot(void)
{
        int rc = 0;

        rc |= test_wait_ipcp_boot_timeout();
        rc |= test_wait_ipcp_boot_fail();
        rc |= test_wait_ipcp_boot_success();

        return rc;
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

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
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
        struct timespec  timeo = TIMESPEC_INIT_S(10);
        pthread_t        thr;
        struct proc_info info = TEST_PROC_INFO;

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
                pthread_join(thr, NULL);
                reg_destroy_proc(info.pid);
                reg_fini();
                goto fail;
        }

        pthread_join(thr, NULL);

        reg_destroy_proc(info.pid);

        reg_fini();

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        REG_TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_wait_proc(void)
{
        int rc = 0;

        rc |= test_wait_proc_timeout();
        rc |= test_wait_proc_success();

        return rc;
}

int reg_test(int     argc,
             char ** argv)
{
        int rc = 0;

        (void) argc;
        (void) argv;

        rc |= test_reg_init();
        rc |= test_reg_flow();
        rc |= test_reg_ipcp();
        rc |= test_reg_name();
        rc |= test_reg_proc();
        rc |= test_reg_prog();
        rc |= test_reg_spawned();
        rc |= test_bind_proc();
        rc |= test_bind_prog();
        rc |= test_inherit_prog();
        rc |= test_wait_accepting();
        rc |= test_wait_ipcp_boot();
        rc |= test_wait_proc();

        return rc;
}
