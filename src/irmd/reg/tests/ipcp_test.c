/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * The IPC Resource Manager - Registry - IPCPs - Unit Tests
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

#include <ouroboros/test.h>

#include "../ipcp.c"

#define TEST_PID 65535

static int test_reg_ipcp_create(void)
{
        struct reg_ipcp *  ipcp;
        struct ipcp_info   info = {
                .pid   = TEST_PID,
                .state = IPCP_BOOT
        };
        struct layer_info layer = {
                .name = "testlayer",
                .dir_hash_algo = DIR_HASH_SHA3_224
        };

        TEST_START();

        ipcp = reg_ipcp_create(&info);
        if (ipcp == NULL) {
                printf("Failed to create ipcp.\n");
                goto fail;
        }

        if (strcmp(ipcp->layer.name, "Not enrolled.") != 0) {
                printf("Layer name was not set.\n");
                goto fail;
        }

        ipcp->info.state = IPCP_OPERATIONAL;

        reg_ipcp_set_layer(ipcp, &layer);

        if (strcmp(ipcp->layer.name, layer.name) != 0) {
                printf("Layer name was not set.\n");
                goto fail;
        }

        if (ipcp->info.state != IPCP_OPERATIONAL) {
                printf("IPCP state was not set.\n");
                goto fail;
        }

        reg_ipcp_destroy(ipcp);

        TEST_SUCCESS();

        return 0;
 fail:
        TEST_FAIL();
        return -1;
}

int ipcp_test(int     argc,
              char ** argv)
{
        int res = 0;

        (void) argc;
        (void) argv;

        res |= test_reg_ipcp_create();

        return res;
}
