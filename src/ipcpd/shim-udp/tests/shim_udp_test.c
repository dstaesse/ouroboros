/*
 * Ouroboros - Copyright (C) 2016
 *
 * Test of the Shim UDP IPCP Daemon
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#include <ouroboros/config.h>
#include <ouroboros/dif_config.h>
#include <ouroboros/utils.h>
#include <ouroboros/shm_du_map.h>
#include <sys/types.h>
#include <stdlib.h>
#include "main.c"

#include <ouroboros/logs.h>

struct ipcp * _ipcp;

int shim_udp_test(int argc, char ** argv)
{
        /* argument 1: pid of irmd ? */
        /* argument 2: ap name */
        /* argument 3: instance id */
        struct shm_du_map * dum;
        char * ipcp_name = "test-shim-ipcp";
        int i = 0;

        char bogus[16];
        memset(&bogus, 0, 16);

        struct dif_config conf;
        memset(&conf, 0, sizeof conf);
        conf.dif_name = strdup("test-dif");
        conf.type = IPCP_SHIM_UDP;
        conf.ip_addr = 0;

        dum = shm_du_map_create();
        if (dum == NULL) {
                LOG_ERR("Failed to create shared memory.");
                exit(1);
        }

        _ipcp = ipcp_udp_create(ipcp_name);
        if (_ipcp == NULL) {
                LOG_ERR("Could not instantiate shim IPCP.");
                shm_du_map_close(dum);
                exit(1);
        }

        if (ipcp_udp_bootstrap(&conf)) {
                LOG_ERR("Could not bootstrap.");
        }

        if (ipcp_udp_name_reg("bogus name")) {
                LOG_ERR("Failed to register application.");
                shm_du_map_close(dum);
                exit(1);
        }

        if (ipcp_udp_name_unreg("bogus name")) {
                LOG_ERR("Failed to unregister application.");
                shm_du_map_close(dum);
                exit(1);
        }

        for (i = 0; i  < 1000; ++i) {
                sprintf(bogus, "bogus name %4d", i);
                if (ipcp_udp_name_reg(bogus)) {
                         LOG_ERR("Failed to register application %s.", bogus);
                         shm_du_map_close(dum);
                         exit(1);
                }
        }

        for (i = 0; i  < 1000; ++i) {
                sprintf(bogus, "bogus name %4d", i);
                if(ipcp_udp_name_unreg(bogus)) {
                         LOG_ERR("Failed to unregister application %s.", bogus);
                         shm_du_map_close(dum);
                         exit(1);
                }
        }

        shm_du_map_close(dum);

        exit(0);
}
