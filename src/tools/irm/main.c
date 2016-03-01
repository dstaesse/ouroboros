/*
 * Ouroboros - Copyright (C) 2016
 *
 * A tool to instruct the IRM
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "irm"

#include <ouroboros/logs.h>
#include <ouroboros/common.h>
#include <ouroboros/irm.h>

int main () {
        char * ap_name = "test";
        char * ipcp_type = "normal-ipcp";
        rina_name_t name;
        name.ap_name = ap_name;
        name.api_id = 1;
        name.ae_name = "";
        name.aei_id = 0;
        struct dif_info info;
        char * dif_name = "wienerschnitzel";
        size_t difs_size = 1;

        if (irm_create_ipcp(name, ipcp_type)) {
                LOG_ERR("Failed to create IPCP");
                return -1;
        }

        if (irm_destroy_ipcp(name)) {
                LOG_ERR("Failed to destroy IPCP");
                return -1;
        }

        if (irm_bootstrap_ipcp(name, info)) {
                LOG_ERR("Failed to bootstrap IPCP");
                return -1;
        }

        if (irm_enroll_ipcp(name, dif_name)) {
                LOG_ERR("Failed to enroll IPCP");
                return -1;
        }

        if (irm_reg_ipcp(name, &dif_name, difs_size)) {
                LOG_ERR("Failed to register IPCP");
                return -1;
        }

        if (irm_unreg_ipcp(name, &dif_name, difs_size)) {
                LOG_ERR("Failed to unregister IPCP");
                return -1;
        }


        return 0;
}
