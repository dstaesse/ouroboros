/*
 * Ouroboros - Copyright (C) 2016
 *
 * The API to instruct IPCPs
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

#include <ouroboros/ipcp.h>

struct ipcp {};

struct ipcp * ipcp_create(rina_name_t name,
                          char * ipcp_type)
{
        return NULL;
}

int ipcp_destroy(struct ipcp * instance)
{
        return -1;
}

int ipcp_reg(struct ipcp * instance,
             char ** difs,
             size_t difs_size)
{
        return -1;
}

int ipcp_unreg(struct ipcp * instance,
               char ** difs,
               size_t difs_size)
{
        return -1;
}

int ipcp_bootstrap(struct ipcp * instance,
                   struct dif_config conf)
{
        return -1;
}

int ipcp_enroll(struct ipcp * instance,
                char * dif_name,
                rina_name_t member)
{
        return -1;
}
