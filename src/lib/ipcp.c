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

int ipcp_create(rina_name_t name,
                char * ipcp_type)
{
        /* zero means failure */
        return 0;
}

int ipcp_destroy(int pid)
{
        return -1;
}

int ipcp_reg(int pid,
             char ** difs,
             size_t difs_size)
{
        return -1;
}

int ipcp_unreg(int pid,
               char ** difs,
               size_t difs_size)
{
        return -1;
}

int ipcp_bootstrap(int pid,
                   struct dif_config conf)
{
        return -1;
}

int ipcp_enroll(int pid,
                char * dif_name,
                rina_name_t member,
                char ** n_1_difs,
                ssize_t n_1_difs_size)
{
        return -1;
}
