/*
 * Ouroboros - Copyright (C) 2016
 *
 * The API to instruct the global Namespace Manager
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <ouroboros/nsm.h>

int nsm_reg(char * name,
            char ** dafs,
            size_t dafs_size)
{
        (void) name;
        (void) dafs;
        (void) dafs_size;

        return -1;
}

int nsm_unreg(char * name,
              char ** dafs,
              size_t dafs_size)
{
        (void) name;
        (void) dafs;
        (void) dafs_size;


        return -1;
}

ssize_t nsm_resolve(char * name,
                    char ** dafs)
{
        (void) name;
        (void) dafs;

        return -1;
}
