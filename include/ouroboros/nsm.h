/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The API to instruct the global Namespace Manager
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_NSM_H
#define OUROBOROS_NSM_H

#include <ouroboros/cdefs.h>

#include <stdint.h>
#include <unistd.h>

__BEGIN_DECLS

int    nsm_reg(char *  name,
               char ** dafs,
               size_t  dafs_size);

int    nsm_unreg(char *  name,
                 char ** dafs,
                 size_t  dafs_size);

/*
 * dafs is an out parameter
 * The amount of DAFs is returned
 */
ssize_t nsm_resolve(char *  name,
                    char ** dafs);

__END_DECLS

#endif
