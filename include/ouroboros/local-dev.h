/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Optimized calls for the local IPCPs
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#ifndef OUROBOROS_LIB_LOCAL_DEV_H
#define OUROBOROS_LIB_LOCAL_DEV_H

#include <ouroboros/ssm_pool.h>

int     local_flow_transfer(int               src_fd,
                            int               dst_fd,
                            struct ssm_pool * src_pool,
                            struct ssm_pool * dst_pool);

#endif /* OUROBOROS_LIB_LOCAL_DEV_H */
