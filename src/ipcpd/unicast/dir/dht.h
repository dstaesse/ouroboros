/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * Distributed Hash Table based on Kademlia
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

#ifndef OUROBOROS_IPCPD_UNICAST_DIR_DHT_H
#define OUROBOROS_IPCPD_UNICAST_DIR_DHT_H

#include <ouroboros/ipcp-dev.h>

#include "ops.h"

#include <stdint.h>
#include <sys/types.h>

void *   dht_create(void);

void     dht_destroy(void * dir);

int      dht_bootstrap(void * dir);

int      dht_reg(void *          dir,
                 const uint8_t * key);

int      dht_unreg(void *          dir,
                   const uint8_t * key);

uint64_t dht_query(void *          dir,
                   const uint8_t * key);

int      dht_wait_running(void * dir);

extern struct dir_ops dht_dir_ops;

#endif /* OUROBOROS_IPCPD_UNICAST_DIR_DHT_H */
