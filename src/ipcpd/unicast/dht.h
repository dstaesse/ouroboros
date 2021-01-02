/*
 * Ouroboros - Copyright (C) 2016 - 2021
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

#ifndef OUROBOROS_IPCPD_UNICAST_DHT_H
#define OUROBOROS_IPCPD_UNICAST_DHT_H

#include <ouroboros/ipcp-dev.h>

#include <stdint.h>
#include <sys/types.h>

struct dht;

struct dht * dht_create(uint64_t addr);

int          dht_bootstrap(struct dht * dht,
                           size_t       b,
                           time_t       t_expire);

void         dht_destroy(struct dht * dht);

int          dht_reg(struct dht *    dht,
                     const uint8_t * key);

int          dht_unreg(struct dht *    dht,
                       const uint8_t * key);

uint64_t     dht_query(struct dht *    dht,
                       const uint8_t * key);

int          dht_wait_running(struct dht * dht);

#endif /* OUROBOROS_IPCPD_UNICAST_DHT_H */
