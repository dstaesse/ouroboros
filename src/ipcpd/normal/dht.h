/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Distributed Hash Table based on Kademlia
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OUROBOROS_IPCPD_NORMAL_DHT_H
#define OUROBOROS_IPCPD_NORMAL_DHT_H

#include <ouroboros/ipcp-dev.h>

#include <stdint.h>
#include <sys/types.h>

struct dht;

struct dht * dht_create(uint64_t addr);

int          dht_bootstrap(struct dht * dht,
                           size_t       b,
                           time_t       t_expire);

int          dht_enroll(struct dht * dht,
                        uint64_t     addr);

void         dht_destroy(struct dht * dht);

int          dht_reg(struct dht *    dht,
                     const uint8_t * key);

int          dht_unreg(struct dht *    dht,
                       const uint8_t * key);

uint64_t     dht_query(struct dht *    dht,
                       const uint8_t * key);

#endif /* OUROBOROS_IPCPD_NORMAL_DHT_H */
