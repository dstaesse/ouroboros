/*
 * Ouroboros - Copyright (C) 2016 - 2022
 *
 * Unit tests of the DHT
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#define __DHT_TEST__
#define DHT_TEST_KEY_LEN  32

#include "dht.c"

#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#define CONTACTS          1000

int dht_test(int     argc,
             char ** argv)
{
        struct dht * dht;
        uint8_t      key[DHT_TEST_KEY_LEN];
        size_t       i;

        (void) argc;
        (void) argv;

        dht = dht_create();
        if (dht == NULL) {
                printf("Failed to create dht.\n");
                return -1;
        }

        dht_destroy(dht);

        dht = dht_create();
        if (dht == NULL) {
                printf("Failed to re-create dht.\n");
                return -1;
        }

        if (dht_bootstrap(dht)) {
                printf("Failed to bootstrap dht.\n");
                dht_destroy(dht);
                return -1;
        }

        dht_destroy(dht);

        dht = dht_create();
        if (dht == NULL) {
                printf("Failed to re-create dht.\n");
                return -1;
        }

        if (dht_bootstrap(dht)) {
                printf("Failed to bootstrap dht.\n");
                dht_destroy(dht);
                return -1;
        }

        for (i = 0; i < CONTACTS; ++i) {
                uint64_t addr;
                random_buffer(&addr, sizeof(addr));
                random_buffer(key, DHT_TEST_KEY_LEN);
                pthread_rwlock_wrlock(&dht->lock);
                if (dht_update_bucket(dht, key, addr)) {
                        pthread_rwlock_unlock(&dht->lock);
                        printf("Failed to update bucket.\n");
                        dht_destroy(dht);
                        return -1;
                }
                pthread_rwlock_unlock(&dht->lock);
        }

        dht_destroy(dht);

        return 0;
}
