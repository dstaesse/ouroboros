/*
 * Ouroboros - Copyright (C) 2016
 *
 * Test of the Shared Memory Map
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
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

#include <ouroboros/shm_du_map.h>
#include <sys/types.h>
#include <stdlib.h>
#include <time.h>
#include <pthread.h>
#include "shm_du_map.c"

#define TEST_BUFF_SIZE (SHM_DU_BLOCK_DATA_SIZE)

#define MAX(a,b) (a > b ? a : b)
#define MIN(a,b) (a < b ? a : b)

int sync;

void * produce()
{
        struct shm_du_map * dum;
        long                test_buf_size = 0;
        uint8_t           * test_values;
        int                 headspace;
        int                 tailspace;
        long                i;
        long                bytes_written = 0;
        struct timespec     starttime;
        struct timespec     stoptime;
        double              elapsed;

        dum = shm_du_map_open();
        if (dum == NULL)
                return (void *)-1;

        srand(time(NULL));

        test_values = malloc (sizeof *test_values * TEST_BUFF_SIZE);
        for (i = 0; i < TEST_BUFF_SIZE; i++)
                test_values[i] = 170;

        clock_gettime(CLOCK_MONOTONIC, &starttime);
        for (i = 0; i < SHM_BLOCKS_IN_MAP; i++) {
                struct shm_du_buff * sdb;
                size_t               len;

                test_buf_size = TEST_BUFF_SIZE;

                headspace     = 32;
                tailspace     = 8;

                len = test_buf_size - (headspace + tailspace);

                sdb = shm_create_du_buff(dum,
                                         test_buf_size,
                                         headspace,
                                         test_values,
                                         len);

                if (sdb != NULL) {
                        bytes_written += len;
                }
                else {
                        sync = -2;
                        break;
                }
        }

        clock_gettime(CLOCK_MONOTONIC, &stoptime);
        elapsed =(stoptime.tv_sec + stoptime.tv_nsec / 1000000000.0) -
                (starttime.tv_sec + starttime.tv_nsec / 1000000000.0);
        LOG_INFO("%ld bytes written in %.1lf ms = %lf Gb/s",
                 bytes_written,
                 elapsed * 1000.0,
                 bytes_written * 8 / (elapsed * 1000000000));

        free(test_values);
        shm_du_map_close(dum);

        sync = -1;

        return 0;
}

void * consume()
{
        struct shm_du_map * dum;

        struct timespec     ts;

        ts.tv_sec = 0;
        ts.tv_nsec = 1000;

        dum = shm_du_map_open();

        if (dum == NULL)
                pthread_exit((void *) -1);

        while (!sync) {
                while (!shm_release_du_buff(dum));
                nanosleep(&ts, NULL);
        }

        shm_du_map_close(dum);

        return 0;
}

int shm_du_map_test_prod_cons(int argc, char ** argv)
{
        struct shm_du_map * dum;

        int res1;

        pthread_t producer;
        pthread_t consumer;
        shm_unlink(SHM_DU_MAP_FILENAME);

        dum = shm_du_map_create();

        if (dum == NULL)
                return -1;

        sync = 0;

        res1 = (int) pthread_create(&producer, NULL, produce, NULL);
        pthread_create(&consumer, NULL, consume, NULL);

        pthread_join(producer, NULL);
        pthread_join(consumer, NULL);

        shm_du_map_close(dum);

        return res1;
}
