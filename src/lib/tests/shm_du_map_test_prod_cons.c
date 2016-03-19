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

#define TEST_BUFF_SIZE (3 * SHM_DU_BLOCK_DATA_SIZE)

#define MAX(a,b) (a > b ? a : b)
#define MIN(a,b) (a < b ? a : b)

int * sync;

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
        long                overruns = 0;

        dum = shm_du_map_open();
        if (dum == NULL)
                return (void *)-1;

        srand(time(NULL));
        clock_gettime(CLOCK_MONOTONIC, &starttime);

        test_values = malloc (sizeof *test_values * TEST_BUFF_SIZE);
        for (i = 0; i < TEST_BUFF_SIZE; i++)
                test_values[i] = 170;

        for (i = 0; i < 4 * SHM_BLOCKS_IN_MAP; i++) {
                struct shm_du_buff * sdb;
                size_t               len;
                struct timespec      ts;

                test_buf_size = rand() % (TEST_BUFF_SIZE - 512) + 512;

                headspace     = MAX(4, rand() % 64);
                tailspace     = MAX(1, rand() % 24);

                ts.tv_sec     = 0;
                ts.tv_nsec    = rand() % 90000;

                len = test_buf_size - (headspace + tailspace);

                sdb = shm_create_du_buff(dum,
                                         test_buf_size,
                                         headspace,
                                         test_values,
                                         len);

                if (sdb != NULL) {
                        sync[i] = du_buff_ptr_to_idx(dum, sdb);
                        bytes_written += len;
                }
                else {
                        i--;
                        ++overruns;
                        ts.tv_nsec = 10000;
                        nanosleep(&ts, NULL);
                }
                nanosleep(&ts, NULL);

                if (overruns > 100) {
                        LOG_INFO("Bugging out due to overruns.");
                        sync[i+1] = -2;
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
        return 0;
}

void * consume()
{
        struct shm_du_map * dum;

        long                i;

        struct timespec     ts;

        ts.tv_sec = 0;
        ts.tv_nsec = 5000;

        dum = shm_du_map_open();

        if (dum == NULL)
                pthread_exit((void *) -1);

        for (i = 0; i < 4 * SHM_BLOCKS_IN_MAP; i++) {
                while (sync[i] == -1)
                        nanosleep(&ts, NULL); /* wait for the producer */
                if (sync[i] == -2)
                        break;
                shm_release_du_buff(dum, idx_to_du_buff_ptr(dum, sync[i]));
        }

        shm_du_map_close(dum);

        return 0;
}

int shm_du_map_test_prod_cons(int argc, char ** argv)
{
        struct shm_du_map * dum;

        int res1;

        int i;

        pthread_t producer;
        pthread_t consumer;

        shm_unlink(SHM_DU_MAP_FILENAME);

        dum = shm_du_map_create();

        if (dum == NULL)
                return -1;

        sync = malloc(sizeof *sync * 4 * SHM_BLOCKS_IN_MAP);

        for (i = 0; i < 4 * SHM_BLOCKS_IN_MAP; i++)
                sync[i] = -1;

        res1 = (int) pthread_create(&producer, NULL, produce, NULL);
        pthread_create(&consumer, NULL, consume, NULL);

        pthread_join(producer, NULL);
        pthread_join(consumer, NULL);

        free(sync);

        shm_du_map_close(dum);

        return res1;
}
