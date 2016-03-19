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
#include <sys/mman.h>


#define SHM_DU_BLOCK_DATA_SIZE (SHM_DU_BUFF_BLOCK_SIZE - 3 * sizeof(long))
#define TEST_BUFF_SIZE (16 * SHM_DU_BLOCK_DATA_SIZE)

#define MAX(a,b) (a > b ? a : b)
#define MIN(a,b) (a < b ? a : b)

int shm_du_map_test_du_buff_create(int argc, char ** argv)
{
        struct shm_du_map * dum;
        struct shm_du_map * dum2;

        int i, j, k;
        int i_inc, j_inc, k_inc;

        uint8_t bits[TEST_BUFF_SIZE];

        shm_unlink(SHM_DU_MAP_FILENAME);

        dum = shm_du_map_create();

        if (dum == NULL)
                return -1;

        for (i = 0; i < TEST_BUFF_SIZE; i++)
                bits[i] = 0;

        i_inc = MAX(1, SHM_DU_BLOCK_DATA_SIZE / 4);
        j_inc = MAX(1, SHM_DU_BLOCK_DATA_SIZE / 8);
        k_inc = MAX(1, SHM_DU_BLOCK_DATA_SIZE / 16);

        for (i = SHM_DU_BUFF_BLOCK_SIZE / 4; i <= TEST_BUFF_SIZE; i += i_inc) {
                for (j = 0; j < i; j += j_inc) {
                        for (k = 0; k < i - j; k += k_inc) {
                                if (k > SHM_DU_BLOCK_DATA_SIZE)
                                        continue;

                                if (i - (j + k) > SHM_DU_BLOCK_DATA_SIZE)
                                        continue;

                                struct shm_du_buff * dub = shm_create_du_buff(
                                        dum,
                                        i,
                                        k,
                                        bits,
                                        j);
                                if (dub == NULL) {
                                        shm_du_map_close(dum);
                                        return -1;
                                }
                                shm_release_du_buff(dum, dub);
                        }
                }
        }

        dum2 = shm_du_map_open();

        if (dum2 == NULL) {
                shm_du_map_close(dum);
                return 1;
        }

        shm_du_map_close(dum2);

        shm_du_map_close(dum);

        return 0; /* tests succeeded */
}
