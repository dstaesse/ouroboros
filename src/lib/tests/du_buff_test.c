/*
 * Ouroboros - Copyright (C) 2016
 *
 * Test of the du_buff
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

#include "du_buff.c"

#define TEST_BUFF_SIZE 16 * DU_BUFF_BLOCKSIZE
#define MAX(a,b) a > b ? a : b

int du_buff_test(int argc, char ** argv)
{
        int i, j, k;
        int i_inc, j_inc, k_inc;

        uint8_t bits[TEST_BUFF_SIZE];

        for (i = 0; i < TEST_BUFF_SIZE; i++)
                bits[i] = 170;

        i_inc = MAX(1, DU_BUFF_BLOCKSIZE / 4);
        j_inc = MAX(1, DU_BUFF_BLOCKSIZE / 8);
        k_inc = MAX(1, DU_BUFF_BLOCKSIZE / 16);

        for (i = DU_BUFF_BLOCKSIZE / 4; i <= TEST_BUFF_SIZE; i += i_inc) {
                for (j = 0; j < i; j += j_inc) {
                        for (k = 0; k < i - j; k += k_inc) {
                                du_buff_t * dub = du_buff_create(i);
                                if (dub == NULL)
                                        return -1;

                                if (du_buff_init(dub, k, bits, j) < 0)
                                        return -1;

                                du_buff_destroy (dub);
                        }
                }
        }
        return 0; /* tests succeeded */
}
