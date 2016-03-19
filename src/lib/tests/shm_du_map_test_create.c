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
#include <ouroboros/common.h>
#include <sys/mman.h>

int shm_du_map_test_create(int argc, char ** argv)
{
        struct shm_du_map * dum;
        struct shm_du_map * dum2;

        shm_unlink(SHM_DU_MAP_FILENAME);

        dum = shm_du_map_create();

        if (dum == NULL)
                return -1;

        dum2 = shm_du_map_open();

        if (dum2 == NULL) {
                shm_du_map_close(dum);
                return 1;
        }

        shm_du_map_close(dum2);

        shm_du_map_close(dum);

        return 0; /* tests succeeded */
}
