/*
 * Ouroboros - Copyright (C) 2016
 *
 * Test of the timer wheel
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

#include "timerwheel.c"

#include <pthread.h>
#include <time.h>
#include <stdlib.h>

#define MAX_ELEMENTS   500
#define MAX_RESOLUTION 10  /* ms */
#define MAX_ADDITIONS  1000

int total;

int add(void * o)
{
        total += *((int *) o);
        return 0;
}

int timerwheel_test(int argc, char ** argv)
{
        struct timerwheel * tw;
        long resolution;
        long elements;
        struct timespec wait;

        int additions;

        int check_total = 0;

        int i;

        (void) argc;
        (void) argv;

        srand(time(NULL));

        total = 0;

        resolution = rand() % (MAX_RESOLUTION - 1) + 1;
        elements = rand() % (MAX_ELEMENTS - 10) + 10;

        tw = timerwheel_create(resolution, resolution * elements);
        if (tw == NULL)
                return -1;

        wait.tv_sec = (resolution * elements) / 1000;
        wait.tv_nsec = ((resolution * elements) % 1000) * MILLION;

        additions = rand() % MAX_ADDITIONS + 1000;

        for (i = 0; i < additions; ++i) {
                int delay = rand() % (resolution * elements);
                int var = rand() % 5;
                check_total += var;
                timerwheel_add(tw,
                               (void (*)(void *)) add,
                               (void *) &var,
                               sizeof(var),
                               delay);
        }

        nanosleep(&wait, NULL);

        timerwheel_destroy(tw);

        if (total != check_total)
                return -1;

        return 0;
}
