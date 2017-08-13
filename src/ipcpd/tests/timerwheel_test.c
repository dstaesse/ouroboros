/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Test of the timer wheel
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#include "timerwheel.c"

#include <pthread.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>

#define MAX_ELEMENTS   100
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

        total = 0;

        srand(time(NULL));

        resolution = rand() % (MAX_RESOLUTION - 1) + 1;
        elements = rand() % (MAX_ELEMENTS - 10) + 10;

        tw = timerwheel_create(resolution, resolution * elements);
        if (tw == NULL) {
                printf("Failed to create timerwheel.\n");
                return -1;
        }

        wait.tv_sec = (resolution * elements) / 1000;
        wait.tv_nsec = ((resolution * elements) % 1000) * MILLION;

        additions = rand() % MAX_ADDITIONS + 1000;

        for (i = 0; i < additions; ++i) {
                int delay = rand() % (resolution * elements);
                int var = rand() % 5;
                check_total += var;
                if (timerwheel_add(tw,
                                   (void (*)(void *)) add,
                                   (void *) &var,
                                   sizeof(var),
                                   delay)) {
                        printf("Failed to add function.");
                        return -1;
                }
        }

        nanosleep(&wait, NULL);

        /* On some systems and VMs, the scheduler may be too slow. */
        if (total != check_total)
                nanosleep(&wait, NULL);

        timerwheel_destroy(tw);

        if (total != check_total) {
                printf("Totals do not match.\n");
                return -1;
        }

        return 0;
}
