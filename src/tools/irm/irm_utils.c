/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Handy helper functions for the IRM tool
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

#include "irm_utils.h"

int matches(const char * cmd, const char * pattern)
{
        size_t len = strlen(cmd);

        if (len > strlen(pattern))
                return -1;

        return memcmp(pattern, cmd, len);
}
