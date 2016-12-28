/*
 * Ouroboros - Copyright (C) 2016
 *
 * Functions to construct pathnames
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "pathnames"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/errno.h>

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "pathname.h"

char * pathname_create(const char * name)
{
        char * tmp;

        assert(name);

        tmp = malloc(strlen(name) + strlen(PATH_DELIMITER) + 1);
        if (tmp == NULL)
                return NULL;

        strcpy(tmp, PATH_DELIMITER);
        strcat(tmp, name);

        return tmp;
}

char * pathname_append(char *       pname,
                       const char * name)
{
        char * tmp;

        assert(pname);
        assert(name);

        tmp = malloc(strlen(pname) +
                     strlen(PATH_DELIMITER) +
                     strlen(name) + 1);
        if (tmp == NULL)
                return NULL;

        strcpy(tmp, pname);
        strcat(tmp, PATH_DELIMITER);
        strcat(tmp, name);

        free(pname);

        return tmp;
}

void pathname_destroy(char * pname)
{
        free(pname);
}
