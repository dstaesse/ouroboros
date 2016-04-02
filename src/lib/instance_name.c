/*
 * RINA naming related utilities
 *
 *    Sander Vrijders       <sander.vrijders@intec.ugent.be>
 *    Francesco Salvestrini <f.salvestrini@nextworks.it>
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

#define OUROBOROS_PREFIX "instance-name"

#include <ouroboros/logs.h>
#include <ouroboros/common.h>
#include <ouroboros/instance_name.h>
#include <ouroboros/utils.h>

#include <string.h>
#include <math.h>
#include <stdlib.h>

instance_name_t * instance_name_create()
{
        instance_name_t * tmp;

        tmp = malloc(sizeof *tmp);

        tmp->name = NULL;
        tmp->id  = 0;

        return tmp;
}

instance_name_t * instance_name_init_from(instance_name_t * dst,
                                          const char *      name,
                                          uint16_t          id)
{
        if (dst == NULL)
                return NULL;

        /* Clean up the destination, leftovers might be there ... */
        instance_name_fini(dst);

        dst->name = strdup(name);
        dst->id = id;

        if (dst->name == NULL) {
                instance_name_fini(dst);
                return NULL;
        }

        return dst;
}

instance_name_t * instance_name_init_with(instance_name_t * dst,
                                          char *      name,
                                          uint16_t          id)
{
        if (dst == NULL)
                return NULL;

        /* Clean up the destination, leftovers might be there ... */
        instance_name_fini(dst);

        dst->name = name;
        dst->id  = id;

        return dst;
}

void instance_name_fini(instance_name_t * n)
{
        if (n == NULL || n->name == NULL)
                return;

        free(n->name);
        n->name = NULL;
}

void instance_name_destroy(instance_name_t * ptr)
{
        if (ptr == NULL)
                return;

        instance_name_fini(ptr);

        free(ptr);
}

int instance_name_cpy(instance_name_t *       dst,
                      const instance_name_t * src)
{
        instance_name_t * res;

        if (src == NULL || dst == NULL)
                return -1;

        res = instance_name_init_from(dst, src->name, src->id);
        if (res == NULL)
                return -1;

        return 0;
}

instance_name_t * instance_name_dup(const instance_name_t * src)
{
        instance_name_t * tmp;

        if (src == NULL)
                return NULL;

        tmp = instance_name_create();
        if (tmp == NULL)
                return NULL;

        if (instance_name_cpy(tmp, src)) {
                instance_name_destroy(tmp);
                return NULL;
        }

        return tmp;
}

bool instance_name_is_valid(const instance_name_t * n)
{
        return (n != NULL && n->name != NULL && strlen(n->name));
}

int instance_name_cmp(const instance_name_t * a,
                      const instance_name_t * b)
{

        int ret = 0;

        if (a == NULL || b == NULL) {
                LOG_DBGF("Won't compare NULL.");
                return -2;
        }

        if (a == b)
                return 0;

        ret = strcmp(a->name, b->name);

        if (!ret) {
                if (a->id == b-> id)
                        return 0;
                else
                        return a->id < b->id ? -1 : 1;
        }

        return ret;
}



#define DELIMITER "/"

char * instance_name_to_string(const instance_name_t * n)
{
        char *       tmp;
        size_t       size;
        const char * none     = "";
        size_t       none_len = strlen(none);

        if (n == NULL)
                return NULL;

        size = 0;

        size += (n->name != NULL ?
                 strlen(n->name) : none_len);
        size += strlen(DELIMITER);

        size += (n->id == 0 ?
                 1 : n_digits(n->id));
        size += strlen(DELIMITER);

        tmp = malloc(size);
        if (!tmp)
                return NULL;

        if (sprintf(tmp, "%s%s%d",
                    (n->name != NULL ? n->name : none),
                    DELIMITER, n->id)
            != size - 1) {
                free(tmp);
                return NULL;
        }

        return tmp;
}

instance_name_t * string_to_instance_name(const char * s)
{
        instance_name_t * name;

        char *       tmp1      = NULL;
        char *       tmp_ap    = NULL;
        char *       tmp_s_api = NULL;
        unsigned int tmp_api   = 0;
        char *       tmp2;

        if (s == NULL)
                return NULL;

        tmp1 = strdup(s);
        if (tmp1 == NULL) {
                return NULL;
        }

        tmp_ap = strtok(tmp1, DELIMITER);
        tmp_s_api = strtok(NULL, DELIMITER);
        if (tmp_s_api != NULL)
                tmp_api = (unsigned int) strtol(tmp_s_api, &tmp2, 10);

        name = instance_name_create();
        if (name == NULL) {
                if (tmp1 != NULL)
                        free(tmp1);
                return NULL;
        }

        if (!instance_name_init_from(name, tmp_ap, tmp_api)) {
                instance_name_destroy(name);
                if (tmp1 != NULL)
                        free(tmp1);
                return NULL;
        }

        if (tmp1 != NULL)
                free(tmp1);

        return name;
}
