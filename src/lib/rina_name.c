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

#define OUROBOROS_PREFIX "name-utils"

#include <ouroboros/logs.h>
#include <ouroboros/common.h>
#include <ouroboros/rina_name.h>
#include <ouroboros/utils.h>

#include <string.h>
#include <math.h>
#include <malloc.h>
#include <stdlib.h>

static char * strdup(const char * src)
{
        int len = 0;
        char * dst = NULL;

        if (src == NULL)
                return NULL;

        len = strlen(src) + 1;

        dst = malloc(len);
        if (dst == NULL)
                return NULL;

        memcpy(dst, src, len);

        return dst;
}

rina_name_t * name_create()
{
        rina_name_t * tmp;

        tmp = malloc(sizeof(rina_name_t));

        tmp->ap_name = NULL;
        tmp->api_id  = 0;
        tmp->ae_name = NULL;
        tmp->aei_id  = 0;

        return tmp;
}

rina_name_t * name_init_from(rina_name_t * dst,
                             const char *  ap_name,
                             unsigned int  api_id,
                             const char *  ae_name,
                             unsigned int  aei_id)
{
        if (dst == NULL)
                return NULL;

        /* Clean up the destination, leftovers might be there ... */
        name_fini(dst);

        dst->ap_name = strdup(ap_name);
        dst->api_id = api_id;
        dst->ae_name = strdup(ae_name);
        dst->aei_id = aei_id;

        if (dst->ap_name == NULL ||
            dst->ae_name == NULL) {
                name_fini(dst);
                return NULL;
        }

        return dst;
}

rina_name_t * name_init_with(rina_name_t * dst,
                             char *        ap_name,
                             unsigned int  api_id,
                             char *        ae_name,
                             unsigned int  aei_id)
{
        if (dst == NULL)
                return NULL;

        /* Clean up the destination, leftovers might be there ... */
        name_fini(dst);

        dst->ap_name = ap_name;
        dst->api_id  = api_id;
        dst->ae_name = ae_name;
        dst->aei_id  = aei_id;

        return dst;
}

void name_fini(rina_name_t * n)
{
        if (n == NULL)
                return;

        if (n->ap_name != NULL) {
                free(n->ap_name);
                n->ap_name = NULL;
        }

        if (n->ae_name != NULL) {
                free(n->ae_name);
                n->ae_name = NULL;
        }
}

void name_destroy(rina_name_t * ptr)
{
        if (ptr == NULL)
                return;

        name_fini(ptr);

        free(ptr);
}

int name_cpy(const rina_name_t * src,
             rina_name_t *       dst)
{
        rina_name_t * res;

        if (src == NULL || dst == NULL)
                return -1;

        res = name_init_from(dst,
                             src->ap_name,
                             src->api_id,
                             src->ae_name,
                             src->aei_id);
        if (res == NULL)
                return -1;

        return 0;
}

rina_name_t * name_dup(const rina_name_t * src)
{
        rina_name_t * tmp;

        if (src == NULL)
                return NULL;

        tmp = name_create();
        if (tmp == NULL)
                return NULL;

        if (name_cpy(src, tmp)) {
                name_destroy(tmp);
                return NULL;
        }

        return tmp;
}

#define NAME_CMP_FIELD(X, Y, FIELD)                           \
        ((X->FIELD != NULL && Y->FIELD != NULL) ?             \
         strcmp(X->FIELD, Y->FIELD) :                         \
         ((X->FIELD == NULL && Y->FIELD == NULL) ? 0 : -1))

bool name_is_ok(const rina_name_t * n)
{ return (n != NULL &&
          n->ap_name != NULL &&
          strlen(n->ap_name) &&
          n->ae_name != NULL); }

bool name_cmp(uint8_t             flags,
              const rina_name_t * a,
              const rina_name_t * b)
{
        if (a == b)
                return true;

        if (a == NULL || b == NULL)
                return false;

        if (!(flags & NAME_CMP_ALL))
                LOG_DBG("No flags, name comparison will be meaningless ...");

        if (flags & NAME_CMP_APN)
                if (NAME_CMP_FIELD(a, b, ap_name))
                        return false;

        if (flags & NAME_CMP_API)
                if (a->api_id !=  b->api_id)
                        return false;

        if (flags & NAME_CMP_AEN)
                if (NAME_CMP_FIELD(a, b, ae_name))
                        return false;

        if (flags & NAME_CMP_AEI)
                if (a->aei_id != b->aei_id)
                        return false;

        return true;
}

bool name_is_equal(const rina_name_t * a,
                   const rina_name_t * b)
{ return name_cmp(NAME_CMP_ALL, a, b); }

#define DELIMITER "/"

char * name_to_string(const rina_name_t * n)
{
        char *       tmp;
        size_t       size;
        const char * none     = "";
        size_t       none_len = strlen(none);

        if (n == NULL)
                return NULL;

        size  = 0;

        size += (n->ap_name != NULL ?
                 strlen(n->ap_name) : none_len);
        size += strlen(DELIMITER);

        size += (n->api_id == 0 ?
                 1 : n_digits(n->api_id));
        size += strlen(DELIMITER);

        size += (n->ae_name != NULL ?
                 strlen(n->ae_name) : none_len);
        size += strlen(DELIMITER);

        size += (n->aei_id == 0 ?
                 1 : n_digits(n->aei_id));
        size += strlen(DELIMITER);

        tmp = malloc(size);
        if (!tmp)
                return NULL;

        if (sprintf(tmp, "%s%s%d%s%s%s%d",
                    (n->ap_name != NULL ? n->ap_name : none),
                    DELIMITER, n->api_id,
                    DELIMITER, (n->ae_name != NULL ? n->ae_name : none),
                    DELIMITER, n->aei_id)
            != size - 1) {
                free(tmp);
                return NULL;
        }

        return tmp;
}

rina_name_t * string_to_name(const char * s)
{
        rina_name_t * name;

        char *       tmp1      = NULL;
        char *       tmp_ap    = NULL;
        char *       tmp_s_api = NULL;
        unsigned int tmp_api   = 0;
        char *       tmp_ae    = NULL;
        char *       tmp_s_aei = NULL;
        unsigned int tmp_aei   = 0;
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
        tmp_ae = strtok(NULL, DELIMITER);
        tmp_s_aei = strtok(NULL, DELIMITER);
        if (tmp_s_aei != NULL)
                tmp_aei = (unsigned int) strtol(tmp_s_aei, &tmp2, 10);

        name = name_create();
        if (name == NULL) {
                if (tmp1 != NULL)
                        free(tmp1);
                return NULL;
        }

        if (!name_init_from(name, tmp_ap, tmp_api,
                            tmp_ae, tmp_aei)) {
                name_destroy(name);
                if (tmp1 != NULL)
                        free(tmp1);
                return NULL;
        }

        if (tmp1 != NULL)
                free(tmp1);

        return name;
}
