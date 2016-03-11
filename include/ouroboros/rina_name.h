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

#ifndef RINA_NAME_H
#define RINA_NAME_H

#include "common.h"

typedef struct {
        char *       ap_name;
        unsigned int api_id;
        char *       ae_name;
        unsigned int aei_id;
} rina_name_t;

/*
 * Allocates a new name, returning the allocated object.
 * In case of an error, a NULL is returned.
 */
rina_name_t * name_create();

/*
 * Initializes a previously dynamically allocated name (i.e. name_create())
 * or a statically one (e.g. declared into a struct not as a pointer).
 * Returns the passed object pointer in case everything is ok, a NULL
 * otherwise.
 *
 * A call to name_destroy() is allowed in case of error, in order to
 * release the associated resources.
 *
 * It is allowed to call name_init() over an already initialized object
 */
rina_name_t * name_init_from(rina_name_t * dst,
                             const char *  ap_name,
                             unsigned int  api_id,
                             const char *  ae_name,
                             unsigned int  aei_id);

/* Takes ownership of the passed parameters */
rina_name_t * name_init_with(rina_name_t * dst,
                             char *        ap_name,
                             unsigned int  api_id,
                             char *        ae_name,
                             unsigned int  aei_id);

/*
 * Finalize a name object, releasing all the embedded resources (without
 * releasing the object itself). After name_fini() execution the passed
 * object will be in the same states as at the end of name_init().
 */
void          name_fini(rina_name_t * dst);

/* Releases all the associated resources bound to a name object */
void          name_destroy(rina_name_t * ptr);

/* Duplicates a name object, returning the pointer to the new object */
rina_name_t * name_dup(const rina_name_t * src);

/*
 * Copies the source object contents into the destination object, both must
 * be previously allocated
 */
int           name_cpy(const rina_name_t * src, rina_name_t * dst);

bool          name_is_equal(const rina_name_t * a, const rina_name_t * b);
bool          name_is_ok(const rina_name_t * n);

#define NAME_CMP_APN 0x01
#define NAME_CMP_API 0x02
#define NAME_CMP_AEN 0x04
#define NAME_CMP_AEI 0x08
#define NAME_CMP_ALL (NAME_CMP_APN | NAME_CMP_API | NAME_CMP_AEN | NAME_CMP_AEI)

bool          name_cmp(uint8_t             flags,
                       const rina_name_t * a,
                       const rina_name_t * b);

/* Returns a name as a (newly allocated) string */
char *        name_to_string(const rina_name_t * n);

/* Inverse of name_tostring() */
rina_name_t * string_to_name(const char * s);

#endif
