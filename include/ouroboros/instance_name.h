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

#ifndef INSTANCE_NAME_H
#define INSTANCE_NAME_H

#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>

typedef struct {
        char *   name;
        uint16_t id;
} instance_name_t;

/*
 * Allocates a new name, returning the allocated object.
 * In case of an error, a NULL is returned.
 */
instance_name_t * instance_name_create();

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
instance_name_t * instance_name_init_from(instance_name_t * dst,
                                          const char *      name,
                                          uint16_t          api_id);

/* Takes ownership of the passed parameters */
instance_name_t * instance_name_init_with(instance_name_t * dst,
                                          char *            name,
                                          uint16_t          id);

/*
 * Finalize a name object, releasing all the embedded resources (without
 * releasing the object itself). After name_fini() execution the passed
 * object will be in the same states as at the end of name_init().
 */
void          instance_name_fini(instance_name_t * dst);

/* Releases all the associated resources bound to a name object */
void          instance_name_destroy(instance_name_t * ptr);

/* Duplicates a name object, returning the pointer to the new object */
instance_name_t * instance_name_dup(const instance_name_t * src);

/*
 * Copies the source object contents into the destination object, both must
 * be previously allocated
 */
int           instance_name_cpy(instance_name_t * dst,
                                const instance_name_t * src);

int           instance_name_cmp(const instance_name_t * a,
                                const instance_name_t * b);

bool          instance_name_is_valid(const instance_name_t * n);

/* Returns a name as a (newly allocated) string */
char *        instance_name_to_string(const instance_name_t * n);

/* Inverse of name_tostring() */
instance_name_t * string_to_instance_name(const char * s);

#endif /* INSTANCE_NAME_H */
