/*
 * Ouroboros - Copyright (C) 2016
 *
 * Data Unit Buffer
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#include <malloc.h>
#include <string.h>
#include <errno.h>
#include <ouroboros/du_buff.h>
#include <ouroboros/list.h>

#define OUROBOROS_PREFIX "du_buff"

#include "ouroboros/logs.h"

#define DU_BLOCK_DATA_SIZE (DU_BUFF_BLOCK_SIZE - sizeof (struct buffer))

struct buffer {
        uint8_t        * data;
        size_t           size;
        struct list_head list;
};

struct du_buff {
        struct buffer  * buffer;
        size_t           size;
        size_t           du_head;
        size_t           du_tail;
};

void buffer_destroy(struct buffer * buf)
{
        if (buf == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return;
        }

        free (buf->data);
        free (buf);
}

void buffer_destroy_list(struct buffer * head)
{
        struct list_head * ptr;
        struct list_head * n;

        if (head == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return;
        }

        list_for_each_safe(ptr, n, &(head->list)) {
                struct buffer * tmp = list_entry(ptr, struct buffer, list);
                list_del(ptr);
                buffer_destroy(tmp);
        }
}

struct buffer * buffer_create (size_t size, size_t headspace, size_t len)
{
        struct buffer * head = NULL;
        size_t          remaining = size;
        size_t          ts = size - (headspace + len);

        if (headspace > DU_BLOCK_DATA_SIZE || ts > DU_BLOCK_DATA_SIZE)
        {
                LOG_WARN("Illegal du_buff. Cannot fit PCI in DU_BUFF_BLOCK.");
                return NULL;
        }

        head = malloc(sizeof *head);
        if (head == NULL)
                return NULL;

        head->size = 0;
        head->data = NULL;

        INIT_LIST_HEAD(&(head->list));

        while (remaining > 0) {
                struct buffer * buf;

                size_t sz;

                if (size > DU_BLOCK_DATA_SIZE
                           && remaining - ts <=  DU_BLOCK_DATA_SIZE
                           && remaining != ts) {
                        sz = remaining - ts;
                } else if (size >  DU_BLOCK_DATA_SIZE && remaining == ts) {
                        sz = ts;
                } else {
                        sz = remaining <  DU_BLOCK_DATA_SIZE ?
                                remaining :  DU_BLOCK_DATA_SIZE;
                }

                buf = malloc(sizeof *buf);
                if (buf == NULL) {
                        LOG_WARN("Could not allocate struct.");
                        free(head);
                        return NULL;
                }

                if (sz > 0) {
                        buf->data = malloc(sz);
                        if (buf->data == NULL) {
                                LOG_WARN("Could not allocate memory block.");
                                buffer_destroy_list(head);
                                free(head);
                                return NULL;
                        }
                } else {
                        buf->data = NULL;
                }

                buf->size = sz;

                list_add_tail(&(buf->list), &(head->list));

                remaining -= buf->size;
        }

        return head;
}

struct buffer * buffer_seek(const struct buffer * head, size_t pos)
{
        struct list_head * ptr = NULL;
        size_t cur_buf_start   = 0;
        size_t cur_buf_end     = 0;

        if (head == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return NULL;
        }

        list_for_each(ptr, &(head->list)) {
                struct buffer * tmp = list_entry(ptr, struct buffer, list);

                cur_buf_end = cur_buf_start + tmp->size;
                if (cur_buf_end > pos)
                        return tmp;

                cur_buf_start = cur_buf_end;
        }

        return NULL;
}

uint8_t * buffer_seek_pos(const struct buffer * head, size_t pos)
{
        struct list_head * ptr = NULL;
        size_t cur_buf_start   = 0;
        size_t cur_buf_end     = 0;

        if (head == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return NULL;
        }

        list_for_each(ptr, &(head->list)) {
                struct buffer * tmp = list_entry(ptr, struct buffer, list);

                cur_buf_end = cur_buf_start + tmp->size;

                if (cur_buf_end > pos)
                        return tmp->data + (pos - cur_buf_start);

                cur_buf_start = cur_buf_end;
        }

        return NULL;
}

int buffer_copy_data(struct buffer * head,
                     size_t          pos,
                     const void    * src,
                     size_t          len)
{
        struct list_head * ptr       = NULL;
        struct buffer    * buf_start = NULL;
        struct buffer    * buf_end   = NULL;
        uint8_t          * ptr_start = NULL;
        size_t             space_in_buf;
        size_t             bytes_remaining;
        uint8_t          * copy_pos  = NULL;

        if (head == NULL || src == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -EINVAL;
        }

        if (len == 0) {
                LOG_DBGF("Nothing to copy.");
                return 0;
        }

        buf_start = buffer_seek(head, pos);
        buf_end   = buffer_seek(head, pos + len - 1);

        if (buf_start == NULL || buf_end == NULL) {
                LOG_DBGF("Index out of bounds %lu, %lu", pos, pos + len);
                return -EINVAL;
        }

        ptr_start = buffer_seek_pos(head, pos);

        if (buf_start == buf_end) {
                memcpy(ptr_start, src, len);
                return 0;
        }

        copy_pos = (uint8_t *)src;
        bytes_remaining = len;
        list_for_each(ptr, &(head->list)) {
                struct buffer * tmp = list_entry(ptr, struct buffer, list);
                if (tmp != buf_start)
                        continue;

                space_in_buf = (tmp->data + tmp->size) - ptr_start;
                if (space_in_buf >= bytes_remaining) {
                        memcpy(ptr_start, copy_pos, bytes_remaining);
                        return 0;
                }
                else
                        memcpy(ptr_start, copy_pos, space_in_buf);
                bytes_remaining -= space_in_buf;
        }

        return 0;
}

du_buff_t * du_buff_create(size_t size)
{
        du_buff_t * dub = (du_buff_t *)malloc(sizeof(du_buff_t));

        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return NULL;
        }

        dub->buffer  = NULL;
        dub->size    = size;
        dub->du_head = 0;
        dub->du_tail = 0;

        return dub;
}

void du_buff_destroy(du_buff_t * dub)
{
        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return;
        }
        buffer_destroy_list(dub->buffer);

        free (dub);
}

int du_buff_init(du_buff_t * dub,
                 size_t      start,
                 uint8_t   * data,
                 size_t      len)
{
        if (dub == NULL || data == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -EINVAL;
        }

        if (start >= dub->size) {
                LOG_DBGF("Index out of bounds %lu.", start);
                return -EINVAL;
        }

        if (start + len > dub->size) {
                LOG_DBGF("Buffer too small for data.");
                return -EINVAL;
        }

        dub->buffer = buffer_create(dub->size, start, len);
        if (dub->buffer == NULL)
                return -ENOMEM;

        dub->du_head = start;
        dub->du_tail = start + len;

        return buffer_copy_data(dub->buffer, start, data, len);
}

uint8_t * du_buff_head_alloc(du_buff_t * dub, size_t size)
{
        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return NULL;
        }

        if ((long) (dub->du_head - size) < 0) {
                LOG_WARN("Failed to allocate PCI headspace.");
                return NULL;
        }

        dub->du_head -= size;

        return (buffer_seek_pos(dub->buffer, dub->du_head));
}

uint8_t * du_buff_tail_alloc(du_buff_t * dub, size_t size)
{
        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return NULL;
        }

        if (dub->du_tail + size >= dub->size) {
                LOG_WARN("Failed to allocate PCI tailspace.");
                return NULL;
        }

        dub->du_tail += size;

        return (buffer_seek_pos(dub->buffer, dub->du_tail));
}

int du_buff_head_release(du_buff_t * dub, size_t size)
{
        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -EINVAL;
        }

        if (size > dub->du_tail - dub->du_head) {
                LOG_WARN("Tried to release beyond sdu boundary.");
                return -EOVERFLOW;
        }

        dub->du_head += size;

        /* FIXME: copy some random crap to the buffer for security */

        return 0;
}

int du_buff_tail_release(du_buff_t * dub, size_t size)
{
        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -EINVAL;
        }

        if (size > dub->du_tail - dub->du_head) {
                LOG_WARN("Tried to release beyond sdu boundary.");
                return -EOVERFLOW;
        }

        dub->du_tail -= size;

        /* FIXME: copy some random crap to the buffer for security */

        return 0;
}
