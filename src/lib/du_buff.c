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
#include "ouroboros/du_buff.h"

#define OUROBOROS_PREFIX "du_buff"

#include "ouroboros/logs.h"

struct buffer {
        uint8_t        * data;
        size_t           size;
        struct list_head list;
};

struct du_buff {
        struct buffer  * buffer;
        size_t           size;
        size_t           du_start;
        size_t           du_end;
        struct list_head list;
};

void buffer_destroy(struct buffer * buf)
{
        if (buf == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return;
        }

        list_del(&(buf->list));

        free (&(buf->data));

        free (buf);
}


void buffer_destroy_list(struct buffer * buf)
{
        struct list_head * ptr;
        struct list_head * n;

        if (buf == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return;
        }

        list_for_each_safe(ptr, n, &(buf->list)) {
                struct buffer * tmp = list_entry(ptr, struct buffer, list);
                list_del(ptr);
                buffer_destroy(tmp);
        }
}

struct buffer * buffer_create (size_t size)
{
        struct buffer * head      = NULL;
        size_t          remaining = size;
        const size_t    page_size = sysconf(_SC_PAGESIZE);

        while (remaining > 0) {
                struct buffer * buf;
                size_t sz = remaining < page_size ? remaining : page_size;

                buf = (struct buffer *) malloc(sizeof(struct buffer));
                if (buf == NULL) {
                        LOG_WARN("Could not allocate struct.");
                        return NULL;
                }

                buf->data = (uint8_t *) malloc(sz);
                if (buf->data == NULL) {
                        LOG_WARN("Could not allocate memory block.");
                        buffer_destroy_list(head);
                        return NULL;
                }

                buf->size = sz;
                INIT_LIST_HEAD(&(buf->list));

                if (head == NULL)
                        head = buf;
                else
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

        buf_start = buffer_seek(head, pos);
        buf_end   = buffer_seek(head, pos + len);

        if (buf_start == NULL || buf_end == NULL) {
                LOG_DBGF("Index out of bounds %d, %d",
                        pos,
                        pos+len);
                return -EINVAL;
        }

        ptr_start = buffer_seek_pos(head, pos);

        if (buf_start == buf_end) {
                memcpy(ptr_start, src, len);
                return 0;
        }

        copy_pos = (uint8_t *)src;
        bytes_remaining = len;
        list_for_each(ptr, &(buf_start->list)) {
                struct buffer * tmp = list_entry(ptr, struct buffer, list);
                space_in_buf = tmp->data + tmp->size - ptr_start;
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

        dub->buffer = buffer_create(size);
        if (dub->buffer == NULL) {
                free (dub);
                return NULL;
        }

        dub->size     = size;
        dub->du_start = 0;
        dub->du_end   = 0;

        INIT_LIST_HEAD(&(dub->list));

        return dub;
}

void du_buff_destroy(du_buff_t * dub)
{
        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return;
        }
        buffer_destroy_list(dub->buffer);

        list_del(&(dub->list));

        free (dub);
}

int du_buff_init(du_buff_t * dub,
                 size_t      start,
                 uint8_t *   data,
                 size_t      len)
{
        if (dub == NULL || data == NULL) {
                LOG_DBG("Bogus input, bugging out.");
                return -EINVAL;
        }

        if (start + len > dub->size) {
                LOG_DBGF("Index out of bounds %d", start);
                return -EINVAL;
        }

        dub->du_start = start;
        dub->du_end = start + len;

        return buffer_copy_data(dub->buffer, start, data, len);
}

uint8_t * du_buff_data_ptr_start(du_buff_t * dub)
{
        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return NULL;
        }
        return buffer_seek_pos(dub->buffer, dub->du_start);
}

uint8_t * du_buff_data_ptr_end(du_buff_t * dub)
{
        if (dub == NULL) {
                LOG_DBG("Bogus input, bugging out.");
                return NULL;
        }
        return buffer_seek_pos(dub->buffer, dub->du_end);
}

int du_buff_head_alloc(du_buff_t * dub, size_t size)
{
        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -EINVAL;
        }

        if (dub->du_start - size < 0) {
                LOG_WARN("Failed to allocate PCI headspace");
                return -1;
        }

        dub->du_start -= size;

        return 0;
}
int du_buff_tail_alloc(du_buff_t * dub, size_t size)
{
        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -EINVAL;
        }

        if (dub->du_end + size >= dub->size) {
                LOG_WARN("Failed to allocate PCI tailspace");
                return -1;
        }

        dub->du_end += size;

        return 0;

}

int du_buff_head_release(du_buff_t * dub, size_t size)
{
        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -EINVAL;
        }

        if (size > dub->du_end - dub->du_start) {
                LOG_WARN("Tried to release beyond sdu boundary");
                return -1;
        }

        dub->du_start += size;

        /* FIXME: copy some random crap to the buffer for security */

        return 0;
}

int du_buff_tail_release(du_buff_t * dub, size_t size)
{
        if (dub == NULL) {
                LOG_DBGF("Bogus input, bugging out.");
                return -EINVAL;
        }

        if (size > dub->du_end - dub->du_start) {
                LOG_WARN("Tried to release beyond sdu boundary");
                return -1;
        }

        dub->du_end -= size;

        /* FIXME: copy some random crap to the buffer for security */

        return 0;
}
