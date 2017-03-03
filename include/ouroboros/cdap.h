/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The Common Distributed Application Protocol
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * version 2.1 as published by the Free Software Foundation.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#ifndef OUROBOROS_CDAP_H
#define OUROBOROS_CDAP_H

#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define F_SYNC 0x0001

#define INVALID_CDAP_KEY -1
#define CDAP_PROTO "CDAP"

enum cdap_opcode {
        CDAP_READ = 0,
        CDAP_WRITE,
        CDAP_START,
        CDAP_STOP,
        CDAP_CREATE,
        CDAP_DELETE
};

struct cdap;

typedef int32_t cdap_key_t;

/* Assumes flow is blocking */
struct cdap * cdap_create(int fd);

int           cdap_destroy(struct cdap * instance);

cdap_key_t    cdap_request_send(struct cdap *    instance,
                                enum cdap_opcode code,
                                const char *     name,
                                const void *     data,
                                size_t           len,
                                uint32_t         flags);

int           cdap_reply_wait(struct cdap * instance,
                              cdap_key_t    key,
                              uint8_t **    data,
                              size_t *      len);

cdap_key_t    cdap_request_wait(struct cdap *      instance,
                                enum cdap_opcode * opcode,
                                char **            name,
                                uint8_t **         data,
                                size_t *           len,
                                uint32_t *         flags);

int           cdap_reply_send(struct cdap * instance,
                              cdap_key_t    key,
                              int           result,
                              const void *  data,
                              size_t        len);

#endif /* OUROBOROS_CDAP_H */
