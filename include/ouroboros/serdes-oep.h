/*
 * Ouroboros - Copyright (C) 2016 - 2023
 *
 * Ouroboros Enrollment Protocol - serialization/deserialization
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#ifndef OUROBOROS_LIB_SERDES_OEP_H
#define OUROBOROS_LIB_SERDES_OEP_H

#include <ouroboros/ipcp.h>
#include <ouroboros/utils.h>

#include <sys/time.h>

/* Enrollment */

/* no structs yet for req and ack. TODO: authentication. */

struct enroll_resp {
    struct timespec    t;
    int                response;
    struct ipcp_config conf;
};


ssize_t enroll_req_ser(buffer_t buf);

int     enroll_req_des(const buffer_t buf);

ssize_t enroll_resp_ser(const struct enroll_resp * resp,
                        buffer_t                   buf);

int     enroll_resp_des(struct enroll_resp * resp,
                        buffer_t             buf);

ssize_t enroll_ack_ser(const int response,
                       buffer_t  buf);

int     enroll_ack_des(int *          response,
                       const buffer_t buf);

#endif /* OUROBOROS_LIB_SERDES_OEP_H*/