/*
 * Ouroboros - Copyright (C) 2016 - 2024
 *
 * Enrollment Task
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

#ifndef OUROBOROS_IPCPD_COMMON_ENROLL_H
#define OUROBOROS_IPCPD_COMMON_ENROLL_H

#include <ouroboros/ipcp.h>

#include "comp.h"

int                  enroll_init(void);

void                 enroll_fini(void);

int                  enroll_start(void);

void                 enroll_stop(void);

void                 enroll_bootstrap(const struct ipcp_config * conf);

int                  enroll_boot(struct conn *   conn,
                                 const uint8_t * id);

int                  enroll_ack(struct conn *   conn,
                                const uint8_t * id,
                                const int       result);

struct ipcp_config * enroll_get_conf(void);

#endif /* OUROBOROS_IPCPD_COMMON_ENROLL_H */
