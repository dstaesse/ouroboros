/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Flow allocator of the IPC Process
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

#ifndef OUROBOROS_IPCPD_UNICAST_FA_H
#define OUROBOROS_IPCPD_UNICAST_FA_H

#include <ouroboros/qos.h>
#include <ouroboros/utils.h>

int  fa_init(void);

void fa_fini(void);

int  fa_start(void);

void fa_stop(void);

int  fa_alloc(int              fd,
              const uint8_t *  dst,
              qosspec_t        qs,
              const buffer_t * data);

int  fa_alloc_resp(int              fd,
                   int              response,
                   const buffer_t * data);

int  fa_dealloc(int fd);

void fa_np1_rcv(uint64_t             eid,
                uint8_t              ecn,
                struct ssm_pk_buff * spb);

#endif /* OUROBOROS_IPCPD_UNICAST_FA_H */
