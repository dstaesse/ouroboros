/*
 * Ouroboros - Copyright (C) 2016 - 2021
 *
 * Threadpool management
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_LIB_TPM_H
#define OUROBOROS_LIB_TPM_H

#include <stdbool.h>

struct tpm;

struct tpm * tpm_create(size_t    min,
                        size_t    inc,
                        void * (* func)(void *),
                        void *    o);

void         tpm_destroy(struct tpm * tpm);

int          tpm_start(struct tpm * tpm);

void         tpm_stop(struct tpm * tpm);

void         tpm_dec(struct tpm * tpm);

void         tpm_inc(struct tpm * tpm);

#endif /* OUROBOROS_LIB_TPM_H */
