/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Threadpool management
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
 * Foundation, Inc., http://www.fsf.org/about/contact/.
 */

#ifndef OUROBOROS_LIB_TPM_H
#define OUROBOROS_LIB_TPM_H

#include <stdbool.h>

int  tpm_init(size_t    min,
              size_t    inc,
              void * (* func)(void *));

int  tpm_start(void);

void tpm_stop(void);

void tpm_fini(void);

bool tpm_check(void);

void tpm_exit(void);

void tpm_dec(void);

void tpm_inc(void);

#endif /* OUROBOROS_LIB_TPM_H */
