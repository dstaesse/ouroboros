/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * OAP - Credential and configuration file I/O
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

#ifndef OUROBOROS_IRMD_OAP_IO_H
#define OUROBOROS_IRMD_OAP_IO_H

#include <ouroboros/crypt.h>
#include <ouroboros/name.h>

#ifndef OAP_TEST_MODE
int  load_credentials(const char *                  name,
                      const struct name_sec_paths * paths,
                      void **                       pkp,
                      void **                       crt);

int  load_kex_config(const char *        name,
                     const char *        path,
                     struct sec_config * cfg);
#endif

#endif /* OUROBOROS_IRMD_OAP_IO_H */
