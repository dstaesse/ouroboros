/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * OAP - Authentication functions
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

#ifndef OUROBOROS_IRMD_OAP_AUTH_H
#define OUROBOROS_IRMD_OAP_AUTH_H

#include "hdr.h"

int  oap_check_hdr(const struct oap_hdr * hdr);

/* name is updated with the peer's certificate name if available */
int  oap_auth_peer(char *                 name,
                   const struct oap_hdr * local_hdr,
                   const struct oap_hdr * peer_hdr);

#endif /* OUROBOROS_IRMD_OAP_AUTH_H */
