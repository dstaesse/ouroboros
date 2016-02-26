/*
 * Ouroboros - Copyright (C) 2016
 *
 * Protocol Control Information
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

#ifndef OUROBOROS_IPCP_PCI_H
#define OUROBOROS_IPCP_PCI_H

#define OUROBOROS_PREFIX "ipcp/pci"

#include "ouroboros/du_buff.h"
#include "ouroboros/logs.h"
#include "dt_const.h"

struct pci;

typedef struct pci pci_t;

pci_t * pci_create(du_buff_t                   * dub,
                   const struct ipcp_dtp_const dtpc,
                   const struct ipcp_dup_const dupc);
void    pci_destroy(pci_t * pci);

int     pci_init(pci_t * pci);
void    pci_release(pci_t * pci);

#endif /* OUROBOROS_IPCP_PCI_H */
