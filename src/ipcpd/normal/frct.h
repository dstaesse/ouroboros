/*
 * Ouroboros - Copyright (C) 2016
 *
 * The Flow and Retransmission control component
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef OUROBOROS_IPCPD_NORMAL_FRCT_H
#define OUROBOROS_IPCPD_NORMAL_FRCT_H

#include <ouroboros/shared.h>
#include <ouroboros/utils.h>

#include "shm_pci.h"

struct frct_i;

int         frct_init(void);

int         frct_fini(void);

cep_id_t    frct_i_create(uint64_t      address,
                          buffer_t *    buf,
                          enum qos_cube cube);

int         frct_i_accept(cep_id_t      id,
                          buffer_t *    buf,
                          enum qos_cube cube);

int         frct_i_destroy(cep_id_t   id,
                           buffer_t * buf);

int         frct_i_write_sdu(cep_id_t             id,
                             struct shm_du_buff * sdb);

int         frct_nm1_post_sdu(struct pci *         pci,
                              struct shm_du_buff * sdb);

#endif /* OUROBOROS_IPCPD_NORMAL_FRCT_H */
