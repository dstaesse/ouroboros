/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Protocol Control Information of Data Transfer AE
 *
 *    Dimitri Staessens <dimitri.staessens@ugent.be>
 *    Sander Vrijders   <sander.vrijders@ugent.be>
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

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/rib.h>

#include "dt_pci.h"
#include "ribconfig.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define DEFAULT_TTL   60

struct {
        uint8_t         addr_size;
        uint8_t         fd_size;
        bool            has_ttl;
        size_t          head_size;

        /* offsets */
        size_t          qc_o;
        size_t          ttl_o;
        size_t          fd_o;
} dt_pci_info;

int dt_pci_init()
{
        /* read dt constants from the RIB */
        if (rib_read(BOOT_PATH "/dt/const/addr_size",
                     &dt_pci_info.addr_size,
                     sizeof(dt_pci_info.addr_size)) < 0 ||
            rib_read(BOOT_PATH "/dt/const/fd_size",
                     &dt_pci_info.fd_size,
                     sizeof(dt_pci_info.fd_size)) < 0 ||
            rib_read(BOOT_PATH "/dt/const/has_ttl",
                     &dt_pci_info.has_ttl,
                     sizeof(dt_pci_info.has_ttl)) < 0)
                return -1;

        dt_pci_info.qc_o = dt_pci_info.addr_size;
        dt_pci_info.ttl_o = dt_pci_info.qc_o + QOS_LEN;
        if (dt_pci_info.has_ttl)
                dt_pci_info.fd_o = dt_pci_info.ttl_o + TTL_LEN;
        else
                dt_pci_info.fd_o = dt_pci_info.ttl_o;

        dt_pci_info.head_size = dt_pci_info.fd_o + dt_pci_info.fd_size;

        return 0;
}

void dt_pci_fini(void) {
        return;
}

int dt_pci_ser(struct shm_du_buff * sdb,
               struct dt_pci *      dt_pci)
{
        uint8_t * head;
        uint8_t ttl = DEFAULT_TTL;

        assert(sdb);
        assert(dt_pci);

        head = shm_du_buff_head_alloc(sdb, dt_pci_info.head_size);
        if (head == NULL)
                return -EPERM;

        /* FIXME: Add check and operations for Big Endian machines */
        memcpy(head, &dt_pci->dst_addr, dt_pci_info.addr_size);
        memcpy(head + dt_pci_info.qc_o, &dt_pci->qc, QOS_LEN);
        if (dt_pci_info.has_ttl)
                memcpy(head + dt_pci_info.ttl_o, &ttl, TTL_LEN);
        memcpy(head + dt_pci_info.fd_o, &dt_pci->fd, dt_pci_info.fd_size);

        return 0;
}

void dt_pci_des(struct shm_du_buff * sdb,
                struct dt_pci *      dt_pci)
{
        uint8_t * head;

        assert(sdb);
        assert(dt_pci);

        head = shm_du_buff_head(sdb);

        /* FIXME: Add check and operations for Big Endian machines */
        memcpy(&dt_pci->dst_addr, head, dt_pci_info.addr_size);
        memcpy(&dt_pci->qc, head + dt_pci_info.qc_o, QOS_LEN);

        if (dt_pci_info.has_ttl) {
                --*(head + dt_pci_info.ttl_o); /* decrease TTL */
                memcpy(&dt_pci->ttl, head + dt_pci_info.ttl_o, TTL_LEN);
        } else {
                dt_pci->ttl = 1;
        }

        memcpy(&dt_pci->fd, head + dt_pci_info.fd_o, dt_pci_info.fd_size);
}

void dt_pci_shrink(struct shm_du_buff * sdb)
{
        assert(sdb);

        shm_du_buff_head_release(sdb, dt_pci_info.head_size);
}
