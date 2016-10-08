/*
 * Ouroboros - Copyright (C) 2016
 *
 * The Relaying and Multiplexing task
 *
 *    Sander Vrijders <sander.vrijders@intec.ugent.be>
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

#define OUROBOROS_PREFIX "flow-manager"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/select.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/errno.h>
#include <ouroboros/dev.h>

#include <stdlib.h>

#include "rmt.h"
#include "config.h"
#include "frct.h"

struct {
        pthread_t         sdu_reader;
        struct flow_set * set;
        uint32_t          address;

        /*
         * FIXME: Normally the PFF is held here,
         * for now we keep 1 fd to forward a PDU on
         */
        int fd;
} rmt;

int rmt_init(uint32_t address)
{
        rmt.set = flow_set_create();
        if (rmt.set == NULL)
                return -1;

        rmt.address = address;

        return 0;
}

int rmt_fini()
{
        flow_set_destroy(rmt.set);

        return 0;
}

void * rmt_sdu_reader(void * o)
{
        struct timespec timeout = {0, FD_UPDATE_TIMEOUT};
        struct shm_du_buff * sdb;
        struct pci * pci;

        while (true) {
                int fd = flow_select(rmt.set, &timeout);
                if (fd == -ETIMEDOUT)
                        continue;

                if (fd < 0) {
                        LOG_ERR("Failed to get active fd.");
                        continue;
                }

                if (ipcp_flow_read(fd, &sdb)) {
                        LOG_ERR("Failed to read SDU from fd %d.", fd);
                        continue;
                }

                pci = shm_pci_des(sdb);
                if (pci == NULL) {
                        LOG_ERR("Failed to get PCI.");
                        ipcp_flow_del(sdb);
                        continue;
                }

                if (pci->dst_addr != rmt.address) {
                        LOG_DBG("PDU needs to be forwarded.");

                        if (pci->ttl == 0) {
                                LOG_DBG("TTL was zero.");
                                ipcp_flow_del(sdb);
                                free(pci);
                                continue;
                        }

                        if (shm_pci_dec_ttl(sdb)) {
                                LOG_ERR("Failed to decrease TTL.");
                                ipcp_flow_del(sdb);
                                free(pci);
                                continue;
                        }
                        /*
                         * FIXME: Dropping for now, since
                         * we don't have a PFF yet
                         */
                        ipcp_flow_del(sdb);
                        free(pci);
                        continue;
                }

                if (shm_pci_shrink(sdb)) {
                        LOG_ERR("Failed to shrink PDU.");
                        ipcp_flow_del(sdb);
                        free(pci);
                        continue;
                }

                if (frct_rmt_post_sdu(pci, sdb)) {
                        LOG_ERR("Failed to hand PDU to FRCT.");
                        ipcp_flow_del(sdb);
                        free(pci);
                        continue;
                }
        }

        return (void *) 0;
}

int rmt_dt_flow(int           fd,
                enum qos_cube qos)
{
        struct flow_set * set = rmt.set;
        if (set == NULL)
                return -1;

        flow_set_add(set, fd);

        /* FIXME: This will be removed once we have a PFF */
        rmt.fd = fd;

        return 0;
}

int rmt_frct_write_sdu(struct pci *         pci,
                       struct shm_du_buff * sdb)
{
        if (shm_pci_ser(sdb, pci)) {
                LOG_ERR("Failed to serialize PDU.");
                ipcp_flow_del(sdb);
                return -1;
        }

        if (ipcp_flow_write(rmt.fd, sdb)) {
                LOG_ERR("Failed to write SDU to fd %d.", rmt.fd);
                ipcp_flow_del(sdb);
                return -1;
        }

        return 0;
}

int rmt_frct_write_buf(struct pci * pci,
                       buffer_t *   buf)
{
        buffer_t * buffer;

        if (pci == NULL || buf == NULL || buf->data == NULL)
                return -1;

        buffer = shm_pci_ser_buf(buf, pci);
        if (buffer == NULL) {
                LOG_ERR("Failed to serialize buffer.");
                free(buf->data);
                return -1;
        }

        if (flow_write(rmt.fd, buffer->data, buffer->len) == -1) {
                LOG_ERR("Failed to write buffer to fd.");
                free(buffer);
                return -1;
        }

        free(buffer);
        return 0;
}
