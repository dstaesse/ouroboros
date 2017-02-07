/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Protocol Control Information in Shared Memory Map
 *
 *    Dimitri Staessens <dimitri.staessens@intec.ugent.be>
 *    Sander Vrijders   <sander.vrijders@intec.ugent.be>
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

#include <ouroboros/config.h>
#include <ouroboros/errno.h>
#include <ouroboros/crc32.h>
#include <ouroboros/rib.h>

#include "shm_pci.h"
#include "dt_const.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#define PDU_TYPE_SIZE 1
#define QOS_ID_SIZE 1
#define DEFAULT_TTL 60
#define TTL_SIZE 1
#define CHK_SIZE 4

#define BOOT_PATH "/" BOOT_NAME

struct {
        struct dt_const dtc;
        size_t head_size;
        size_t tail_size;

        /* offsets */
        size_t dst_addr_o;
        size_t src_addr_o;
        size_t dst_cep_id_o;
        size_t src_cep_id_o;
        size_t pdu_length_o;
        size_t seqno_o;
        size_t qos_id_o;
        size_t ttl_o;
} pci_info;


static void ser_pci_head(uint8_t *    head,
                         struct pci * pci)
{
        uint8_t ttl = DEFAULT_TTL;

        assert(head);
        assert(pci);

        /* FIXME: Add check and operations for Big Endian machines */
        memcpy(head, &pci->pdu_type, PDU_TYPE_SIZE);
        memcpy(head + pci_info.dst_addr_o, &pci->dst_addr,
               pci_info.dtc.addr_size);
        memcpy(head + pci_info.src_addr_o, &pci->src_addr,
               pci_info.dtc.addr_size);
        memcpy(head + pci_info.dst_cep_id_o, &pci->dst_cep_id,
               pci_info.dtc.cep_id_size);
        memcpy(head + pci_info.src_cep_id_o, &pci->src_cep_id,
               pci_info.dtc.cep_id_size);
        memcpy(head + pci_info.pdu_length_o, &pci->pdu_length,
               pci_info.dtc.pdu_length_size);
        memcpy(head + pci_info.seqno_o, &pci->seqno,
               pci_info.dtc.seqno_size);
        memcpy(head + pci_info.qos_id_o, &pci->qos_id, QOS_ID_SIZE);
        if (pci_info.dtc.has_ttl)
                memcpy(head + pci_info.ttl_o, &ttl, TTL_SIZE);
}

int shm_pci_init(void)
{
        /* read dt constants from the RIB */
        if (rib_read(BOOT_PATH "/dt/const/addr_size",
                     &pci_info.dtc.addr_size,
                     sizeof(pci_info.dtc.addr_size)) ||
            rib_read(BOOT_PATH "/dt/const/cep_id_size",
                      &pci_info.dtc.cep_id_size,
                      sizeof(pci_info.dtc.cep_id_size)) ||
            rib_read(BOOT_PATH "/dt/const/seqno_size",
                      &pci_info.dtc.seqno_size,
                      sizeof(pci_info.dtc.seqno_size)) ||
            rib_read(BOOT_PATH "/dt/const/has_ttl",
                      &pci_info.dtc.has_ttl,
                      sizeof(pci_info.dtc.has_ttl)) ||
            rib_read(BOOT_PATH "/dt/const/has_chk",
                      &pci_info.dtc.has_chk,
                      sizeof(pci_info.dtc.has_chk)) ||
            rib_read(BOOT_PATH "/dt/const/min_pdu_size",
                      &pci_info.dtc.min_pdu_size,
                      sizeof(pci_info.dtc.min_pdu_size)) ||
            rib_read(BOOT_PATH "/dt/const/max_pdu_size",
                      &pci_info.dtc.max_pdu_size,
                      sizeof(pci_info.dtc.max_pdu_size)))
                return -1;

        pci_info.dst_addr_o = PDU_TYPE_SIZE;
        pci_info.src_addr_o = pci_info.dst_addr_o + pci_info.dtc.addr_size;
        pci_info.dst_cep_id_o = pci_info.dst_addr_o + pci_info.dtc.addr_size;
        pci_info.dst_cep_id_o = pci_info.src_addr_o + pci_info.dtc.addr_size;
        pci_info.src_cep_id_o = pci_info.dst_cep_id_o
                + pci_info.dtc.cep_id_size;
        pci_info.pdu_length_o = pci_info.src_cep_id_o
                + pci_info.dtc.cep_id_size;
        pci_info.seqno_o = pci_info.pdu_length_o + pci_info.dtc.pdu_length_size;
        pci_info.qos_id_o = pci_info.seqno_o + pci_info.dtc.seqno_size;
        pci_info.ttl_o = pci_info.qos_id_o + QOS_ID_SIZE;

        pci_info.head_size = pci_info.ttl_o;

        if (pci_info.dtc.has_ttl)
                pci_info.head_size += TTL_SIZE;

        pci_info.tail_size = pci_info.dtc.has_chk ? CHK_SIZE : 0;

        return 0;
}

void shm_pci_fini(void) {
        return ;
}

int shm_pci_ser(struct shm_du_buff * sdb,
                struct pci *         pci)
{
        uint8_t * head;
        uint8_t * tail;

        assert(sdb);
        assert(pci);

        head = shm_du_buff_head_alloc(sdb, pci_info.head_size);
        if (head == NULL)
                return -EPERM;

        ser_pci_head(head, pci);

        if (pci_info.dtc.has_chk) {
                tail = shm_du_buff_tail_alloc(sdb, pci_info.tail_size);
                if (tail == NULL) {
                        shm_du_buff_head_release(sdb, pci_info.head_size);
                        return -EPERM;
                }

                crc32((uint32_t *) tail, head, tail - head);
        }

        return 0;
}

buffer_t * shm_pci_ser_buf(buffer_t *   buf,
                           struct pci * pci)
{
        buffer_t * buffer;

        assert(buf);
        assert(pci);

        buffer = malloc(sizeof(*buffer));
        if (buffer == NULL)
                return NULL;

        buffer->len = buf->len + pci_info.head_size +
                pci_info.tail_size;

        buffer->data = malloc(buffer->len);
        if (buffer->data == NULL) {
                free(buffer);
                return NULL;
        }

        ser_pci_head(buffer->data, pci);
        memcpy(buffer->data + pci_info.head_size,
               buf->data, buf->len);

        free(buf->data);

        if (pci_info.dtc.has_chk)
                crc32((uint32_t *) (buffer->data +
                                    pci_info.head_size + buf->len),
                      buffer->data,
                      pci_info.head_size + buf->len);

        return buffer;
}

void shm_pci_des(struct shm_du_buff * sdb,
                 struct pci *         pci)
{
        uint8_t * head;

        assert(sdb);
        assert(pci);

        head = shm_du_buff_head(sdb);

        /* FIXME: Add check and operations for Big Endian machines */
        memcpy(&pci->pdu_type, head, PDU_TYPE_SIZE);
        memcpy(&pci->dst_addr, head + pci_info.dst_addr_o,
               pci_info.dtc.addr_size);
        memcpy(&pci->src_addr, head + pci_info.src_addr_o,
               pci_info.dtc.addr_size);
        memcpy(&pci->dst_cep_id, head + pci_info.dst_cep_id_o,
               pci_info.dtc.cep_id_size);
        memcpy(&pci->src_cep_id, head + pci_info.src_cep_id_o,
               pci_info.dtc.cep_id_size);
        memcpy(&pci->pdu_length, head + pci_info.pdu_length_o,
               pci_info.dtc.pdu_length_size);
        memcpy(&pci->seqno, head + pci_info.seqno_o,
               pci_info.dtc.seqno_size);
        memcpy(&pci->qos_id, head + pci_info.qos_id_o, QOS_ID_SIZE);

        if (pci_info.dtc.has_ttl) {
                --*(head + pci_info.ttl_o); /* decrease TTL */
                memcpy(&pci->ttl, head + pci_info.ttl_o, TTL_SIZE);
        } else {
                pci->ttl = 1;
        }
}

void shm_pci_shrink(struct shm_du_buff * sdb)
{
        assert(sdb);

        shm_du_buff_head_release(sdb, pci_info.head_size);
        shm_du_buff_tail_release(sdb, pci_info.tail_size);
}
