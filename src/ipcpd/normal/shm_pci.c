/*
 * Ouroboros - Copyright (C) 2016
 *
 * Protocol Control Information in Shared Memory Map
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

#define OUROBOROS_PREFIX "ipcpd/shm_pci"

#include <ouroboros/logs.h>
#include <ouroboros/errno.h>

#include <stdlib.h>
#include <string.h>

#include "shm_pci.h"
#include "frct.h"
#include "crc32.h"
#include "ribmgr.h"

#define QOS_ID_SIZE 1
#define DEFAULT_TTL 60
#define TTL_SIZE 1
#define CHK_SIZE 4

static int shm_pci_head_size(struct dt_const * dtc)
{
        int len = 0;

        len = dtc->addr_size * 2 + dtc->cep_id_size * 2
                + dtc->pdu_length_size + dtc->seqno_size
                + QOS_ID_SIZE;

        if (dtc->has_ttl)
                len += TTL_SIZE;

        return len;
}

static int shm_pci_tail_size(struct dt_const * dtc)
{
        return dtc->has_chk ? CHK_SIZE : 0;
}

static void ser_pci_head(uint8_t * head,
                         struct pci * pci,
                         struct dt_const * dtc)
{
        int offset = 0;
        uint8_t ttl = DEFAULT_TTL;

        memcpy(head, &pci->dst_addr, dtc->addr_size);
        offset += dtc->addr_size;
        memcpy(head + offset, &pci->src_addr, dtc->addr_size);
        offset += dtc->addr_size;
        memcpy(head + offset, &pci->dst_cep_id, dtc->cep_id_size);
        offset += dtc->cep_id_size;
        memcpy(head + offset, &pci->src_cep_id, dtc->cep_id_size);
        offset += dtc->cep_id_size;
        memcpy(head + offset, &pci->pdu_length, dtc->pdu_length_size);
        offset += dtc->pdu_length_size;
        memcpy(head + offset, &pci->seqno, dtc->seqno_size);
        offset += dtc->seqno_size;
        memcpy(head + offset, &pci->qos_id, QOS_ID_SIZE);
        offset += QOS_ID_SIZE;
        if (dtc->has_ttl)
                memcpy(head + offset, &ttl, TTL_SIZE);
}

int shm_pci_ser(struct shm_du_buff * sdb,
                struct pci * pci)
{
        uint8_t * head;
        uint8_t * tail;
        struct dt_const * dtc;

        dtc = ribmgr_dt_const();
        if (dtc == NULL)
                return -1;

        head = shm_du_buff_head_alloc(sdb, shm_pci_head_size(dtc));
        if (head == NULL)
                return -1;

        ser_pci_head(head, pci, dtc);

        if (dtc->has_chk) {
                tail = shm_du_buff_tail_alloc(sdb, shm_pci_tail_size(dtc));
                if (tail == NULL) {
                        shm_du_buff_head_release(sdb, shm_pci_tail_size(dtc));
                        return -1;
                }

                crc32((uint32_t *) tail, head, tail - head);
        }

        return 0;
}

buffer_t * shm_pci_ser_buf(buffer_t *   buf,
                           struct pci * pci)
{
        buffer_t * buffer;
        struct dt_const * dtc;

        if (buf == NULL || pci == NULL)
                return NULL;

        dtc = ribmgr_dt_const();
        if (dtc == NULL)
                return NULL;

        buffer = malloc(sizeof(*buffer));
        if (buffer == NULL)
                return NULL;

        buffer->len = buf->len +
                shm_pci_head_size(dtc) +
                shm_pci_tail_size(dtc);

        buffer->data = malloc(buffer->len);
        if (buffer->data == NULL) {
                free(buffer);
                return NULL;
        }

        ser_pci_head(buffer->data, pci, dtc);
        memcpy(buffer->data + shm_pci_head_size(dtc),
               buf->data, buf->len);

        free(buf->data);

        if (dtc->has_chk)
                crc32((uint32_t *) buffer->data +
                      shm_pci_head_size(dtc) + buf->len,
                      buffer->data,
                      shm_pci_head_size(dtc) + buf->len);

        return buffer;
}

struct pci * shm_pci_des(struct shm_du_buff * sdb)
{
        uint8_t * head;
        struct pci * pci;
        int offset = 0;
        struct dt_const * dtc;

        head = shm_du_buff_head(sdb);
        if (head == NULL)
                return NULL;

        dtc = ribmgr_dt_const();
        if (dtc == NULL)
                return NULL;

        pci = malloc(sizeof(*pci));
        if (pci == NULL)
                return NULL;

        memcpy(&pci->dst_addr, head, dtc->addr_size);
        offset += dtc->addr_size;
        memcpy(&pci->src_addr, head + offset, dtc->addr_size);
        offset += dtc->addr_size;
        memcpy(&pci->dst_cep_id, head + offset, dtc->cep_id_size);
        offset += dtc->cep_id_size;
        memcpy(&pci->src_cep_id, head + offset, dtc->cep_id_size);
        offset += dtc->cep_id_size;
        memcpy(&pci->pdu_length, head + offset, dtc->pdu_length_size);
        offset += dtc->pdu_length_size;
        memcpy(&pci->seqno, head + offset, dtc->seqno_size);
        offset += dtc->seqno_size;
        memcpy(&pci->qos_id, head + offset, QOS_ID_SIZE);
        offset += QOS_ID_SIZE;
        if (dtc->has_ttl)
                memcpy(&pci->ttl, head + offset, TTL_SIZE);

        return pci;
}

int shm_pci_shrink(struct shm_du_buff * sdb)
{
        struct dt_const * dtc;

        if (sdb == NULL)
                return -1;

        dtc = ribmgr_dt_const();
        if (dtc == NULL)
                return -1;

        if (shm_du_buff_head_release(sdb, shm_pci_head_size(dtc))) {
                LOG_ERR("Failed to shrink head.");
                return -1;
        }

        if (shm_du_buff_tail_release(sdb, shm_pci_tail_size(dtc))) {
                LOG_ERR("Failed to shrink tail.");
                return -1;
        }

        return 0;
}

int shm_pci_dec_ttl(struct shm_du_buff * sdb)
{
        struct dt_const * dtc;
        int offset = 0;
        uint8_t * head;
        uint8_t * tail;

        dtc = ribmgr_dt_const();
        if (dtc == NULL)
                return -1;

        if (dtc->has_ttl == false)
                return 0;

        offset = shm_pci_head_size(dtc) - 1;

        head = shm_du_buff_head(sdb);
        if (head == NULL)
                return -1;

        head[offset]--;

        if (dtc->has_chk) {
                tail = shm_du_buff_tail(sdb);
                if (tail == NULL)
                        return -1;

                tail -= CHK_SIZE;

                crc32((uint32_t *) tail, head, tail - head);
        }

        return 0;
}
