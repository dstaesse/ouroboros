/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Protocol Control Information of FRCT
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

#include <ouroboros/frct_pci.h>
#include <ouroboros/hash.h>
#include <ouroboros/errno.h>

#include <assert.h>
#include <string.h>

#define TYPE_SIZE       1
#define SEQNO_SIZE      8
#define FLAGS_SIZE      1
#define CONF_FLAGS_SIZE sizeof(((struct frct_pci *) NULL)->conf_flags)
#define BASE_SIZE       TYPE_SIZE + FLAGS_SIZE + SEQNO_SIZE
#define CONFIG_SIZE     CONF_FLAGS_SIZE

static size_t get_head_len(struct frct_pci * pci)
{
        size_t len = BASE_SIZE;

        if (pci->type & PDU_TYPE_CONFIG)
                len += CONFIG_SIZE;

        return len;
}

int frct_pci_ser(struct shm_du_buff * sdb,
                 struct frct_pci *    pci,
                 bool                 error_check)
{
        uint8_t * head;
        uint8_t * tail;
        size_t    len;
        size_t    offset = 0;

        assert(sdb);
        assert(pci);

        len = get_head_len(pci);

        head = shm_du_buff_head_alloc(sdb, len);
        if (head == NULL)
                return -EPERM;

        memcpy(head, &pci->type, TYPE_SIZE);
        offset += TYPE_SIZE;
        memcpy(head + offset, &pci->flags, FLAGS_SIZE);
        offset += FLAGS_SIZE;
        memcpy(head + offset, &pci->seqno, SEQNO_SIZE);
        offset += SEQNO_SIZE;

        if (pci->type & PDU_TYPE_CONFIG) {
                memcpy(head + offset, &pci->conf_flags, CONF_FLAGS_SIZE);
                /* offset += CONF_FLAGS_SIZE; */
        }

        if (error_check) {
                tail = shm_du_buff_tail_alloc(sdb, hash_len(HASH_CRC32));
                if (tail == NULL) {
                        shm_du_buff_head_release(sdb, len);
                        return -EPERM;
                }

                *((uint32_t *) tail) = 0;
                mem_hash(HASH_CRC32, (uint32_t *) tail, head, tail - head);
        }

        return 0;
}

int frct_pci_des(struct shm_du_buff * sdb,
                 struct frct_pci *    pci,
                 bool                 error_check)
{
        uint8_t * head;
        uint8_t * tail;
        uint32_t  crc;
        uint32_t  crc2;
        size_t    offset = 0;

        assert(sdb);
        assert(pci);

        head = shm_du_buff_head(sdb);

         /* Depending on the type a different deserialization. */
        memcpy(&pci->type, head, TYPE_SIZE);
        offset += TYPE_SIZE;
        memcpy(&pci->flags, head + offset, FLAGS_SIZE);
        offset += FLAGS_SIZE;
        memcpy(&pci->seqno, head + offset, SEQNO_SIZE);
        offset += SEQNO_SIZE;

        if (pci->type & PDU_TYPE_CONFIG) {
                memcpy(&pci->conf_flags, head + offset, CONF_FLAGS_SIZE);
                /* offset += CONF_FLAGS_SIZE; */
        }

        if (error_check) {
                tail = shm_du_buff_tail(sdb);
                if (tail == NULL)
                        return -EPERM;

                mem_hash(HASH_CRC32, &crc, head,
                         tail - head - hash_len(HASH_CRC32));

                memcpy(&crc2, tail - hash_len(HASH_CRC32),
                       hash_len(HASH_CRC32));

                /* Corrupted SDU. */
                if (crc != crc2)
                        return -1;

                shm_du_buff_tail_release(sdb, hash_len(HASH_CRC32));
        }

        shm_du_buff_head_release(sdb, get_head_len(pci));

        return 0;
}
