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

#define TYPE_SIZE  1
#define SEQNO_SIZE 8
#define FLAGS_SIZE 1

/* FIXME: Head size will differ on type */
#define HEAD_SIZE TYPE_SIZE + FLAGS_SIZE + SEQNO_SIZE

int frct_pci_ser(struct shm_du_buff * sdb,
                 struct frct_pci *    pci,
                 bool                 error_check)
{
        uint8_t * head;
        uint8_t * tail;

        assert(sdb);
        assert(pci);

        head = shm_du_buff_head_alloc(sdb, HEAD_SIZE);
        if (head == NULL)
                return -EPERM;

        memcpy(head, &pci->type, TYPE_SIZE);
        memcpy(head + TYPE_SIZE, &pci->flags, FLAGS_SIZE);
        memcpy(head + TYPE_SIZE + FLAGS_SIZE, &pci->seqno, SEQNO_SIZE);

        if (error_check) {
                tail = shm_du_buff_tail_alloc(sdb, hash_len(HASH_CRC32));
                if (tail == NULL) {
                        shm_du_buff_head_release(sdb, HEAD_SIZE);
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

        assert(sdb);
        assert(pci);

        head = shm_du_buff_head(sdb);

         /* FIXME: Depending on the type a different deserialization */
        memcpy(&pci->type, head, TYPE_SIZE);
        memcpy(&pci->flags, head + TYPE_SIZE, FLAGS_SIZE);
        memcpy(&pci->seqno, head + TYPE_SIZE + FLAGS_SIZE, SEQNO_SIZE);

        if (error_check) {
                tail = shm_du_buff_tail(sdb);
                if (tail == NULL)
                        return -EPERM;

                mem_hash(HASH_CRC32, &crc, head, tail - head);

                /* Corrupted SDU */
                if (crc != 0)
                        return -1;

                shm_du_buff_tail_release(sdb, hash_len(HASH_CRC32));
        }

        shm_du_buff_head_release(sdb, HEAD_SIZE);

        return 0;
}
