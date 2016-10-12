/*
 * Ouroboros - Copyright (C) 2016
 *
 * The Flow and Retransmission control component
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

#define OUROBOROS_PREFIX "flow-rtx-control"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/list.h>

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>

#include "frct.h"
#include "fmgr.h"
#include "ribmgr.h"

enum conn_state {
        CONN_PENDING = 0,
        CONN_ESTABLISHED
};

struct frct_i {
        uint32_t cep_id;
        uint32_t r_address;
        uint32_t r_cep_id;
        enum qos_cube cube;
        uint64_t seqno;

        enum conn_state state;
};

struct {
        pthread_mutex_t instances_lock;
        struct frct_i ** instances;

        struct bmp * cep_ids;
        pthread_mutex_t cep_ids_lock;
} frct;

static int next_cep_id()
{
        int ret;

        pthread_mutex_lock(&frct.cep_ids_lock);
        ret = bmp_allocate(frct.cep_ids);
        pthread_mutex_unlock(&frct.cep_ids_lock);

        return ret;
}

static int release_cep_id(int id)
{
        int ret;

        pthread_mutex_lock(&frct.cep_ids_lock);
        ret = bmp_release(frct.cep_ids, id);
        pthread_mutex_unlock(&frct.cep_ids_lock);

        return ret;
}

int frct_init()
{
        int i;

        if (pthread_mutex_init(&frct.cep_ids_lock, NULL))
                return -1;

        if (pthread_mutex_init(&frct.instances_lock, NULL))
                return -1;

        frct.instances = malloc(sizeof(*(frct.instances)) * IRMD_MAX_FLOWS);
        if (frct.instances == NULL)
                return -1;

        for (i = 0; i < IRMD_MAX_FLOWS; i++)
                frct.instances[i] = NULL;

        frct.cep_ids = bmp_create(IRMD_MAX_FLOWS, (INVALID_CEP_ID + 1));
        if (frct.cep_ids == NULL) {
                free(frct.instances);
                return -1;
        }

        return 0;
}

int frct_fini()
{
        pthread_mutex_lock(&frct.cep_ids_lock);
        bmp_destroy(frct.cep_ids);
        pthread_mutex_unlock(&frct.cep_ids_lock);

        free(frct.instances);

        return 0;
}

static struct frct_i * create_frct_i(uint32_t address,
                                     cep_id_t r_cep_id)
{
        struct frct_i * instance;
        cep_id_t        id;

        instance = malloc(sizeof(*instance));
        if (instance == NULL)
                return NULL;

        id = next_cep_id();
        instance->r_address = address;
        instance->cep_id = id;
        instance->r_cep_id = r_cep_id;
        instance->state = CONN_PENDING;
        instance->seqno = 0;

        frct.instances[id] = instance;

        return instance;
}

int frct_nm1_post_sdu(struct pci * pci,
                      struct shm_du_buff * sdb)
{
        struct frct_i * instance;
        buffer_t buf;
        cep_id_t id;

        if (pci == NULL || sdb == NULL)
                return -1;

        if (pci->dst_cep_id == INVALID_CEP_ID) {
                pthread_mutex_lock(&frct.instances_lock);
                instance = create_frct_i(pci->src_addr,
                                         pci->src_cep_id);
                if (instance == NULL) {
                        pthread_mutex_unlock(&frct.instances_lock);
                        return -1;
                }
                id = instance->cep_id;
                instance->r_cep_id = pci->src_cep_id;
                pthread_mutex_unlock(&frct.instances_lock);

                buf.len = shm_du_buff_tail(sdb) - shm_du_buff_head(sdb);
                buf.data = shm_du_buff_head(sdb);

                if (fmgr_np1_post_buf(id, &buf)) {
                        LOG_ERR("Failed to hand buffer to FMGR.");
                        free(pci);
                        return -1;
                }
        } else {
                /* FIXME: Known cep-ids are delivered to FMGR (minimal DTP) */
                if (fmgr_np1_post_sdu(pci->dst_cep_id, sdb)) {
                        LOG_ERR("Failed to hand SDU to FMGR.");
                        free(pci);
                        return -1;
                }
        }

        free(pci);

        return 0;
}

/* Call under instances lock */
static void destroy_frct_i(struct frct_i * instance)
{
        release_cep_id(instance->cep_id);
        frct.instances[instance->cep_id] = NULL;
        free(instance);
}

cep_id_t frct_i_create(uint32_t      address,
                       buffer_t *    buf,
                       enum qos_cube cube)
{
        struct frct_i * instance;
        struct pci pci;
        cep_id_t id;

        if (buf == NULL || buf->data == NULL)
                return INVALID_CEP_ID;

        pthread_mutex_lock(&frct.instances_lock);
        instance = create_frct_i(address, INVALID_CEP_ID);
        if (instance == NULL) {
                pthread_mutex_unlock(&frct.instances_lock);
                return INVALID_CEP_ID;
        }
        id = instance->cep_id;
        instance->cube = cube;
        pthread_mutex_unlock(&frct.instances_lock);

        pci.pdu_type = PDU_TYPE_MGMT;
        pci.dst_addr = address;
        pci.src_addr = ribmgr_address();
        pci.dst_cep_id = 0;
        pci.src_cep_id = id;
        pci.seqno = 0;
        pci.qos_id = cube;

        if (fmgr_nm1_write_buf(&pci, buf)) {
                free(instance);
                LOG_ERR("Failed to hand PDU to FMGR.");
                return INVALID_CEP_ID;
        }

        return id;
}

int frct_i_accept(cep_id_t       id,
                  buffer_t *     buf,
                  enum qos_cube  cube)
{
        struct pci pci;
        struct frct_i * instance;

        if (buf == NULL || buf->data == NULL)
                return -1;

        pthread_mutex_lock(&frct.instances_lock);

        instance = frct.instances[id];
        if (instance == NULL) {
                pthread_mutex_unlock(&frct.instances_lock);
                LOG_ERR("Invalid instance.");
                return -1;
        }

        if (instance->state != CONN_PENDING) {
                pthread_mutex_unlock(&frct.instances_lock);
                return -1;
        }

        instance->state = CONN_ESTABLISHED;
        instance->cube = cube;
        instance->seqno = 0;

        pci.pdu_type = PDU_TYPE_MGMT;
        pci.dst_addr = instance->r_address;
        pci.src_addr = ribmgr_address();
        pci.dst_cep_id = instance->r_cep_id;
        pci.src_cep_id = instance->cep_id;
        pci.seqno = 0;
        pci.qos_id = cube;

        pthread_mutex_unlock(&frct.instances_lock);

        if (fmgr_nm1_write_buf(&pci, buf))
                return -1;

        return 0;
}

int frct_i_destroy(cep_id_t   id,
                   buffer_t * buf)
{
        struct pci pci;
        struct frct_i * instance;

        pthread_mutex_lock(&frct.instances_lock);

        instance = frct.instances[id];
        if (instance == NULL) {
                pthread_mutex_unlock(&frct.instances_lock);
                LOG_ERR("Invalid instance.");
                return -1;
        }

        if (!(instance->state == CONN_PENDING ||
              instance->state == CONN_ESTABLISHED)) {
                pthread_mutex_unlock(&frct.instances_lock);
                return -1;
        }

        pci.pdu_type = PDU_TYPE_MGMT;
        pci.dst_addr = instance->r_address;
        pci.src_addr = ribmgr_address();
        pci.dst_cep_id = instance->r_cep_id;
        pci.src_cep_id = instance->cep_id;
        pci.seqno = 0;
        pci.qos_id = instance->cube;

        destroy_frct_i(instance);
        pthread_mutex_unlock(&frct.instances_lock);

        if (buf != NULL && buf->data != NULL)
                if (fmgr_nm1_write_buf(&pci, buf))
                        return -1;

        return 0;
}

int frct_i_write_sdu(cep_id_t             id,
                     struct shm_du_buff * sdb)
{
        struct pci pci;
        struct frct_i * instance;

        if (sdb == NULL)
                return -1;

        pthread_mutex_lock(&frct.instances_lock);

        instance = frct.instances[id];
        if (instance == NULL) {
                pthread_mutex_unlock(&frct.instances_lock);
                LOG_ERR("Invalid instance.");
                return -1;
        }

        if (instance->state != CONN_ESTABLISHED) {
                pthread_mutex_unlock(&frct.instances_lock);
                LOG_ERR("Connection is not established.");
                return -1;
        }

        pci.pdu_type = PDU_TYPE_DTP;
        pci.dst_addr = instance->r_address;
        pci.src_addr = ribmgr_address();
        pci.dst_cep_id = instance->r_cep_id;
        pci.src_cep_id = instance->cep_id;
        pci.seqno = (instance->seqno)++;
        pci.qos_id = instance->cube;

        if (fmgr_nm1_write_sdu(&pci, sdb)) {
                pthread_mutex_unlock(&frct.instances_lock);
                LOG_ERR("Failed to hand SDU to FMGR.");
                return -1;
        }

        return 0;
}
