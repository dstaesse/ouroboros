/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * The Flow and Retransmission control component
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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define OUROBOROS_PREFIX "flow-rtx-control"

#include <ouroboros/config.h>
#include <ouroboros/logs.h>
#include <ouroboros/bitmap.h>
#include <ouroboros/list.h>
#include <ouroboros/ipcp-dev.h>
#include <ouroboros/errno.h>

#include "frct.h"
#include "ipcp.h"
#include "dt.h"
#include "fa.h"

#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <assert.h>

enum conn_state {
        CONN_PENDING = 0,
        CONN_ESTABLISHED
};

struct frct_i {
        uint32_t  cep_id;
        uint64_t  r_address;
        uint32_t  r_cep_id;
        qoscube_t cube;
        uint64_t  seqno;

        enum conn_state state;
};

struct {
        struct frct_i ** instances;
        pthread_mutex_t  instances_lock;

        struct bmp *     cep_ids;
        pthread_mutex_t  cep_ids_lock;
} frct;

static cep_id_t next_cep_id(void)
{
        cep_id_t ret;

        pthread_mutex_lock(&frct.cep_ids_lock);

        ret = bmp_allocate(frct.cep_ids);
        if (!bmp_is_id_valid(frct.cep_ids, ret))
                ret = INVALID_CEP_ID;

        pthread_mutex_unlock(&frct.cep_ids_lock);

        return ret;
}

static int release_cep_id(cep_id_t id)
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

        if (frct_pci_init())
                return -1;

        if (pthread_mutex_init(&frct.cep_ids_lock, NULL))
                return -1;

        frct.cep_ids = bmp_create(IRMD_MAX_FLOWS, (INVALID_CEP_ID + 1));
        if (frct.cep_ids == NULL)
                goto fail_cep_ids_lock;

        if (pthread_mutex_init(&frct.instances_lock, NULL))
                goto fail_bmp;

        frct.instances = malloc(sizeof(*(frct.instances)) * IRMD_MAX_FLOWS);
        if (frct.instances == NULL)
                goto fail_instance_lock;

        for (i = 0; i < IRMD_MAX_FLOWS; i++)
                frct.instances[i] = NULL;

        return 0;

 fail_instance_lock:
        pthread_mutex_destroy(&frct.instances_lock);
 fail_bmp:
        bmp_destroy(frct.cep_ids);
 fail_cep_ids_lock:
        pthread_mutex_destroy(&frct.cep_ids_lock);

        return -1;
}

int frct_fini()
{
        pthread_mutex_destroy(&frct.instances_lock);

        free(frct.instances);

        bmp_destroy(frct.cep_ids);

        pthread_mutex_destroy(&frct.cep_ids_lock);

        return 0;
}

cep_id_t frct_i_create(uint64_t   address,
                       qoscube_t  cube)
{
        struct frct_i * instance;
        cep_id_t        id;

        pthread_mutex_lock(&frct.instances_lock);

        instance = malloc(sizeof(*instance));
        if (instance == NULL)
                return INVALID_CEP_ID;

        id = next_cep_id();
        if (id == INVALID_CEP_ID) {
                free(instance);
                return INVALID_CEP_ID;
        }

        instance->r_address = address;
        instance->cep_id = id;
        instance->state = CONN_PENDING;
        instance->seqno = 0;
        instance->cube = cube;

        frct.instances[id] = instance;

        pthread_mutex_unlock(&frct.instances_lock);

        return id;
}

int frct_i_destroy(cep_id_t   cep_id)
{
        struct frct_i * instance;

        pthread_mutex_lock(&frct.instances_lock);

        instance = frct.instances[cep_id];
        if (instance == NULL) {
                pthread_mutex_unlock(&frct.instances_lock);
                log_err("Invalid instance.");
                return -1;
        }

        frct.instances[cep_id] = NULL;

        release_cep_id(instance->cep_id);
        free(instance);

        pthread_mutex_unlock(&frct.instances_lock);

        return 0;
}

int frct_i_set_id(cep_id_t cep_id,
                  cep_id_t r_cep_id)
{
        struct frct_i * instance;

        pthread_mutex_lock(&frct.instances_lock);

        instance = frct.instances[cep_id];
        if (instance == NULL) {
                pthread_mutex_unlock(&frct.instances_lock);
                log_err("Invalid instance.");
                return -1;
        }

        instance->r_cep_id = r_cep_id;
        instance->state = CONN_ESTABLISHED;

        pthread_mutex_unlock(&frct.instances_lock);

        return 0;
}

cep_id_t frct_i_get_id(cep_id_t cep_id)
{
        struct frct_i * instance;
        cep_id_t        r_cep_id;

        pthread_mutex_lock(&frct.instances_lock);

        instance = frct.instances[cep_id];
        if (instance == NULL) {
                pthread_mutex_unlock(&frct.instances_lock);
                return INVALID_CEP_ID;
        }

        r_cep_id = instance->r_cep_id;

        pthread_mutex_unlock(&frct.instances_lock);

        return r_cep_id;
}

uint64_t frct_i_get_addr(cep_id_t cep_id)
{
        struct frct_i * instance;
        uint64_t        r_addr;

        pthread_mutex_lock(&frct.instances_lock);

        instance = frct.instances[cep_id];
        if (instance == NULL) {
                pthread_mutex_unlock(&frct.instances_lock);
                return INVALID_ADDR;
        }

        r_addr = instance->r_address;

        pthread_mutex_unlock(&frct.instances_lock);

        return r_addr;
}

int frct_post_sdu(struct shm_du_buff * sdb)
{
        struct frct_pci frct_pci;
        struct frct_i * instance;

        assert(sdb);

        frct_pci_des(sdb, &frct_pci);

        /* Known cep-ids are delivered to FA (minimal DTP) */
        pthread_mutex_lock(&frct.instances_lock);

        instance = frct.instances[frct_pci.dst_cep_id];
        if (instance == NULL) {
                pthread_mutex_unlock(&frct.instances_lock);
                log_err("Invalid instance.");
                return -1;
        }

        if (instance->state != CONN_ESTABLISHED) {
                pthread_mutex_unlock(&frct.instances_lock);
                log_err("Connection is not established.");
                return -1;
        }

        pthread_mutex_unlock(&frct.instances_lock);

        if (fa_post_sdu_user(frct_pci.dst_cep_id, sdb))
                return -1;

        return 0;
}

int frct_i_write_sdu(cep_id_t             id,
                     struct shm_du_buff * sdb)
{
        struct frct_i * instance;
        struct frct_pci frct_pci;

        assert(sdb);

        pthread_mutex_lock(&frct.instances_lock);

        instance = frct.instances[id];
        if (instance == NULL) {
                pthread_mutex_unlock(&frct.instances_lock);
                log_err("Invalid instance.");
                return -1;
        }

        if (instance->state != CONN_ESTABLISHED) {
                pthread_mutex_unlock(&frct.instances_lock);
                log_err("Connection is not established.");
                return -1;
        }

        frct_pci.dst_cep_id = instance->r_cep_id;
        frct_pci.seqno = (instance->seqno)++;

        if (frct_pci_ser(sdb, &frct_pci)) {
                pthread_mutex_unlock(&frct.instances_lock);
                log_err("Failed to serialize.");
                return -1;
        }

        if (dt_write_sdu(instance->r_address,
                         instance->cube,
                         PDU_TYPE_FRCT,
                         sdb)) {
                pthread_mutex_unlock(&frct.instances_lock);
                log_err("Failed to hand SDU to DT.");
                return -1;
        }

        pthread_mutex_unlock(&frct.instances_lock);

        return 0;
}
