/*
 * Ouroboros - Copyright (C) 2016 - 2020
 *
 * Policy for PFF with alternate next hops
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

#define _POSIX_C_SOURCE 200112L

#include "config.h"

#include <ouroboros/errno.h>
#include <ouroboros/list.h>

#include "pft.h"
#include "alternate_pff.h"

#include <string.h>
#include <assert.h>
#include <pthread.h>

struct nhop {
        struct list_head next;
        int              fd;
};

struct addr {
        struct list_head next;
        uint64_t         addr;
};

struct pff_i {
        struct pft *     pft;

        struct list_head addrs;

        struct list_head nhops_down;

        pthread_rwlock_t lock;
};

struct pol_pff_ops alternate_pff_ops = {
        .create            = alternate_pff_create,
        .destroy           = alternate_pff_destroy,
        .lock              = alternate_pff_lock,
        .unlock            = alternate_pff_unlock,
        .add               = alternate_pff_add,
        .update            = alternate_pff_update,
        .del               = alternate_pff_del,
        .flush             = alternate_pff_flush,
        .nhop              = alternate_pff_nhop,
        .flow_state_change = alternate_flow_state_change
};

static int add_addr(struct pff_i * pff_i,
                    uint64_t       addr)
{
        struct addr * a;

        a = malloc(sizeof(*a));
        if (a == NULL)
                return -1;

        a->addr = addr;

        list_add(&a->next, &(pff_i->addrs));

        return 0;
}

static void del_addr(struct pff_i * pff_i,
                     uint64_t       addr)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &(pff_i->addrs)) {
                struct addr * e = list_entry(p, struct addr, next);
                if (e->addr == addr) {
                        list_del(&e->next);
                        free(e);
                        return;
                }
        }
}

static void del_addrs(struct pff_i * pff_i)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &(pff_i->addrs)) {
                struct addr * e = list_entry(p, struct addr, next);
                list_del(&e->next);
                free(e);
        }
}

static void del_nhops_down(struct pff_i * pff_i)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &(pff_i->nhops_down)) {
                struct nhop * e = list_entry(p, struct nhop, next);
                list_del(&e->next);
                free(e);
        }
}

static int del_nhop_down(struct pff_i * pff_i,
                         int            fd)
{
        struct list_head * p;
        struct list_head * h;

        list_for_each_safe(p, h, &(pff_i->nhops_down)) {
                struct nhop * e = list_entry(p, struct nhop, next);
                if (e->fd == fd) {
                        list_del(&e->next);
                        free(e);
                        return 0;
                }
        }

        return -1;
}

static int add_nhop_down(struct pff_i * pff_i,
                         int            fd)
{
        struct nhop *      nhop;

        nhop = malloc(sizeof(*nhop));
        if (nhop == NULL)
                return -1;

        nhop->fd = fd;

        list_add(&nhop->next, &(pff_i->nhops_down));

        return 0;
}

static bool nhops_down_has(struct pff_i * pff_i,
                           int            fd)
{
        struct list_head * pos = NULL;

        list_for_each(pos, &pff_i->nhops_down) {
                struct nhop * e = list_entry(pos, struct nhop, next);
                if (e->fd == fd)
                        return true;
        }

        return false;
}

static int add_to_pft(struct pff_i * pff_i,
                      uint64_t       addr,
                      int *          fd,
                      size_t         len)
{
        int * fds;

        assert(pff_i);
        assert(len > 0);

        fds = malloc(sizeof(*fds) * (len + 1));
        if (fds == NULL)
                goto fail_malloc;

        memcpy(fds, fd, len * sizeof(*fds));
        /* Put primary hop again at the end */
        fds[len] = fds[0];

        if (pft_insert(pff_i->pft, addr, fds, len))
                goto fail_insert;

        return 0;

 fail_insert:
        free(fds);
 fail_malloc:
        return -1;
}

struct pff_i * alternate_pff_create(void)
{
        struct pff_i * tmp;

        tmp = malloc(sizeof(*tmp));
        if (tmp == NULL)
                goto fail_malloc;

        if (pthread_rwlock_init(&tmp->lock, NULL))
                goto fail_lock;

        tmp->pft = pft_create(PFT_SIZE, false);
        if (tmp->pft == NULL)
                goto fail_pft;

        list_head_init(&tmp->nhops_down);
        list_head_init(&tmp->addrs);

        return tmp;

 fail_pft:
        pthread_rwlock_destroy(&tmp->lock);
 fail_lock:
        free(tmp);
 fail_malloc:
        return NULL;
}

void alternate_pff_destroy(struct pff_i * pff_i)
{
        assert(pff_i);

        pft_destroy(pff_i->pft);
        del_nhops_down(pff_i);
        del_addrs(pff_i);
        pthread_rwlock_destroy(&pff_i->lock);
        free(pff_i);
}

void alternate_pff_lock(struct pff_i * pff_i)
{
        pthread_rwlock_wrlock(&pff_i->lock);
}

void alternate_pff_unlock(struct pff_i * pff_i)
{
        pthread_rwlock_unlock(&pff_i->lock);
}

int alternate_pff_add(struct pff_i * pff_i,
                      uint64_t       addr,
                      int *          fd,
                      size_t         len)
{
        assert(pff_i);
        assert(len > 0);

        if (add_to_pft(pff_i, addr, fd, len))
                return -1;

        if (add_addr(pff_i, addr)) {
                pft_delete(pff_i->pft, addr);
                return -1;
        }

        return 0;
}

int alternate_pff_update(struct pff_i * pff_i,
                         uint64_t       addr,
                         int *          fd,
                         size_t         len)
{
        assert(pff_i);
        assert(len > 0);

        if (pft_delete(pff_i->pft, addr))
                return -1;

        if (add_to_pft(pff_i, addr, fd, len))
                return -1;

        return 0;
}

int alternate_pff_del(struct pff_i * pff_i,
                      uint64_t       addr)
{
        assert(pff_i);

        del_addr(pff_i, addr);

        if (pft_delete(pff_i->pft, addr))
                return -1;

        return 0;
}

void alternate_pff_flush(struct pff_i * pff_i)
{
        assert(pff_i);

        pft_flush(pff_i->pft);

        del_nhops_down(pff_i);

        del_addrs(pff_i);
}

int alternate_pff_nhop(struct pff_i * pff_i,
                       uint64_t       addr)
{
        int    fd;
        size_t len;
        int *  fds;

        assert(pff_i);

        pthread_rwlock_rdlock(&pff_i->lock);

        if (pft_lookup(pff_i->pft, addr, &fds, &len)) {
                pthread_rwlock_unlock(&pff_i->lock);
                return -1;
        }

        fd = *fds;

        pthread_rwlock_unlock(&pff_i->lock);

        return fd;
}

int alternate_flow_state_change(struct pff_i * pff_i,
                                int            fd,
                                bool           up)
{
        struct list_head * p;
        size_t             len;
        int *              fds;
        size_t             i;
        int                tmp;

        assert(pff_i);

        pthread_rwlock_wrlock(&pff_i->lock);

        if (up) {
                if (del_nhop_down(pff_i, fd)) {
                        pthread_rwlock_unlock(&pff_i->lock);
                        return -1;
                }
        } else {
                if (add_nhop_down(pff_i, fd)) {
                        pthread_rwlock_unlock(&pff_i->lock);
                        return -1;
                }
        }

        list_for_each(p, &pff_i->addrs) {
                struct addr * e = list_entry(p, struct addr, next);
                if (pft_lookup(pff_i->pft, e->addr, &fds, &len)) {
                        pthread_rwlock_unlock(&pff_i->lock);
                        return -1;
                }

                if (up) {
                        /* It is using an alternate */
                        if (fds[len] == fd && fds[0] != fd) {
                                for (i = 0 ; i < len; i++) {
                                        /* Found the primary */
                                        if (fds[i] == fd) {
                                                tmp = fds[0];
                                                fds[0] = fds[i];
                                                fds[i] = tmp;
                                                break;
                                        }
                                }
                        }
                } else {
                        /* Need to switch to a (different) alternate */
                        if (fds[0] == fd) {
                                for (i = 1; i < len; i++) {
                                        /* Usable alternate */
                                        if (!nhops_down_has(pff_i, fds[i])) {
                                                tmp = fds[0];
                                                fds[0] = fds[i];
                                                fds[i] = tmp;
                                                break;
                                        }
                                }
                        }
                }
        }

        pthread_rwlock_unlock(&pff_i->lock);

        return 0;
}
