/*
 * Ouroboros - Copyright (C) 2016 - 2017
 *
 * Reordering queue
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

#include <ouroboros/rq.h>

#include <assert.h>

struct pdu {
        uint64_t seqno;
        size_t   idx;
};

struct rq {
        struct pdu * items;
        int          n_items;
        int          size;
};

struct rq * rq_create(int size)
{
        struct rq * rq;

        rq = malloc(sizeof(*rq));
        if (rq == NULL)
                return NULL;

        rq->items = malloc(sizeof(struct pdu) * (size + 1));
        if (rq->items == NULL) {
                free(rq);
                return NULL;
        }

        rq->size = size;
        rq->n_items = 0;

        return rq;
}

void rq_destroy(struct rq * rq)
{
        assert(rq);

        free(rq->items);
        free(rq);
}

int rq_push(struct rq * rq,
            uint64_t    seqno,
            size_t      idx)
{
        int i;
        int j;

        assert(rq);

        /* Queue is full. */
        if (rq->n_items == rq->size)
                return -1;

        i = ++rq->n_items;
        j = i / 2;
        while (i > 1 && rq->items[j].seqno > seqno) {
                rq->items[i] = rq->items[j];
                i = j;
                j = j / 2;
        }

        rq->items[i].seqno = seqno;
        rq->items[i].idx = idx;

        return 0;
}

uint64_t rq_peek(struct rq * rq)
{
        assert(rq);

        return rq->items[1].seqno;
}

bool rq_is_empty(struct rq * rq)
{
        assert(rq);

        return (rq->n_items == 0);
}

size_t rq_pop(struct rq * rq)
{
        size_t idx;
        int    i;
        int    j;
        int    k;

        assert(rq);

        idx = rq->items[1].idx;

        rq->items[1] = rq->items[rq->n_items];
        rq->n_items--;

        i = 1;
        while (true) {
                k = i;
                j = 2 * i;

                if (j <= rq->n_items && rq->items[j].seqno < rq->items[k].seqno)
                        k = j;

                if (j + 1 <= rq->n_items &&
                    rq->items[j + 1].seqno < rq->items[k].seqno)
                        k = j + 1;

                if (k == i)
                        break;

                rq->items[i] = rq->items[k];
                i = k;
        }

        rq->items[i] = rq->items[rq->n_items + 1];

        return idx;
}

bool rq_has(struct rq * rq,
            uint64_t    seqno)
{
        int i;

        assert(rq);

        for (i = 1; i <= rq->n_items; i++)
                if (rq->items[i].seqno == seqno)
                        return true;

        return false;
}
