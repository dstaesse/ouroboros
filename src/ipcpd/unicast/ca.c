/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Congestion Avoidance
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

#define OUROBOROS_PREFIX "ca"

#include "config.h"

#include <ouroboros/list.h>
#include <ouroboros/logs.h>

#include "ca.h"
#include "ca/pol.h"

#include <pthread.h>
#include <stdlib.h>

/*
 * A ca_ctx holds congestion state for a (peer address, qos cube) PATH,
 * not for a flow. In the default build the façade interns one ctx per
 * (addr, qc) and shares it across every flow on that path; the policy
 * runs on the shared ctx and cannot tell one flow from many. Per-flow
 * ctx (IPCP_CA_PER_FLOW) is a testing build only: it skips interning so
 * every flow gets its own ctx.
 */

struct ca_ctx {
        uint64_t         addr;
        qoscube_t        qc;
        size_t           refs;
        void *           pol;   /* policy ctx (ops->ctx_create result) */
        struct list_head next;
};

struct {
        struct ca_ops *  ops;
#ifndef IPCP_CA_PER_FLOW
        struct list_head buckets[CA_BUCKETS];
        pthread_mutex_t  mtx;
#endif
} ca;

int ca_init(enum pol_cong_avoid pol)
{
#ifndef IPCP_CA_PER_FLOW
        size_t i;
#endif
        switch(pol) {
        case CA_NONE:
                log_dbg("Disabling congestion control.");
                ca.ops = &nop_ca_ops;
                break;
        case CA_MB_ECN:
                log_dbg("Using multi-bit ECN.");
                ca.ops = &mb_ecn_ca_ops;
                break;
        default:
                return -1;
        }

#ifndef IPCP_CA_PER_FLOW
        for (i = 0; i < CA_BUCKETS; i++)
                list_head_init(&ca.buckets[i]);

        if (pthread_mutex_init(&ca.mtx, NULL) != 0)
                return -1;
#endif
        return 0;
}

void ca_fini(void)
{
#ifndef IPCP_CA_PER_FLOW
        size_t i;

        /* Data path is stopped; drain any ctx a flow left interned. */
        for (i = 0; i < CA_BUCKETS; i++) {
                struct list_head * p;
                struct list_head * h;

                list_for_each_safe(p, h, &ca.buckets[i]) {
                        struct ca_ctx * ctx;
                        ctx = list_entry(p, struct ca_ctx, next);
                        list_del(&ctx->next);
                        ca.ops->ctx_destroy(ctx->pol);
                        free(ctx);
                }
        }

        pthread_mutex_destroy(&ca.mtx);
#endif
        ca.ops = NULL;
}

#ifndef IPCP_CA_PER_FLOW
static size_t ca_bucket(uint64_t addr,
                        qoscube_t qc)
{
        return (addr ^ (addr >> 32) ^ (uint64_t) qc) & (CA_BUCKETS - 1);
}
#endif

void * ca_ctx_get(uint64_t  addr,
                  qoscube_t qc)
{
        struct ca_ctx *    ctx;
#ifndef IPCP_CA_PER_FLOW
        struct list_head * p;
        size_t             b = ca_bucket(addr, qc);

        pthread_mutex_lock(&ca.mtx);

        list_for_each(p, &ca.buckets[b]) {
                ctx = list_entry(p, struct ca_ctx, next);
                if (ctx->addr == addr && ctx->qc == qc) {
                        ctx->refs++;
                        pthread_mutex_unlock(&ca.mtx);
                        return ctx;
                }
        }
#endif
        ctx = malloc(sizeof(*ctx));
        if (ctx == NULL)
                goto fail_ctx;

        ctx->pol = ca.ops->ctx_create();
        if (ctx->pol == NULL)
                goto fail_pol;

        ctx->addr = addr;
        ctx->qc   = qc;
        ctx->refs = 1;

#ifndef IPCP_CA_PER_FLOW
        list_add(&ctx->next, &ca.buckets[b]);

        pthread_mutex_unlock(&ca.mtx);
#endif
        return ctx;
 fail_pol:
        free(ctx);
 fail_ctx:
#ifndef IPCP_CA_PER_FLOW
        pthread_mutex_unlock(&ca.mtx);
#endif
        return NULL;
}

void ca_ctx_put(void * _ctx)
{
        struct ca_ctx * ctx = _ctx;

#ifndef IPCP_CA_PER_FLOW
        pthread_mutex_lock(&ca.mtx);

        if (--ctx->refs > 0) {
                pthread_mutex_unlock(&ca.mtx);
                return;
        }

        list_del(&ctx->next);

        pthread_mutex_unlock(&ca.mtx);
#endif
        ca.ops->ctx_destroy(ctx->pol);

        free(ctx);
}

time_t ca_ctx_update_snd(void *     _ctx,
                         size_t     len,
                         uint8_t    lecn,
                         uint64_t * ftag)
{
        struct ca_ctx * ctx = _ctx;

        return ca.ops->ctx_update_snd(ctx->pol, len, lecn, ftag);
}

bool ca_ctx_update_rcv(void *     _ctx,
                       size_t     len,
                       uint8_t    ecn,
                       uint8_t    cap,
                       uint16_t * ece,
                       uint8_t *  fcap)
{
        struct ca_ctx * ctx = _ctx;

        return ca.ops->ctx_update_rcv(ctx->pol, len, ecn, cap, ece, fcap);
}

void ca_ctx_update_ece(void *   _ctx,
                       uint16_t ece,
                       uint8_t  cap)
{
        struct ca_ctx * ctx = _ctx;

        return ca.ops->ctx_update_ece(ctx->pol, ece, cap);
}

int  ca_calc_ecn(size_t    queued,
                 uint8_t * ecn,
                 qoscube_t qc,
                 size_t    len)
{
        return ca.ops->calc_ecn(queued, ecn, qc, len);
}

bool ca_marks_ecn(void)
{
        return ca.ops->marks_ecn;
}

ssize_t ca_print_stats(void * _ctx,
                       char * buf,
                       size_t len)
{
        struct ca_ctx * ctx = _ctx;

        if (ca.ops->print_stats == NULL)
                return 0;

        return ca.ops->print_stats(ctx->pol, buf, len);
}
