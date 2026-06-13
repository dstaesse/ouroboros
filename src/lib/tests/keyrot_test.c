/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Test of the key-rotation schedule
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

#define _POSIX_C_SOURCE 200809L

#include "config.h"

#include <test/test.h>

#ifdef HAVE_OPENSSL
#include <ouroboros/crypt.h>
#include <ouroboros/pthread.h>

#include "crypt/keyrot.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static const uint8_t SEED_A[SYMMKEYSZ] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
};

static int test_create_destroy(void)
{
        struct keyrot * kr;

        TEST_START();

        kr = keyrot_create(SEED_A, 0, 0);
        if (kr == NULL)
                goto fail;

        keyrot_destroy(kr);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_epoch_range(void)
{
        struct keyrot * a;

        TEST_START();

        /* epoch is a 4-bit wire field; 16 and up must be refused. */
        if (keyrot_create(SEED_A, 16, 0) != NULL)
                goto fail;

        a = keyrot_create(SEED_A, 0, 0);
        if (a == NULL)
                goto fail;

        if (keyrot_rekey(a, SEED_A, 16) == 0)
                goto fail_a;

        keyrot_destroy(a);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_a:
        keyrot_destroy(a);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_tx_deterministic(void)
{
        struct keyrot * a;
        struct keyrot * b;
        uint8_t         sela[KR_SELECTOR_LEN];
        uint8_t         selb[KR_SELECTOR_LEN];
        uint8_t         na[KR_NONCE_LEN];
        uint8_t         nb[KR_NONCE_LEN];
        const uint8_t * ka;
        const uint8_t * kb;

        TEST_START();

        a = keyrot_create(SEED_A, 0, 0);
        if (a == NULL)
                goto fail;

        b = keyrot_create(SEED_A, 0, 0);
        if (b == NULL)
                goto fail_a;

        if (keyrot_tx_next(a, sela, &ka, na) != 0)
                goto fail_b;

        if (keyrot_tx_next(b, selb, &kb, nb) != 0)
                goto fail_b;

        if (memcmp(sela, selb, KR_SELECTOR_LEN) != 0)
                goto fail_b;

        if (memcmp(ka, kb, SYMMKEYSZ) != 0)
                goto fail_b;

        if (memcmp(na, nb, KR_NONCE_LEN) != 0)
                goto fail_b;

        keyrot_destroy(b);
        keyrot_destroy(a);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_b:
        keyrot_destroy(b);
 fail_a:
        keyrot_destroy(a);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_selector_layout(void)
{
        struct keyrot * a;
        uint8_t         sel[KR_SELECTOR_LEN];
        uint8_t         nonce[KR_NONCE_LEN];
        const uint8_t * k;

        TEST_START();

        a = keyrot_create(SEED_A, 3, 0);
        if (a == NULL)
                goto fail;

        /* First packet: epoch 3, node 0, seq 0 */
        if (keyrot_tx_next(a, sel, &k, nonce) != 0)
                goto fail_a;

        if ((sel[0] >> 4) != 3)            /* epoch */
                goto fail_a;

        if ((((sel[0] & 0x0F) << 8) | sel[1]) != 0) /* node */
                goto fail_a;

        if (sel[2] != 0 || sel[3] != 0 || sel[4] != 0 || sel[5] != 0)
                goto fail_a;

        /* Second packet: seq advances to 1 */
        if (keyrot_tx_next(a, sel, &k, nonce) != 0)
                goto fail_a;

        if (sel[5] != 1)
                goto fail_a;

        keyrot_destroy(a);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_a:
        keyrot_destroy(a);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_nodes_left_initial(void)
{
        struct keyrot * a;

        TEST_START();

        a = keyrot_create(SEED_A, 0, 0);
        if (a == NULL)
                goto fail;

        if (keyrot_tx_nodes_left(a) != KEY_NODE_COUNT)
                goto fail_a;

        keyrot_destroy(a);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_a:
        keyrot_destroy(a);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_roundtrip(void)
{
        struct keyrot * a; /* role 0 */
        struct keyrot * b; /* role 1 */
        uint8_t         sel[KR_SELECTOR_LEN];
        uint8_t         ntx[KR_NONCE_LEN];
        uint8_t         nrx[KR_NONCE_LEN];
        uint8_t         ktx[SYMMKEYSZ];
        const uint8_t * ptx;
        const uint8_t * prx;
        struct kr_rx    rx;
        int             i;

        TEST_START();

        a = keyrot_create(SEED_A, 0, 0);
        if (a == NULL)
                goto fail;

        b = keyrot_create(SEED_A, 0, 1);
        if (b == NULL)
                goto fail_a;

        for (i = 0; i < 256; i++) {
                if (keyrot_tx_next(a, sel, &ptx, ntx) != 0)
                        goto fail_b;
                memcpy(ktx, ptx, SYMMKEYSZ);
                if (keyrot_rx_lookup(b, sel, &prx, nrx, &rx) != 0)
                        goto fail_b;
                if (keyrot_rx_commit(b, &rx) != 0)
                        goto fail_b;
                if (memcmp(ktx, prx, SYMMKEYSZ) != 0)
                        goto fail_b;
                if (memcmp(ntx, nrx, KR_NONCE_LEN) != 0)
                        goto fail_b;
        }

        keyrot_destroy(b);
        keyrot_destroy(a);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_b:
        keyrot_destroy(b);
 fail_a:
        keyrot_destroy(a);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_direction_separation(void)
{
        struct keyrot * a; /* role 0 */
        struct keyrot * b; /* role 1 */
        uint8_t         sela[KR_SELECTOR_LEN];
        uint8_t         selb[KR_SELECTOR_LEN];
        uint8_t         n[KR_NONCE_LEN];
        uint8_t         ka[SYMMKEYSZ];
        const uint8_t * pa;
        const uint8_t * pb;

        TEST_START();

        a = keyrot_create(SEED_A, 0, 0);
        if (a == NULL)
                goto fail;

        b = keyrot_create(SEED_A, 0, 1);
        if (b == NULL)
                goto fail_a;

        if (keyrot_tx_next(a, sela, &pa, n) != 0)
                goto fail_b;

        memcpy(ka, pa, SYMMKEYSZ);
        if (keyrot_tx_next(b, selb, &pb, n) != 0)
                goto fail_b;

        /* Same position, different role -> different leaf key */
        if (memcmp(ka, pb, SYMMKEYSZ) == 0)
                goto fail_b;

        keyrot_destroy(b);
        keyrot_destroy(a);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_b:
        keyrot_destroy(b);
 fail_a:
        keyrot_destroy(a);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/* Build a selector by hand (test knows the wire format). */
static void mk_sel(uint8_t  epoch,
                   uint16_t node,
                   uint32_t seq,
                   uint8_t  sel[KR_SELECTOR_LEN])
{
        sel[0] = (uint8_t) ((epoch << 4) | ((node >> 8) & 0x0F));
        sel[1] = (uint8_t) (node & 0xFF);
        sel[2] = (uint8_t) (seq >> 24);
        sel[3] = (uint8_t) (seq >> 16);
        sel[4] = (uint8_t) (seq >> 8);
        sel[5] = (uint8_t) (seq);
}

static int test_random_access(void)
{
        struct keyrot * b;
        uint8_t         s0[KR_SELECTOR_LEN];
        uint8_t         s5[KR_SELECTOR_LEN];
        uint8_t         n[KR_NONCE_LEN];
        uint8_t         k_first[SYMMKEYSZ];
        uint8_t         k_node5[SYMMKEYSZ];
        const uint8_t * p;
        struct kr_rx    rx;

        TEST_START();

        b = keyrot_create(SEED_A, 0, 1);
        if (b == NULL)
                goto fail;

        mk_sel(0, 0, 0, s0);
        mk_sel(0, 5, 12345, s5); /* a far-ahead node, mid-span */

        /* Jump straight to node 0 */
        if (keyrot_rx_lookup(b, s0, &p, n, &rx) != 0)
                goto fail_b;

        memcpy(k_first, p, SYMMKEYSZ);

        /* Jump forward to node 5 (simulates a burst skip) */
        if (keyrot_rx_lookup(b, s5, &p, n, &rx) != 0)
                goto fail_b;

        memcpy(k_node5, p, SYMMKEYSZ);

        /* Different nodes must yield different keys */
        if (memcmp(k_first, k_node5, SYMMKEYSZ) == 0)
                goto fail_b;

        /* Jump back to node 0: still works, identical (no wedge) */
        if (keyrot_rx_lookup(b, s0, &p, n, &rx) != 0)
                goto fail_b;

        if (memcmp(k_first, p, SYMMKEYSZ) != 0)
                goto fail_b;

        /* Out-of-range node must be rejected */
        mk_sel(0, KEY_NODE_COUNT, 0, s0);
        if (keyrot_rx_lookup(b, s0, &p, n, &rx) == 0)
                goto fail_b;

        keyrot_destroy(b);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_b:
        keyrot_destroy(b);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static const uint8_t SEED_B[SYMMKEYSZ] = {
        0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8,
        0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf, 0xb0,
        0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8,
        0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf, 0xc0
};

/*
 * Look up and commit one within-node counter on epoch 0. Returns 0 on
 * accept, 1 on a rejected commit (replay or too old), and -1 if the
 * lookup itself failed - kept distinct so a reject assertion can never
 * pass on an unrelated lookup miss.
 */
static int commit_ctr(struct keyrot * kr,
                      uint32_t        ctr)
{
        uint8_t         sel[KR_SELECTOR_LEN];
        uint8_t         n[KR_NONCE_LEN];
        const uint8_t * k;
        struct kr_rx    rx;

        mk_sel(0, 0, ctr, sel);

        if (keyrot_rx_lookup(kr, sel, &k, n, &rx) != 0)
                return -1;

        return keyrot_rx_commit(kr, &rx) == 0 ? 0 : 1;
}

static int test_replay_window(void)
{
        struct keyrot * b;
        struct keyrot * c;
        uint32_t        base;
        uint32_t        jump;

        TEST_START();

        b = keyrot_create(SEED_A, 0, 1);
        if (b == NULL)
                goto fail;

        /* Fresh counters accepted; an immediate replay is rejected. */
        if (commit_ctr(b, 100) != 0)
                goto fail_b;

        if (commit_ctr(b, 100) != 1)
                goto fail_b;

        /* In-window reorder: accepted once, rejected on replay. */
        if (commit_ctr(b, 105) != 0)
                goto fail_b;

        if (commit_ctr(b, 102) != 0)
                goto fail_b;

        if (commit_ctr(b, 102) != 1)
                goto fail_b;

        /* Too-old boundary: the window edge is rejected, just inside is not. */
        base = 4 * KEY_REPLAY_WINDOW;
        if (commit_ctr(b, base) != 0)
                goto fail_b;

        if (commit_ctr(b, base - (KEY_REPLAY_WINDOW - 64)) != 1)
                goto fail_b;

        if (commit_ctr(b, base - (KEY_REPLAY_WINDOW - 64) + 1) != 0)
                goto fail_b;

        /*
         * RFC 6479 slack-word regression: two low counters, then a
         * forward jump of a full bitmap that aliases their slot, then a
         * replay of a low counter. Without the reserved slack word this
         * replay is wrongly accepted.
         */
        c = keyrot_create(SEED_A, 0, 1);
        if (c == NULL)
                goto fail_b;

        if (commit_ctr(c, 70) != 0)
                goto fail_c;

        if (commit_ctr(c, 74) != 0)
                goto fail_c;

        jump = KEY_REPLAY_WINDOW + 63;
        if (commit_ctr(c, jump) != 0)
                goto fail_c;

        if (commit_ctr(c, 74) != 1)
                goto fail_c;

        keyrot_destroy(c);
        keyrot_destroy(b);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_c:
        keyrot_destroy(c);
 fail_b:
        keyrot_destroy(b);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_lookup_no_commit(void)
{
        struct keyrot * b;
        uint8_t         sel[KR_SELECTOR_LEN];
        uint8_t         n[KR_NONCE_LEN];
        const uint8_t * k;
        struct kr_rx    rx;
        int             i;

        TEST_START();

        b = keyrot_create(SEED_A, 0, 1);
        if (b == NULL)
                goto fail;

        mk_sel(0, 0, 100, sel);

        /* Repeated lookups are pre-AEAD and must not consume the slot. */
        for (i = 0; i < 4; i++) {
                if (keyrot_rx_lookup(b, sel, &k, n, &rx) != 0)
                        goto fail_b;
        }

        /* The slot is still fresh, so the first commit accepts ... */
        if (keyrot_rx_commit(b, &rx) != 0)
                goto fail_b;

        /* ... and only the commit advanced it, so the next is a replay. */
        if (keyrot_rx_commit(b, &rx) == 0)
                goto fail_b;

        keyrot_destroy(b);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_b:
        keyrot_destroy(b);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_commit_prev_batch(void)
{
        struct keyrot * b;
        uint8_t         sel[KR_SELECTOR_LEN];
        uint8_t         n[KR_NONCE_LEN];
        const uint8_t * k;
        struct kr_rx    rx;

        TEST_START();

        b = keyrot_create(SEED_A, 0, 1);
        if (b == NULL)
                goto fail;

        /* Capture a packet under cur (epoch 0). */
        mk_sel(0, 0, 7, sel);
        if (keyrot_rx_lookup(b, sel, &k, n, &rx) != 0)
                goto fail_b;

        /* Re-key: the captured batch becomes prev and the flag clears. */
        if (keyrot_rekey(b, SEED_B, 1) != 0)
                goto fail_b;

        /* The straggler commits under prev without claiming a switch. */
        if (keyrot_rx_commit(b, &rx) != 0)
                goto fail_b;

        if (keyrot_peer_switched(b))
                goto fail_b;

        /* prev still holds a replay window: its replay is rejected. */
        if (keyrot_rx_commit(b, &rx) == 0)
                goto fail_b;

        keyrot_destroy(b);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_b:
        keyrot_destroy(b);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_replay_forward_clear(void)
{
        struct keyrot * d;
        uint32_t        low;
        uint32_t        alias;
        uint32_t        jump;

        TEST_START();

        d = keyrot_create(SEED_A, 0, 1);
        if (d == NULL)
                goto fail;

        /* alias shares low's slot a window away; the jump must clear it. */
        low   = 10;
        alias = low + KEY_REPLAY_WINDOW;
        jump  = alias + KEY_REPLAY_WINDOW / 2;

        if (commit_ctr(d, low) != 0)
                goto fail_d;

        if (commit_ctr(d, jump) != 0)
                goto fail_d;

        if (commit_ctr(d, alias) != 0)
                goto fail_d;

        if (commit_ctr(d, alias) != 1)
                goto fail_d;

        keyrot_destroy(d);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_d:
        keyrot_destroy(d);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_rekey_overlap(void)
{
        struct keyrot * a; /* role 0 */
        struct keyrot * b; /* role 1 */
        uint8_t         old_sel[KR_SELECTOR_LEN];
        uint8_t         sel[KR_SELECTOR_LEN];
        uint8_t         ntx[KR_NONCE_LEN];
        uint8_t         nrx[KR_NONCE_LEN];
        uint8_t         ktx[SYMMKEYSZ];
        const uint8_t * ptx;
        const uint8_t * prx;
        struct kr_rx    rx;

        TEST_START();

        a = keyrot_create(SEED_A, 0, 0);
        if (a == NULL)
                goto fail;

        b = keyrot_create(SEED_A, 0, 1);
        if (b == NULL)
                goto fail_a;

        /* Send one gen-0 packet; keep its selector for the overlap. */
        if (keyrot_tx_next(a, old_sel, &ptx, ntx) != 0)
                goto fail_b;

        memcpy(ktx, ptx, SYMMKEYSZ);
        if (keyrot_rx_lookup(b, old_sel, &prx, nrx, &rx) != 0)
                goto fail_b;

        if (memcmp(ktx, prx, SYMMKEYSZ) != 0)
                goto fail_b;

        /* Both ends re-key to epoch 1 with a fresh seed. */
        if (keyrot_rekey(a, SEED_B, 1) != 0)
                goto fail_b;

        if (keyrot_rekey(b, SEED_B, 1) != 0)
                goto fail_b;

        /* TX is gated until promotion; promote a to emit the new epoch. */
        keyrot_tx_promote(a);

        /* New gen-1 traffic works. */
        if (keyrot_tx_next(a, sel, &ptx, ntx) != 0)
                goto fail_b;

        memcpy(ktx, ptx, SYMMKEYSZ);
        if (keyrot_rx_lookup(b, sel, &prx, nrx, &rx) != 0)
                goto fail_b;

        if (memcmp(ktx, prx, SYMMKEYSZ) != 0)
                goto fail_b;

        /* A straggling gen-0 packet still decrypts (overlap window). */
        if (keyrot_rx_lookup(b, old_sel, &prx, nrx, &rx) != 0)
                goto fail_b;

        /* An unknown epoch is rejected. */
        mk_sel(7, 0, 0, sel);
        if (keyrot_rx_lookup(b, sel, &prx, nrx, &rx) == 0)
                goto fail_b;

        keyrot_destroy(b);
        keyrot_destroy(a);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_b:
        keyrot_destroy(b);
 fail_a:
        keyrot_destroy(a);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_tx_gate(void)
{
        struct keyrot * a; /* role 0 */
        struct keyrot * b; /* role 1 */
        uint8_t         sel[KR_SELECTOR_LEN];
        uint8_t         n[KR_NONCE_LEN];
        const uint8_t * p;
        struct kr_rx    rx;

        TEST_START();

        a = keyrot_create(SEED_A, 0, 0);
        if (a == NULL)
                goto fail;

        b = keyrot_create(SEED_A, 0, 1);
        if (b == NULL)
                goto fail_a;

        /* Both re-key to epoch 1; TX must stay on epoch 0 until promoted. */
        if (keyrot_rekey(a, SEED_B, 1) != 0)
                goto fail_b;

        if (keyrot_rekey(b, SEED_B, 1) != 0)
                goto fail_b;

        /* a's TX still stamps the old epoch (0). */
        if (keyrot_tx_next(a, sel, &p, n) != 0)
                goto fail_b;

        if ((sel[0] >> 4) != 0)
                goto fail_b;

        /* b decrypts the old-epoch packet via its prev batch. */
        if (keyrot_rx_lookup(b, sel, &p, n, &rx) != 0)
                goto fail_b;

        if (keyrot_rx_commit(b, &rx) != 0)
                goto fail_b;

        /* b has not yet seen the new epoch from a. */
        if (keyrot_peer_switched(b))
                goto fail_b;

        /* a promotes; its TX now stamps the new epoch (1). */
        keyrot_tx_promote(a);
        if (keyrot_tx_next(a, sel, &p, n) != 0)
                goto fail_b;

        if ((sel[0] >> 4) != 1)
                goto fail_b;

        /* b sees the new epoch and reports the peer switched. */
        if (keyrot_rx_lookup(b, sel, &p, n, &rx) != 0)
                goto fail_b;

        if (keyrot_rx_commit(b, &rx) != 0)
                goto fail_b;

        if (!keyrot_peer_switched(b))
                goto fail_b;

        keyrot_destroy(b);
        keyrot_destroy(a);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_b:
        keyrot_destroy(b);
 fail_a:
        keyrot_destroy(a);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_peer_switched_commit_only(void)
{
        struct keyrot * b;
        uint8_t         sel[KR_SELECTOR_LEN];
        uint8_t         n[KR_NONCE_LEN];
        const uint8_t * k;
        struct kr_rx    rx;

        TEST_START();

        b = keyrot_create(SEED_A, 0, 1);
        if (b == NULL)
                goto fail;

        /* A re-key clears the flag until a packet is seen on cur. */
        if (keyrot_rekey(b, SEED_B, 1) != 0)
                goto fail_b;

        if (keyrot_peer_switched(b))
                goto fail_b;

        mk_sel(1, 0, 0, sel);

        /* Lookup is pre-AEAD: selecting a key must not flip the flag. */
        if (keyrot_rx_lookup(b, sel, &k, n, &rx) != 0)
                goto fail_b;

        if (keyrot_peer_switched(b))
                goto fail_b;

        /* Commit runs post-AEAD and is what records the peer switched. */
        if (keyrot_rx_commit(b, &rx) != 0)
                goto fail_b;

        if (!keyrot_peer_switched(b))
                goto fail_b;

        keyrot_destroy(b);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_b:
        keyrot_destroy(b);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_commit_evicted(void)
{
        struct keyrot * b;
        uint8_t         sel[KR_SELECTOR_LEN];
        uint8_t         n[KR_NONCE_LEN];
        const uint8_t * k;
        struct kr_rx    rx;

        TEST_START();

        b = keyrot_create(SEED_A, 0, 1);
        if (b == NULL)
                goto fail;

        mk_sel(0, 0, 3, sel);
        if (keyrot_rx_lookup(b, sel, &k, n, &rx) != 0)
                goto fail_b;

        /* Two re-keys drop the captured batch from both cur and prev. */
        if (keyrot_rekey(b, SEED_B, 1) != 0)
                goto fail_b;

        if (keyrot_rekey(b, SEED_A, 2) != 0)
                goto fail_b;

        /* Commit on an evicted batch is a silent no-op, not a fault. */
        if (keyrot_rx_commit(b, &rx) != 0)
                goto fail_b;

        keyrot_destroy(b);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_b:
        keyrot_destroy(b);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

/*
 * Concurrency: many TX threads + RX + re-key share one keyrot. The
 * (epoch, counter) the TX side stamps must be globally unique (no AEAD
 * nonce reuse). Capped below 16 re-keys so epoch maps 1:1 to a batch and
 * the wire epoch never wraps (a wrapped epoch under a fresh key is not
 * reuse but would false-trip the uniqueness check). Run under TSan to
 * catch data races the static reviews can't.
 */
#define CT_THREADS 4
#define CT_PKTS    2000
#define CT_REKEYS  8

struct ct_rec {
        uint8_t  epoch;
        uint64_t ctr;
};

struct ct_arg {
        struct keyrot * kr;
        struct ct_rec * recs;
        size_t          n;
};

static void * ct_tx_thread(void * a)
{
        struct ct_arg * arg = a;
        uint8_t         sel[KR_SELECTOR_LEN];
        uint8_t         nonce[KR_NONCE_LEN];
        const uint8_t * k;
        uint64_t        ctr;
        size_t          i;
        size_t          j;

        for (i = 0; i < CT_PKTS; i++) {
                if (keyrot_tx_next(arg->kr, sel, &k, nonce) != 0)
                        continue;

                ctr = 0;
                for (j = 0; j < 8; j++)
                        ctr = (ctr << 8) | nonce[j];

                arg->recs[arg->n].epoch = (uint8_t) (sel[0] >> 4);
                arg->recs[arg->n].ctr   = ctr;
                arg->n++;
        }

        return NULL;
}

static void * ct_rx_thread(void * a)
{
        struct keyrot * kr = a;
        uint8_t         sel[KR_SELECTOR_LEN];
        uint8_t         nonce[KR_NONCE_LEN];
        const uint8_t * k;
        struct kr_rx    rx;
        size_t          i;

        /* Exercise rx_lookup against re-key reclaim; results ignored. */
        for (i = 0; i < CT_PKTS; i++) {
                mk_sel((uint8_t) (i % 16), 0, (uint32_t) i, sel);
                if (keyrot_rx_lookup(kr, sel, &k, nonce, &rx) == 0)
                        (void) keyrot_rx_commit(kr, &rx);
        }

        return NULL;
}

static void * ct_rekey_thread(void * a)
{
        struct keyrot * kr = a;
        struct timespec t;
        int             e;

        t.tv_sec  = 0;
        t.tv_nsec = 2 * 1000 * 1000; /* 2 ms */

        for (e = 1; e <= CT_REKEYS; e++) {
                nanosleep(&t, NULL);
                if (keyrot_rekey(kr, (e & 1) ? SEED_B : SEED_A,
                                 (uint8_t) e) != 0)
                        break;
                keyrot_tx_promote(kr);
        }

        return NULL;
}

static int ct_cmp(const void * x,
                  const void * y)
{
        const struct ct_rec * a = x;
        const struct ct_rec * b = y;

        if (a->epoch != b->epoch)
                return a->epoch < b->epoch ? -1 : 1;

        if (a->ctr != b->ctr)
                return a->ctr < b->ctr ? -1 : 1;

        return 0;
}

static int test_concurrent_nonce_unique(void)
{
        struct keyrot * kr;
        struct ct_arg   arg[CT_THREADS];
        pthread_t       tx[CT_THREADS];
        pthread_t       rx;
        pthread_t       rk;
        struct ct_rec * all;
        size_t          total;
        size_t          i;
        bool            reuse = false;

        TEST_START();

        kr = keyrot_create(SEED_A, 0, 0);
        if (kr == NULL)
                goto fail;

        all = malloc(sizeof(*all) * CT_THREADS * CT_PKTS);
        if (all == NULL)
                goto fail_kr;

        for (i = 0; i < CT_THREADS; i++) {
                arg[i].kr   = kr;
                arg[i].n    = 0;
                arg[i].recs = all + i * CT_PKTS;
        }

        for (i = 0; i < CT_THREADS; i++)
                pthread_create(&tx[i], NULL, ct_tx_thread, &arg[i]);

        pthread_create(&rx, NULL, ct_rx_thread, kr);
        pthread_create(&rk, NULL, ct_rekey_thread, kr);

        for (i = 0; i < CT_THREADS; i++)
                pthread_join(tx[i], NULL);

        pthread_join(rx, NULL);
        pthread_join(rk, NULL);

        total = 0;
        for (i = 0; i < CT_THREADS; i++) {
                memmove(all + total, all + i * CT_PKTS,
                        arg[i].n * sizeof(*all));
                total += arg[i].n;
        }

        qsort(all, total, sizeof(*all), ct_cmp);

        for (i = 1; i < total; i++)
                if (ct_cmp(&all[i - 1], &all[i]) == 0) {
                        printf("(epoch %u, ctr %llu) reused\n",
                               all[i].epoch,
                               (unsigned long long) all[i].ctr);
                        reuse = true;
                        break;
                }

        free(all);

        if (reuse)
                goto fail_kr;

        keyrot_destroy(kr);

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail_kr:
        keyrot_destroy(kr);
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}
#endif /* HAVE_OPENSSL */

int keyrot_test(int     argc,
                char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

#ifdef HAVE_OPENSSL
        ret |= test_create_destroy();
        ret |= test_epoch_range();
        ret |= test_tx_deterministic();
        ret |= test_selector_layout();
        ret |= test_nodes_left_initial();
        ret |= test_roundtrip();
        ret |= test_direction_separation();
        ret |= test_random_access();
        ret |= test_peer_switched_commit_only();
        ret |= test_commit_evicted();
        ret |= test_replay_window();
        ret |= test_lookup_no_commit();
        ret |= test_commit_prev_batch();
        ret |= test_replay_forward_clear();
        ret |= test_rekey_overlap();
        ret |= test_tx_gate();
        ret |= test_concurrent_nonce_unique();
#endif
        return ret;
}
