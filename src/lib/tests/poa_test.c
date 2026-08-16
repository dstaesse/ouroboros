/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * Flow PoA tests
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

#if defined(__linux__) || defined(__CYGWIN__)
#define _DEFAULT_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif

#include <test/test.h>

#include "poa/addr.c"
#ifdef HAVE_RAW_SOCKETS
#include "poa/eth.c"
#endif

#include <arpa/inet.h>
#include <stdio.h>

#ifdef HAVE_RAW_SOCKETS
static const uint8_t eth_our_mac[POA_MAC_SIZE] =
        { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
static const uint8_t eth_far_mac[POA_MAC_SIZE] =
        { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 };
static const uint8_t eth_bc_mac[POA_MAC_SIZE] =
        { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
#endif

/* PoA core stubs: the reader threads never run in this test. */
void poa_rx_pkt(struct poa *         poa,
                uint32_t             eid,
                struct ssm_pk_buff * spb)
{
        (void) poa;
        (void) eid;
        (void) spb;
}

void poa_rx_mgmt(struct poa *            poa,
                 const struct poa_addr * src,
                 const uint8_t *         buf,
                 size_t                  len)
{
        (void) poa;
        (void) src;
        (void) buf;
        (void) len;
}

int poa_spb_reserve(struct ssm_pk_buff ** spb,
                    size_t                len)
{
        (void) spb;
        (void) len;

        return -1;
}

size_t poa_link_updown(int  ifindex,
                       bool up)
{
        (void) ifindex;
        (void) up;

        return 0;
}

bool poa_has_name(const uint8_t * hash)
{
        (void) hash;

        return false;
}

int poa_bcast_mgmt(const struct poa_addr * dst,
                   const uint8_t *         buf,
                   size_t                  len)
{
        (void) dst;
        (void) buf;
        (void) len;

        return 0;
}

static void udp4_addr(struct poa_addr * addr,
                      const char *      ip,
                      uint16_t          port)
{
        memset(addr, 0, sizeof(*addr));

        addr->type      = POA_UDP4;
        addr->udp4.port = port;

        inet_pton(AF_INET, ip, &addr->udp4.ip_addr);
}

static int test_poa_addr_cmp(void)
{
        struct poa_addr a;
        struct poa_addr b;

        TEST_START();

        udp4_addr(&a, "10.0.0.10", 3435);
        udp4_addr(&b, "10.0.0.10", 3435);

        if (poa_addr_cmp(&a, &b) != 0) {
                printf("Identical addresses did not match.\n");
                goto fail;
        }

        udp4_addr(&b, "10.0.0.10", 3436);

        if (poa_addr_cmp(&a, &b) == 0) {
                printf("Addresses with a different port matched.\n");
                goto fail;
        }

        udp4_addr(&b, "10.0.0.11", 3435);

        if (poa_addr_cmp(&a, &b) == 0) {
                printf("Addresses with a different ip matched.\n");
                goto fail;
        }

        b.type = POA_UDP6;
        if (poa_addr_cmp(&a, &b) == 0) {
                printf("Addresses of a different type matched.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

static int test_poa_mgmt_msg_qos(void)
{
        struct poa_mgmt_msg msg;
        qosspec_t           qs;

        TEST_START();

        poa_mgmt_msg_ser(&msg, POA_FLOW_REQ, 1, 2, qos_stream, 0, 0);

        if (msg.code != POA_FLOW_REQ) {
                printf("Wrong code in management message.\n");
                goto fail;
        }

        if (ntoh32(msg.s_eid) != 1 || ntoh32(msg.d_eid) != 2) {
                printf("Wrong PoA ids in management message.\n");
                goto fail;
        }

        memset(&qs, 0, sizeof(qs));

        poa_mgmt_msg_qos(&msg, &qs);

        if (memcmp(&qs, &qos_stream, sizeof(qs)) != 0) {
                printf("QoS did not survive the management message.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

#ifdef HAVE_RAW_SOCKETS

static void eth_fake_priv(struct eth_priv * priv,
                          struct poa *      e)
{
        memset(priv, 0, sizeof(*priv));
        memset(e, 0, sizeof(*e));

        e->type = POA_ETH;

        strcpy(e->local.eth.src.dev, "test0");

        priv->poa       = e;
        priv->ethertype = htons(0xA000);
        priv->mtu       = 1500;

        memcpy(priv->hw_addr, eth_our_mac, POA_MAC_SIZE);
}

static int test_eth_frame(void)
{
        struct eth_priv  priv;
        struct poa       e;
        uint8_t          buf[64];
        struct eth_hdr * hdr = (struct eth_hdr *) buf;
        const char *     body = "hello";
        size_t           n;
        size_t           plen;
        uint32_t         eid;

        TEST_START();

        eth_fake_priv(&priv, &e);

        eth_hdr_ser(&priv, hdr, eth_our_mac, 7, strlen(body));

        memcpy(buf + ETH_HDR_TOT_SIZE, body, strlen(body));

        n = ETH_HDR_TOT_SIZE + strlen(body);
        if (frame_parse(&priv, buf, n, &eid, &plen) < 0) {
                printf("Failed to parse a valid frame.\n");
                goto fail;
        }

        if (eid != 7 || plen != strlen(body)) {
                printf("Expected eid 7 len %zu, got %u len %zu.\n",
                       strlen(body), eid, plen);
                goto fail;
        }

        hdr->poa.hcs ^= 0xFF;

        if (frame_parse(&priv, buf, n, &eid, &plen) == 0) {
                printf("Accepted a corrupt header checksum.\n");
                goto fail;
        }

        hdr->poa.hcs ^= 0xFF;
        hdr->ethertype ^= 0xFF;

        if (frame_parse(&priv, buf, n, &eid, &plen) == 0) {
                printf("Accepted a foreign Ethertype.\n");
                goto fail;
        }

        hdr->ethertype ^= 0xFF;

        if (frame_parse(&priv, buf, ETH_HDR_SIZE + 2, &eid, &plen) == 0) {
                printf("Accepted a truncated frame.\n");
                goto fail;
        }

        eth_hdr_ser(&priv, hdr, eth_far_mac, 7, strlen(body));

        if (frame_parse(&priv, buf, n, &eid, &plen) == 0) {
                printf("Accepted a frame for another host.\n");
                goto fail;
        }

        eth_hdr_ser(&priv, hdr, eth_bc_mac, 7, strlen(body));

        if (frame_parse(&priv, buf, n, &eid, &plen) < 0) {
                printf("Rejected a broadcast frame.\n");
                goto fail;
        }

        TEST_SUCCESS();

        return TEST_RC_SUCCESS;
 fail:
        TEST_FAIL();
        return TEST_RC_FAIL;
}

#endif /* HAVE_RAW_SOCKETS */

int poa_test(int     argc,
             char ** argv)
{
        int ret = 0;

        (void) argc;
        (void) argv;

        ret |= test_poa_addr_cmp();
        ret |= test_poa_mgmt_msg_qos();
#ifdef HAVE_RAW_SOCKETS
        ret |= test_eth_frame();
#endif

        return ret;
}
