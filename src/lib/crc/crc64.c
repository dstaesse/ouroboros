/*
 * Ouroboros - Copyright (C) 2016 - 2026
 *
 * 64-bit Cyclic Redundancy Check (NVMe variant)
 *
 *    Dimitri Staessens <dimitri@ouroboros.rocks>
 *    Sander Vrijders   <sander@ouroboros.rocks>
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

/*
 * CRC-64/NVMe (reveng catalog):
 *   poly   = 0xad93d23594c93659
 *   init   = 0xffffffffffffffff
 *   refin  = true
 *   refout = true
 *   xorout = 0xffffffffffffffff
 *   check  = crc64_nvme("123456789") == 0xae8b14860a799888
 */

#include "config.h"

#include <ouroboros/crc64.h>

/*
 * Reflected CRC-64/NVMe table. Polynomial in reflected form:
 * 0x9a6c9329ac4bc9b5 (bitrev of 0xad93d23594c93659).
 */
static const uint64_t crc64_nvme_tab[256] = {
        0x0000000000000000ULL, 0x7f6ef0c830358979ULL,
        0xfedde190606b12f2ULL, 0x81b31158505e9b8bULL,
        0xc962e5739841b68fULL, 0xb60c15bba8743ff6ULL,
        0x37bf04e3f82aa47dULL, 0x48d1f42bc81f2d04ULL,
        0xa61cecb46814fe75ULL, 0xd9721c7c5821770cULL,
        0x58c10d24087fec87ULL, 0x27affdec384a65feULL,
        0x6f7e09c7f05548faULL, 0x1010f90fc060c183ULL,
        0x91a3e857903e5a08ULL, 0xeecd189fa00bd371ULL,
        0x78e0ff3b88be6f81ULL, 0x078e0ff3b88be6f8ULL,
        0x863d1eabe8d57d73ULL, 0xf953ee63d8e0f40aULL,
        0xb1821a4810ffd90eULL, 0xceecea8020ca5077ULL,
        0x4f5ffbd87094cbfcULL, 0x30310b1040a14285ULL,
        0xdefc138fe0aa91f4ULL, 0xa192e347d09f188dULL,
        0x2021f21f80c18306ULL, 0x5f4f02d7b0f40a7fULL,
        0x179ef6fc78eb277bULL, 0x68f0063448deae02ULL,
        0xe943176c18803589ULL, 0x962de7a428b5bcf0ULL,
        0xf1c1fe77117cdf02ULL, 0x8eaf0ebf2149567bULL,
        0x0f1c1fe77117cdf0ULL, 0x7072ef2f41224489ULL,
        0x38a31b04893d698dULL, 0x47cdebccb908e0f4ULL,
        0xc67efa94e9567b7fULL, 0xb9100a5cd963f206ULL,
        0x57dd12c379682177ULL, 0x28b3e20b495da80eULL,
        0xa900f35319033385ULL, 0xd66e039b2936bafcULL,
        0x9ebff7b0e12997f8ULL, 0xe1d10778d11c1e81ULL,
        0x606216208142850aULL, 0x1f0ce6e8b1770c73ULL,
        0x8921014c99c2b083ULL, 0xf64ff184a9f739faULL,
        0x77fce0dcf9a9a271ULL, 0x08921014c99c2b08ULL,
        0x4043e43f0183060cULL, 0x3f2d14f731b68f75ULL,
        0xbe9e05af61e814feULL, 0xc1f0f56751dd9d87ULL,
        0x2f3dedf8f1d64ef6ULL, 0x50531d30c1e3c78fULL,
        0xd1e00c6891bd5c04ULL, 0xae8efca0a188d57dULL,
        0xe65f088b6997f879ULL, 0x9931f84359a27100ULL,
        0x1882e91b09fcea8bULL, 0x67ec19d339c963f2ULL,
        0xd75adabd7a6e2d6fULL, 0xa8342a754a5ba416ULL,
        0x29873b2d1a053f9dULL, 0x56e9cbe52a30b6e4ULL,
        0x1e383fcee22f9be0ULL, 0x6156cf06d21a1299ULL,
        0xe0e5de5e82448912ULL, 0x9f8b2e96b271006bULL,
        0x71463609127ad31aULL, 0x0e28c6c1224f5a63ULL,
        0x8f9bd7997211c1e8ULL, 0xf0f5275142244891ULL,
        0xb824d37a8a3b6595ULL, 0xc74a23b2ba0eececULL,
        0x46f932eaea507767ULL, 0x3997c222da65fe1eULL,
        0xafba2586f2d042eeULL, 0xd0d4d54ec2e5cb97ULL,
        0x5167c41692bb501cULL, 0x2e0934dea28ed965ULL,
        0x66d8c0f56a91f461ULL, 0x19b6303d5aa47d18ULL,
        0x980521650afae693ULL, 0xe76bd1ad3acf6feaULL,
        0x09a6c9329ac4bc9bULL, 0x76c839faaaf135e2ULL,
        0xf77b28a2faafae69ULL, 0x8815d86aca9a2710ULL,
        0xc0c42c4102850a14ULL, 0xbfaadc8932b0836dULL,
        0x3e19cdd162ee18e6ULL, 0x41773d1952db919fULL,
        0x269b24ca6b12f26dULL, 0x59f5d4025b277b14ULL,
        0xd846c55a0b79e09fULL, 0xa72835923b4c69e6ULL,
        0xeff9c1b9f35344e2ULL, 0x90973171c366cd9bULL,
        0x1124202993385610ULL, 0x6e4ad0e1a30ddf69ULL,
        0x8087c87e03060c18ULL, 0xffe938b633338561ULL,
        0x7e5a29ee636d1eeaULL, 0x0134d92653589793ULL,
        0x49e52d0d9b47ba97ULL, 0x368bddc5ab7233eeULL,
        0xb738cc9dfb2ca865ULL, 0xc8563c55cb19211cULL,
        0x5e7bdbf1e3ac9decULL, 0x21152b39d3991495ULL,
        0xa0a63a6183c78f1eULL, 0xdfc8caa9b3f20667ULL,
        0x97193e827bed2b63ULL, 0xe877ce4a4bd8a21aULL,
        0x69c4df121b863991ULL, 0x16aa2fda2bb3b0e8ULL,
        0xf86737458bb86399ULL, 0x8709c78dbb8deae0ULL,
        0x06bad6d5ebd3716bULL, 0x79d4261ddbe6f812ULL,
        0x3105d23613f9d516ULL, 0x4e6b22fe23cc5c6fULL,
        0xcfd833a67392c7e4ULL, 0xb0b6c36e43a74e9dULL,
        0x9a6c9329ac4bc9b5ULL, 0xe50263e19c7e40ccULL,
        0x64b172b9cc20db47ULL, 0x1bdf8271fc15523eULL,
        0x530e765a340a7f3aULL, 0x2c608692043ff643ULL,
        0xadd397ca54616dc8ULL, 0xd2bd67026454e4b1ULL,
        0x3c707f9dc45f37c0ULL, 0x431e8f55f46abeb9ULL,
        0xc2ad9e0da4342532ULL, 0xbdc36ec59401ac4bULL,
        0xf5129aee5c1e814fULL, 0x8a7c6a266c2b0836ULL,
        0x0bcf7b7e3c7593bdULL, 0x74a18bb60c401ac4ULL,
        0xe28c6c1224f5a634ULL, 0x9de29cda14c02f4dULL,
        0x1c518d82449eb4c6ULL, 0x633f7d4a74ab3dbfULL,
        0x2bee8961bcb410bbULL, 0x548079a98c8199c2ULL,
        0xd53368f1dcdf0249ULL, 0xaa5d9839ecea8b30ULL,
        0x449080a64ce15841ULL, 0x3bfe706e7cd4d138ULL,
        0xba4d61362c8a4ab3ULL, 0xc52391fe1cbfc3caULL,
        0x8df265d5d4a0eeceULL, 0xf29c951de49567b7ULL,
        0x732f8445b4cbfc3cULL, 0x0c41748d84fe7545ULL,
        0x6bad6d5ebd3716b7ULL, 0x14c39d968d029fceULL,
        0x95708ccedd5c0445ULL, 0xea1e7c06ed698d3cULL,
        0xa2cf882d2576a038ULL, 0xdda178e515432941ULL,
        0x5c1269bd451db2caULL, 0x237c997575283bb3ULL,
        0xcdb181ead523e8c2ULL, 0xb2df7122e51661bbULL,
        0x336c607ab548fa30ULL, 0x4c0290b2857d7349ULL,
        0x04d364994d625e4dULL, 0x7bbd94517d57d734ULL,
        0xfa0e85092d094cbfULL, 0x856075c11d3cc5c6ULL,
        0x134d926535897936ULL, 0x6c2362ad05bcf04fULL,
        0xed9073f555e26bc4ULL, 0x92fe833d65d7e2bdULL,
        0xda2f7716adc8cfb9ULL, 0xa54187de9dfd46c0ULL,
        0x24f29686cda3dd4bULL, 0x5b9c664efd965432ULL,
        0xb5517ed15d9d8743ULL, 0xca3f8e196da80e3aULL,
        0x4b8c9f413df695b1ULL, 0x34e26f890dc31cc8ULL,
        0x7c339ba2c5dc31ccULL, 0x035d6b6af5e9b8b5ULL,
        0x82ee7a32a5b7233eULL, 0xfd808afa9582aa47ULL,
        0x4d364994d625e4daULL, 0x3258b95ce6106da3ULL,
        0xb3eba804b64ef628ULL, 0xcc8558cc867b7f51ULL,
        0x8454ace74e645255ULL, 0xfb3a5c2f7e51db2cULL,
        0x7a894d772e0f40a7ULL, 0x05e7bdbf1e3ac9deULL,
        0xeb2aa520be311aafULL, 0x944455e88e0493d6ULL,
        0x15f744b0de5a085dULL, 0x6a99b478ee6f8124ULL,
        0x224840532670ac20ULL, 0x5d26b09b16452559ULL,
        0xdc95a1c3461bbed2ULL, 0xa3fb510b762e37abULL,
        0x35d6b6af5e9b8b5bULL, 0x4ab846676eae0222ULL,
        0xcb0b573f3ef099a9ULL, 0xb465a7f70ec510d0ULL,
        0xfcb453dcc6da3dd4ULL, 0x83daa314f6efb4adULL,
        0x0269b24ca6b12f26ULL, 0x7d0742849684a65fULL,
        0x93ca5a1b368f752eULL, 0xeca4aad306bafc57ULL,
        0x6d17bb8b56e467dcULL, 0x12794b4366d1eea5ULL,
        0x5aa8bf68aecec3a1ULL, 0x25c64fa09efb4ad8ULL,
        0xa4755ef8cea5d153ULL, 0xdb1bae30fe90582aULL,
        0xbcf7b7e3c7593bd8ULL, 0xc399472bf76cb2a1ULL,
        0x422a5673a732292aULL, 0x3d44a6bb9707a053ULL,
        0x759552905f188d57ULL, 0x0afba2586f2d042eULL,
        0x8b48b3003f739fa5ULL, 0xf42643c80f4616dcULL,
        0x1aeb5b57af4dc5adULL, 0x6585ab9f9f784cd4ULL,
        0xe436bac7cf26d75fULL, 0x9b584a0fff135e26ULL,
        0xd389be24370c7322ULL, 0xace74eec0739fa5bULL,
        0x2d545fb4576761d0ULL, 0x523aaf7c6752e8a9ULL,
        0xc41748d84fe75459ULL, 0xbb79b8107fd2dd20ULL,
        0x3acaa9482f8c46abULL, 0x45a459801fb9cfd2ULL,
        0x0d75adabd7a6e2d6ULL, 0x721b5d63e7936bafULL,
        0xf3a84c3bb7cdf024ULL, 0x8cc6bcf387f8795dULL,
        0x620ba46c27f3aa2cULL, 0x1d6554a417c62355ULL,
        0x9cd645fc4798b8deULL, 0xe3b8b53477ad31a7ULL,
        0xab69411fbfb21ca3ULL, 0xd407b1d78f8795daULL,
        0x55b4a08fdfd90e51ULL, 0x2ada5047efec8728ULL
};

static __inline__ uint64_t crc64_nvme_step(uint64_t        c,
                                           const uint8_t * p,
                                           size_t          len)
{
        size_t n;

        for (n = 0; n < len; n++)
                c = crc64_nvme_tab[(c ^ p[n]) & 0xff] ^ (c >> 8);

        return c;
}

void crc64_nvme_table(uint64_t *   crc,
                      const void * buf,
                      size_t       len)
{
        uint64_t c;

        c = crc64_nvme_step(*crc ^ UINT64_MAX,
                            (const uint8_t *) buf, len);

        *crc = c ^ UINT64_MAX;
}

#ifdef HAVE_PCLMUL

#include <smmintrin.h>
#include <wmmintrin.h>

/*
 * Fold-by-16 constants for reflected CRC-64/NVMe. Properties of the
 * polynomial; identical between the PCLMUL and PMULL backends.
 *   k3 = bitrev64(x^(128+64) mod P) << 1
 *   k4 = bitrev64(x^(128+0)  mod P) << 1
 */
static const uint64_t k3_clmul = 0xeadc41fd2ba3d420ULL;
static const uint64_t k4_clmul = 0x21e9761e252621acULL;

__attribute__((target("pclmul,sse4.1")))
static __m128i fold16(__m128i x,
                      __m128i k)
{
        __m128i lo;
        __m128i hi;

        lo = _mm_clmulepi64_si128(x, k, 0x00);
        hi = _mm_clmulepi64_si128(x, k, 0x11);
        return _mm_xor_si128(lo, hi);
}

/*
 * Fold-by-16 over 16-byte chunks; the 128-bit folded state is then
 * emitted as 16 little-endian bytes and run through the byte-table
 * loop together with any tail (<=15 bytes). The 16-byte minimum on
 * the bulk loop is why the short-input path uses the table directly.
 */
__attribute__((target("pclmul,sse4.1")))
static void crc64_nvme_clmul(uint64_t *   crc,
                             const void * buf,
                             size_t       len)
{
        const uint8_t * p;
        uint64_t        seed;
        uint64_t        c;
        size_t          off;
        __m128i         x;
        __m128i         k;
        uint8_t         post[16];

        p    = (const uint8_t *) buf;
        seed = *crc;

        if (len < 16) {
                c = crc64_nvme_step(seed ^ UINT64_MAX, p, len);
                *crc = c ^ UINT64_MAX;
                return;
        }

        x = _mm_loadu_si128((const __m128i *) p);
        x = _mm_xor_si128(x, _mm_cvtsi64_si128((int64_t)
                          (seed ^ UINT64_MAX)));

        k = _mm_set_epi64x((int64_t) k4_clmul, (int64_t) k3_clmul);

        off = 16;
        while (off + 16 <= len) {
                __m128i d;

                d = _mm_loadu_si128((const __m128i *) (p + off));
                x = _mm_xor_si128(fold16(x, k), d);
                off += 16;
        }

        _mm_storeu_si128((__m128i *) post, x);

        c = crc64_nvme_step(0, post, 16);
        c = crc64_nvme_step(c, p + off, len - off);

        *crc = c ^ UINT64_MAX;
}

#endif /* HAVE_PCLMUL */

#ifdef HAVE_PMULL

#include <arm_neon.h>

/* Same fold-by-16 constants as the PCLMUL path (poly properties). */
static const uint64_t k3_pmull = 0xeadc41fd2ba3d420ULL;
static const uint64_t k4_pmull = 0x21e9761e252621acULL;

__attribute__((target("+crypto")))
static uint64x2_t fold16_pmull(uint64x2_t x,
                               uint64x2_t k)
{
        poly64x2_t xp;
        poly64x2_t kp;
        uint64x2_t lo;
        uint64x2_t hi;

        xp = vreinterpretq_p64_u64(x);
        kp = vreinterpretq_p64_u64(k);
        lo = vreinterpretq_u64_p128(
                vmull_p64((poly64_t) vgetq_lane_u64(x, 0),
                          (poly64_t) vgetq_lane_u64(k, 0)));
        hi = vreinterpretq_u64_p128(vmull_high_p64(xp, kp));
        return veorq_u64(lo, hi);
}

__attribute__((target("+crypto")))
static void crc64_nvme_pmull(uint64_t *   crc,
                             const void * buf,
                             size_t       len)
{
        const uint8_t * p;
        uint64_t        seed;
        uint64_t        c;
        size_t          off;
        uint64x2_t      x;
        uint64x2_t      k;
        uint64_t        seed_lane[2];
        uint64_t        k_lanes[2];
        uint8_t         post[16];

        p    = (const uint8_t *) buf;
        seed = *crc;

        if (len < 16) {
                c = crc64_nvme_step(seed ^ UINT64_MAX, p, len);
                *crc = c ^ UINT64_MAX;
                return;
        }

        x = vld1q_u64((const uint64_t *) p);
        seed_lane[0] = seed ^ UINT64_MAX;
        seed_lane[1] = 0;
        x = veorq_u64(x, vld1q_u64(seed_lane));

        k_lanes[0] = k3_pmull;
        k_lanes[1] = k4_pmull;
        k = vld1q_u64(k_lanes);

        off = 16;
        while (off + 16 <= len) {
                uint64x2_t d;

                d = vld1q_u64((const uint64_t *) (p + off));
                x = veorq_u64(fold16_pmull(x, k), d);
                off += 16;
        }

        vst1q_u8(post, vreinterpretq_u8_u64(x));

        c = crc64_nvme_step(0, post, 16);
        c = crc64_nvme_step(c, p + off, len - off);

        *crc = c ^ UINT64_MAX;
}
#endif /* HAVE_PMULL */

void crc64_nvme(uint64_t *   crc,
                const void * buf,
                size_t       len)
{
#ifdef HAVE_PCLMUL
        crc64_nvme_clmul(crc, buf, len);
#elif defined(HAVE_PMULL)
        crc64_nvme_pmull(crc, buf, len);
#else
        crc64_nvme_table(crc, buf, len);
#endif
}
