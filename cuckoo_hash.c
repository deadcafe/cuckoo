#include <x86intrin.h>
#include <stdio.h>

#include "cuckoo_hash.h"



static inline cuckoo_sig_t
final_update(uint64_t hi)
{
#if 0
    return hi;
#else
    uint64_t lo = hi >> 32;

    return (cuckoo_sig_t) ((lo ^ hi) & 0xffffffff);
#endif
}

/*****************************************************************************
 * CRC
 *****************************************************************************/
#if 1
cuckoo_sig_t
cuckoo_hash_16n_crc(const void *k,
                    uint32_t init,
                    unsigned n)
{
    uint64_t c1 = init;
    const uint64_t *p = k;

    n <<= 1;
    while (n--) {
        uint64_t d = *p;

        c1 = _mm_crc32_u64(c1, d);
        p++;
    }
    return c1;
}
#else
cuckoo_sig_t
cuckoo_hash_16n_crc(const void *k,
                    uint32_t init,
                    unsigned n)
{
    uint64_t c1 = init;
    uint64_t c2 = ~init;
    const uint64_t *p = k;

    n <<= 1;
    while (n--) {
        __m128i x;
        uint64_t d = *p;

        c1 ^= _mm_crc32_u64(c2, d);
        c2 ^= _mm_crc32_u64(c1, ~d);

        __m128i y = _mm_set_epi64((__m64) c1, (__m64) c2);
        __m128i z = _mm_set_epi64((__m64) c2, (__m64) c1);

        x = _mm_unpacklo_epi8(z, y);
        y = _mm_unpacklo_epi8(y, z);

        x = _mm_mullo_epi32(x, y);

        c1 = _mm_extract_epi64(x, 1);
        c2 = _mm_extract_epi64(x, 0);
        p++;
    }

     return final_update(c2);
}
#endif

/*****************************************************************************
 * AES
 *****************************************************************************/
cuckoo_sig_t
cuckoo_hash_16n_aes(const void *t,
                    uint32_t init,
                    unsigned n)
{
    const __m128i *p = t;
    __m128i key = _mm_set_epi32(init, ~init, ~init, init);

    key = _mm_aeskeygenassist_si128(key, 0xaa);
    key = _mm_aesimc_si128(key);
    key = _mm_aeskeygenassist_si128(key, 0xc1);

    while (n--) {
        __m128i txt;

	txt = _mm_loadu_si128(p++);

        unsigned rounds = 2;
        while (rounds--) {
            txt = _mm_aesimc_si128(txt);
            key = _mm_aesenc_si128(txt, key);

            txt = _mm_aesimc_si128(txt);
            key = _mm_aesdec_si128(txt, key);

            key = _mm_aesimc_si128(key);
            key = _mm_aesenc_si128(txt, key);
        }
    }

    key = _mm_aesimc_si128(key);
    key = _mm_aesenclast_si128(key, key);

    uint64_t a = _mm_extract_epi64(key, 0);
    uint64_t b = _mm_extract_epi64(key, 1);

#if 0
    fprintf(stderr, "%016llx %016llx %016llx\n", a, b, a+b);
#endif
    return final_update(a ^ b);
}
