#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>

#include "cuckoo.h"

/*****************************************************************************
 *
 *****************************************************************************/
static inline uint32_t
align32pow2(uint32_t x)
{
x--;
    x |= x >> 1;
    x |= x >> 2;
    x |= x >> 4;
    x |= x >> 8;
    x |= x >> 16;

    return x + 1;
}

#if 0
static inline void
dump_16(const char *msg,
        const void *ptr)
{
    const uint8_t *c = ptr;

    printf("%s : %p %02x%02x%02x%02x%02x%02x%02x%02x\n",
           msg, ptr,
           c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]);
}
#endif

static int
reset_egg(struct cuckoo_s *cuckoo __attribute__((unused)),
	  struct cuckoo_egg_s *egg,
	  void *arg __attribute__((unused)))
{
    cuckoo_set_invalid(egg);
    return 0;
}

/*****************************************************************************
 * move
 *****************************************************************************/
static inline void
mov16(void * restrict dst,
      const void * restrict src)
{
    __m128i xmm0 = _mm_loadu_si128(src);
    _mm_storeu_si128(dst, xmm0);
}

#ifdef __AVX2__
static inline void
mov32_avx2(void * restrict dst,
           const void * restrict src)
{
    __m256i ymm0 = _mm256_loadu_si256(src);
    _mm256_storeu_si256(dst, ymm0);
}
#endif

static inline void
mov32(void * restrict dst,
      const void * restrict src)
{
    mov16((uint8_t *) dst + 0 * 16, (const uint8_t *) src + 0 * 16);
    mov16((uint8_t *) dst + 1 * 16, (const uint8_t *) src + 1 * 16);
}

static inline void
mov_key(void * restrict dst,
        const void * restrict src,
        unsigned len)
{
    uintptr_t dstu = (uintptr_t) dst;
    uintptr_t srcu = (uintptr_t) src;

    if (len < 16) {
        if (len & 8) {
            *(uint64_t *) dstu = *(const uint64_t *) srcu;
            srcu = (uintptr_t) ((const uint64_t *) srcu + 1);
            dstu = (uintptr_t) ((uint64_t *) dstu + 1);
        }

        if (len & 4) {
            *(uint32_t *) dstu = *(const uint32_t *) srcu;
            srcu = (uintptr_t) ((const uint32_t *) srcu + 1);
            dstu = (uintptr_t) ((uint32_t *) dstu + 1);
        }

        if (len & 2) {
            *(uint16_t *) dstu = *(const uint16_t *) srcu;
            srcu = (uintptr_t) ((const uint16_t *) srcu + 1);
            dstu = (uintptr_t) ((uint16_t *) dstu + 1);
        }

        if (len & 1) {
            *(uint8_t *) dstu = *(const uint8_t *) srcu;
        }
    } else if (len == 16) {
        mov16(dst, src);
    } else if (len <= 32) {
        mov16(dst, src);
        mov16((uint8_t *) dst - 16 + len, (const uint8_t *) src - 16 + len);
    } else if (len <= 48) {
        mov32(dst, src);
        mov16((uint8_t *) dst - 16 + len, (const uint8_t *) src - 16 + len);
    } else if (len <= 64) {
        mov32(dst, src);
        mov16((uint8_t *) dst + 32, (const uint8_t *) src + 32);
        mov16((uint8_t *) dst - 16 + len, (const uint8_t *) src - 16 + len);
    } else {
        memcpy(dst, src, len);
    }
}

static inline void
cuckoo_write(const struct cuckoo_s * restrict cuckoo,
             struct cuckoo_egg_s * restrict egg,
             cuckoo_sig_t sig,
             const void * restrict key,
             void * restrict data)
{
    mov_key(egg->key, key, cuckoo->key_len);
    egg->ptr = data;
    egg->sig = sig;

    /* mb */
    cuckoo_set_valid(egg);
}

/*
 * kickout egg
 */
static int
cuckoo_swap(struct cuckoo_s * restrict cuckoo,
            const struct cuckoo_egg_s * restrict src,
            int depth)
{
    struct cuckoo_egg_s *dst;
    int ret = depth;
    uint16_t cur, next;

    CUCKOO_STATS_UPDATE(cuckoo, CUCKOO_STATS_SWAP, 1);

    cur = cuckoo_get_pos(src);
    for (next = (cur + 1) & CUCKOO_EGG_MASK;
         next != cur;
         next = (next + 1) & CUCKOO_EGG_MASK) {

        dst = cuckoo_get_egg(cuckoo, src->sig, next);

        if (CUCKOO_LIKELY(!cuckoo_is_valid(dst))) {
            cuckoo_set_pos(dst, next);
            goto end;
        }
    }

    if (CUCKOO_LIKELY(depth > 0)) {
        /* all used */

        cuckoo_prefetch0_raw(cuckoo_get_egg(cuckoo, src->sig,
                                            (cur + 1) & CUCKOO_EGG_MASK));
        cuckoo_prefetch1_raw(cuckoo_get_egg(cuckoo, src->sig,
                                            (cur + 2) & CUCKOO_EGG_MASK));
        cuckoo_prefetch2_raw(cuckoo_get_egg(cuckoo, src->sig,
                                            (cur + 3) & CUCKOO_EGG_MASK));

        for (next = (cur + 1) & CUCKOO_EGG_MASK;
             next != cur;
             next = (next + 1) & CUCKOO_EGG_MASK) {

            dst = cuckoo_get_egg(cuckoo, src->sig, next);
            ret = cuckoo_swap(cuckoo, dst, depth - 1);
            if (CUCKOO_UNLIKELY(ret >= 0)) {
                cuckoo_set_invalid(dst);
                cuckoo_set_pos(dst, next);
                goto end;
            }
        }
    }
    return -1;

 end:
    cuckoo_write(cuckoo, dst, src->sig, src->key, src->ptr);
    return ret;
}

/******************************************************************************
 *
 ******************************************************************************/
size_t
cuckoo_sizeof(uint32_t entries,
              uint32_t key_len)
{
    size_t size;

    entries = align32pow2(entries);

    /* nest size */
    if (key_len & 3) {
        key_len += 8;
        key_len &= ~(UINT32_C(-1) & 3);
    }
    size  = (sizeof(struct cuckoo_egg_s) + key_len);
    size *= entries;
    size += sizeof(struct cuckoo_s);

    fprintf(stderr, "key_ley: %u  entries: %u size:%zu\n",
            key_len, entries, size);
    return size;
}

struct cuckoo_s *
cuckoo_map(void *m,
           uint32_t entries,
           uint32_t key_len,
           uint32_t init)
{
    struct cuckoo_s *cuckoo = m;

    if (cuckoo) {
        cuckoo->key_len = key_len;
        if (key_len & 3) {
            key_len += 8;
            key_len &= ~(UINT32_C(-1) & 3);
        }

        cuckoo->egg_size = sizeof(struct cuckoo_egg_s) + key_len;
        cuckoo->sig_mask = ((entries >> CUCKOO_EGG_WIDTH) - 1);
        cuckoo->hash_init = init;
        cuckoo->nb_data = 0;
	cuckoo->max_entries = align32pow2(entries);

        printf("mask:%08x egg:%u len:%u init:%08x max:%u\n",
               cuckoo->sig_mask,
               cuckoo->egg_size,
               cuckoo->key_len,
               cuckoo->hash_init,
               cuckoo->max_entries);

#ifdef CUCKOO_DEBUG
        for (unsigned i = 0; i < CUCKOO_DEPTH_MAX; i++)
            cuckoo->depth[i] = 0;
        memset(&cuckoo->stats, 0, sizeof(cuckoo->stats));
#endif
        cuckoo_reset(cuckoo);
    }
    return cuckoo;
}

void *
cuckoo_remove_sig(struct cuckoo_s * restrict cuckoo,
                  cuckoo_sig_t sig,
                  const void * restrict key)
{
    struct cuckoo_egg_s *egg = cuckoo_find_egg_sig(cuckoo, sig, key);

    if (CUCKOO_LIKELY(egg != NULL)) {
        cuckoo_set_invalid(egg);
        cuckoo->nb_data -= 1;

        compiler_barrier();
        return egg->ptr;
    }
    return NULL;
}

void *
cuckoo_remove(struct cuckoo_s * restrict cuckoo,
              const void * restrict key)
{
    cuckoo_sig_t sig = cuckoo_init_sig(cuckoo, key);
    return cuckoo_remove_sig(cuckoo, sig, key);
}

int
cuckoo_add_ptr_sig(struct cuckoo_s * restrict cuckoo,
                   cuckoo_sig_t sig,
                   const void * restrict key,
                   void * restrict data)
{
    struct cuckoo_egg_s *dst = NULL;
    int depth = CUCKOO_DEPTH_MAX - 1;
    int retry = 0;

    cuckoo_prefetch0_raw(cuckoo_get_egg(cuckoo, sig, 2));
    cuckoo_prefetch0_raw(cuckoo_get_egg(cuckoo, sig, 3));

    for (uint16_t cur = 0; cur < CUCKOO_EGG_NUM; cur++) {
        struct cuckoo_egg_s *egg = cuckoo_get_egg(cuckoo, sig, cur);

        if (CUCKOO_LIKELY(!cuckoo_is_valid(egg))) {
            if (CUCKOO_UNLIKELY(dst == NULL)) {
                dst = egg;
                cuckoo_set_pos(dst, cur);
            }
        } else if (CUCKOO_UNLIKELY(sig == egg->sig)) {
            if (CUCKOO_LIKELY(0 == cuckoo_cmp(key,
                                              egg->key, cuckoo->key_len))) {
                CUCKOO_STATS_UPDATE(cuckoo, CUCKOO_STATS_EEXIST, 1);
                return -EEXIST;
            }
            else {
                CUCKOO_STATS_UPDATE(cuckoo, CUCKOO_STATS_CONFLICT, 1);
            }
        }
    }

    if (CUCKOO_UNLIKELY(dst == NULL)) {
    retry:
        for (uint16_t next = 0; next < CUCKOO_EGG_NUM; next++) {

            dst = cuckoo_get_egg(cuckoo, sig, next);
            depth = cuckoo_swap(cuckoo, dst, depth - 1);
            if (CUCKOO_LIKELY(depth >= 0)) {
                cuckoo_set_invalid(dst);
                cuckoo_set_pos(dst, next);
                goto end;
            }
        }
        if (CUCKOO_LIKELY(retry == 0)) {
            CUCKOO_STATS_UPDATE(cuckoo, CUCKOO_STATS_RETRY, 1);
            depth = CUCKOO_DEPTH_MAX + 2;
            retry = 1;
            goto retry;
        }

        CUCKOO_STATS_UPDATE(cuckoo, CUCKOO_STATS_ENOSPC, 1);
        return -ENOSPC;
    }

 end:
    cuckoo_write(cuckoo, dst, sig, key, data);
    cuckoo->nb_data += 1;

#ifdef CUCKOO_DEBUG
    cuckoo->depth[depth] += 1;
#endif
    return 0;
}

int
cuckoo_add_ptr(struct cuckoo_s * restrict cuckoo,
               const void * restrict key,
               void * restrict data)
{
    cuckoo_sig_t sig = cuckoo_init_sig(cuckoo, key);

    return cuckoo_add_ptr_sig(cuckoo, sig, key,data);
}

int
cuckoo_walk(struct cuckoo_s *cuckoo,
            int (*cb)(struct cuckoo_s *,
                      struct cuckoo_egg_s *,
                      void *),
            void *arg)
{
    for (size_t i = 0; i < cuckoo->max_entries; i++) {
        struct cuckoo_egg_s *egg =
            (struct cuckoo_egg_s *) &cuckoo->nests[i * cuckoo->egg_size];

        int ret = cb(cuckoo, egg, arg);
        if (ret)
            return ret;
    }
    return 0;
}

void
cuckoo_reset(struct cuckoo_s *cuckoo)
{
    cuckoo_walk(cuckoo, reset_egg, NULL);
}

