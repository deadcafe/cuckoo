#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdbool.h>

#include "cuckoo_hash.h"
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

size_t
cuckoo_sizeof(uint32_t entries,
              uint32_t key_len)
{
    size_t size;
    entries = align32pow2(entries);

    /* nest size */
    size  = (sizeof(struct cuckoo_egg_s) + key_len);
    size *= entries;

    size += sizeof(struct cuckoo_s);
    return size;
}

int
cuckoo_walk(struct cuckoo_s *cuckoo,
            int (*cb)(struct cuckoo_s *,
                      struct cuckoo_egg_s *,
                      void *),
            void *arg)
{
    for (size_t i = 0; i < cuckoo->entries; i++) {
        struct cuckoo_egg_s *egg =
            (struct cuckoo_egg_s *) &cuckoo->nests[i * cuckoo->egg_size];

        int ret = cb(cuckoo, egg, arg);
        if (ret)
            return ret;
    }
    return 0;
}

static int
reset_egg(struct cuckoo_s *cuckoo __attribute__((unused)),
	  struct cuckoo_egg_s *egg,
	  void *arg __attribute__((unused)))
{
    cuckoo_set_invalid(egg);
    return 0;
}

void
cuckoo_reset(struct cuckoo_s *cuckoo)
{
    cuckoo_walk(cuckoo, reset_egg, NULL);
}


/*****************************************************************************
 * bcmp
 *****************************************************************************/
#ifdef __AVX2__
static inline int
cmp_32n(const void * restrict target,
        const void * restrict key,
        unsigned n)
{
    const __m256i *kp = key;
    const __m256i *tp = target;
    int ret = 0;

    for (unsigned i = 0; i < n && !ret; i++) {
        const __m256i t = _mm256_load_si256(&tp[i]);
        const __m256i k = _mm256_load_si256(&kp[i]);
        const __m256i x = _mm256_cmpeq_epi8(t, k);

        ret = (_mm256_movemask_epi8(x) != 0xffffU);
    }
    return ret;
}
#endif

static inline int
cmp_16n(const void * restrict target,
        const void * restrict key,
        unsigned n)
{
    const __m128i *kp = key;
    const __m128i *tp = target;
    int ret = 0;

    for (unsigned i = 0; i < n && !ret; i++) {
        const __m128i t = _mm_load_si128(&tp[i]);
        const __m128i k = _mm_load_si128(&kp[i]);
        const __m128i x = _mm_cmpeq_epi8(t, k);
        ret = (_mm_movemask_epi8(x) != 0xffffU);
    }
    return ret;
}

/*****************************************************************************
 * move
 *****************************************************************************/
#ifdef __AVX2__
static inline void
cuckoo_mov_32n(void * restrict dst,
               const void * restrict src,
               unsigned n)
{
    __m256i *d = dst;
    const __m256i *s = src;

    while (n--) {
        const __m256i k = _mm256_load_si256(s++);
        _mm256_store_si256(d++, k);
    }
}
#endif

static inline void
cuckoo_mov_16n(void * restrict dst,
               const void * restrict src,
               unsigned n)
{
    __m128i *d = dst;
    const __m128i *s = src;

    while (n--) {
        const __m128i k = _mm_load_si128(s++);
        _mm_store_si128(d++, k);
    }
}

/******************************************************************************
 *
 ******************************************************************************/
struct cuckoo_s *
cuckoo_map(void *m,
           bool use_aes,
           uint32_t entries,
           uint32_t key_len,
           uint32_t init)
{
    struct cuckoo_s *cuckoo = m;

    if (key_len % CUCKOO_BLOCKS_SIZE ||
        key_len > (CUCKOO_BLOCKS_SIZE * CUCKOO_BLOCKS_MAX) ||
        key_len < CUCKOO_BLOCKS_SIZE)
        return NULL;

    entries = align32pow2(entries);

    if (cuckoo) {
        cuckoo->mask = ((entries / CUCKOO_EGG_NUM) - 1);
        cuckoo->egg_size = sizeof(struct cuckoo_egg_s) + key_len;
        cuckoo->key_blocks = key_len / CUCKOO_BLOCKS_SIZE;
        cuckoo->init = init;
        cuckoo->nb_data = 0;
	cuckoo->entries = entries;

        if (use_aes)
            cuckoo->hash_func = cuckoo_hash_16n_aes;
        else
            cuckoo->hash_func = cuckoo_hash_16n_crc;

        cuckoo->cmp_func = cmp_16n;

#ifdef CUCKOO_DEBUG
        for (unsigned i = 0; i < CUCKOO_DEPTH_MAX; i++)
            cuckoo->depth[i] = 0;
        memset(&cuckoo->stats, 0, sizeof(cuckoo->stats));
#endif
        cuckoo_reset(cuckoo);
    }
    return cuckoo;
}

static inline void
cuckoo_write(const struct cuckoo_s * restrict cuckoo,
             struct cuckoo_egg_s * restrict egg,
             cuckoo_sig_t sig,
             const void * restrict key,
             void * restrict data)
{
    cuckoo_mov_16n(egg->key, key, cuckoo->key_blocks);
    egg->data = data;
    egg->sig = sig;

    /* mb */
    cuckoo_set_valid(egg);
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
        return egg->data;
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

/*
 * kickout egg
 */
static int
cuckoo_rotate(struct cuckoo_s * restrict cuckoo,
              const struct cuckoo_egg_s * restrict src,
              int depth)
{
    struct cuckoo_egg_s *dst;
    int ret = depth;
    uint16_t cur, next;

    CUCKOO_STATS_UPDATE(cuckoo, CUCKOO_STATS_ROTATE, 1);

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
            ret = cuckoo_rotate(cuckoo, dst, depth - 1);
            if (CUCKOO_UNLIKELY(ret >= 0)) {
                cuckoo_set_invalid(dst);
                cuckoo_set_pos(dst, next);
                goto end;
            }
        }
    }
    return -1;

 end:
    cuckoo_write(cuckoo, dst, src->sig, src->key, src->data);
    return ret;
}

int
cuckoo_add_sig(struct cuckoo_s * restrict cuckoo,
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
            if (CUCKOO_LIKELY(0 == cuckoo->cmp_func(key, egg->key,
                                                    cuckoo->key_blocks))) {
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
            depth = cuckoo_rotate(cuckoo, dst, depth - 1);
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
cuckoo_add(struct cuckoo_s * restrict cuckoo,
           const void * restrict key,
           void * restrict data)
{
    cuckoo_sig_t sig = cuckoo_init_sig(cuckoo, key);

    return cuckoo_add_sig(cuckoo, sig, key,data);
}


/*
 * index functions
 */
size_t
cuckoo_index_sizeof(uint32_t count)
{
    size_t size = align32pow2(count);

    size *= sizeof(uint32_t);
    size += sizeof(struct cuckoo_index_s);
    return size;
}


void
cuckoo_index_reset(struct cuckoo_index_s *queue)
{
    queue->head = 0;
    queue->tail = 0;

    for (uint32_t i = 0; i < queue->size; i++)
        queue->free_slot[i] = i;
    queue->num = queue->size;
}


struct cuckoo_index_s *
cuckoo_index_map(void *m,
                 size_t count)
{
    struct cuckoo_index_s *queue = m;
    uint32_t size = align32pow2(count);

    queue->size = size;
    queue->mask = size - 1;
    cuckoo_index_reset(queue);
    return queue;
}

