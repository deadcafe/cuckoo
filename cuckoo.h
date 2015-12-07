#ifndef _CUCKOO_H_
#define _CUCKOO_H_

#include <stdint.h>
#include <x86intrin.h>

#define CUCKOO_DEBUG
//#define CUCKOO_PREFETCH_DISABLE

#define CUCKOO_EGG_WIDTH	2
#define CUCKOO_EGG_NUM		(1U << 	CUCKOO_EGG_WIDTH)  /* MUST be pow2 */
#define CUCKOO_EGG_MASK		(CUCKOO_EGG_NUM - 1)
#define CUCKOO_DEPTH_MAX	4
#define CUCKOO_BLOCKS_SIZE	8
#define CUCKOO_BLOCKS_MAX	8	/* 16 x 4 : 64bytes */
#define CUCKOO_VALID_MARK	0x8000
#define CUCKOO_SIG_BITS		32

#if 1
# define CUCKOO_LIKELY(x)	__builtin_expect((x), 1)
# define CUCKOO_UNLIKELY(x)	__builtin_expect((x), 0)
#else
# define CUCKOO_LIKELY(x)	(x)
# define CUCKOO_UNLIKELY(x)	(x)
#endif


static inline void
compiler_barrier(void)
{
    asm volatile ("" : : : "memory");
}

typedef uint32_t cuckoo_sig_t;

struct cuckoo_egg_s {
    uint16_t cur;	/* current sig point */
    uint16_t _pad;
    cuckoo_sig_t sig;
    union {
        void *data;
        uintptr_t uint_data;
    };

    char key[0]__attribute__((aligned(16)));
} __attribute__((aligned(16)));

static inline bool
cuckoo_is_valid(const struct cuckoo_egg_s *egg)
{
    return (egg->cur & CUCKOO_VALID_MARK);
}

static inline void
cuckoo_set_valid(struct cuckoo_egg_s *egg)
{
    compiler_barrier();
    egg->cur |= CUCKOO_VALID_MARK;
}

static inline void
cuckoo_set_invalid(struct cuckoo_egg_s *egg)
{
    egg->cur &= ~CUCKOO_VALID_MARK;
    compiler_barrier();
}

static inline void
cuckoo_set_pos(struct cuckoo_egg_s *egg,
               uint16_t pos)
{
    egg->cur = pos;
}

static inline uint16_t
cuckoo_get_pos(const struct cuckoo_egg_s *egg)
{
    return (egg->cur & CUCKOO_EGG_MASK);
}

static inline uint32_t
cuckoo_sig_rotate(cuckoo_sig_t sig, unsigned r)
{
    cuckoo_sig_t s;
    r &= (CUCKOO_SIG_BITS - 1);
    s = (sig >> r) | (sig << (CUCKOO_SIG_BITS -r));
    return (uint32_t) (s & 0xffffffff);
}

enum CUCKOO_STATS_E {
    CUCKOO_STATS_SWAP = 0,
    CUCKOO_STATS_CONFLICT,
    CUCKOO_STATS_RETRY,
    CUCKOO_STATS_EEXIST,
    CUCKOO_STATS_ENOSPC,

    CUCKOO_STATS_NUM,
};

struct cuckoo_s {
    uint32_t sig_mask;
    uint32_t hash_init;

    uint16_t egg_size;
    uint16_t key_len;	/* 8 x n bytes */

    uint32_t max_entries;
    uint32_t nb_data;


#ifdef CUCKOO_DEBUG
    char _xxx[0] __attribute__((aligned(64)));
    size_t stats[CUCKOO_STATS_NUM];
    size_t depth[CUCKOO_DEPTH_MAX];
#endif

    /*
     * egg array continue.
     */
    char nests[0] __attribute__((aligned(64)));
}__attribute__((aligned(64)));

#ifdef CUCKOO_DEBUG
# define CUCKOO_STATS_UPDATE(_c,_i,_n)           \
    do {                                         \
        (_c)->stats[(_i)] += (_n);               \
    } while (0)
#else
# define CUCKOO_STATS_UPDATE(_c,_i,_n)
#endif /* !CUCKOO_DEBUG */



static inline uint32_t
cuckoo_hash(const void *k,
            uint32_t init,
            unsigned len)
{
    uint32_t c = init;
    const uint64_t *p = k;
    uint64_t v = *p;

    while (len > 8) {
        p++;
        uint64_t v1 = *p;
        c = _mm_crc32_u64(c, v);
        v = v1;
        len -= 8;
    };

    len = 8 - len;
    len <<= 3;
    v &= (UINT64_C(-1) >> len);
    c = _mm_crc32_u64(c, v);

#if 1
    uint32_t tag = c >> 12;
    return (c ^ (tag * 0x5bd1e995));
#else
    return c;
#endif
}

static inline int
cuckoo_cmp(const void * restrict s1,
           const void * restrict s2,
            unsigned len)
{
    const uint8_t *xp = s1;
    const uint8_t *yp = s2;
    __m128i x = _mm_loadu_si128((const __m128i *) xp);
    __m128i y = _mm_loadu_si128((const __m128i *) yp);
    __m128i cmp;
    const int mask = 0xffff;
    int ret;

    while (len > 16) {
        cmp = _mm_cmpeq_epi8(x, y);
        xp += 16;
        yp += 16;
        __m128i x1 = _mm_loadu_si128((const __m128i *) xp);
        __m128i y1 = _mm_loadu_si128((const __m128i *) yp);

        ret = _mm_movemask_epi8(cmp) ^ mask;
        if (ret)
            return ret;

        x = x1;
        y = y1;
        len -= 16;
    }

    cmp = _mm_cmpeq_epi8(x, y);
    ret = _mm_movemask_epi8(cmp) ^ mask;
    ret &= ((1U << len) - 1);

    return ret;
}

/*****************************************************************************
 * APIs
 *****************************************************************************/
static inline struct cuckoo_egg_s *
cuckoo_get_egg(const struct cuckoo_s * restrict cuckoo,
               cuckoo_sig_t sig,
               uint16_t pos)
{
    uint32_t v = cuckoo_sig_rotate(sig, (pos * 9));

    v &= cuckoo->sig_mask;
    v <<= CUCKOO_EGG_WIDTH;
    v += pos;
    v *= cuckoo->egg_size;

    //    fprintf(stderr, "pos:%u sig:%llx v:%llx\n", pos, sig, v);
    return (struct cuckoo_egg_s *) &cuckoo->nests[v];
}

static inline void
cuckoo_prefetch0_raw(const volatile void *p)
{
#ifndef CUCKOO_PREFETCH_DISABLE
    asm volatile ("prefetcht0 %[p]" : : [p] "m" (*(const volatile char *) p));
#else
    (void) p;
#endif
}

static inline void
cuckoo_prefetch1_raw(const volatile void *p)
{
#ifndef CUCKOO_PREFETCH_DISABLE
    asm volatile ("prefetcht1 %[p]" : : [p] "m" (*(const volatile char *) p));
#else
    (void) p;
#endif
}

static inline void
cuckoo_prefetch2_raw(const volatile void *p)
{
#ifndef CUCKOO_PREFETCH_DISABLE
    asm volatile ("prefetcht2 %[p]" : : [p] "m" (*(const volatile char *) p));
#else
    (void) p;
#endif
}

static inline void
cuckoo_prefetch0_sig(const struct cuckoo_s * restrict cuckoo,
                     cuckoo_sig_t sig)
{
    cuckoo_prefetch0_raw(cuckoo_get_egg(cuckoo, sig, 0));
}

static inline void
cuckoo_prefetch1_sig(const struct cuckoo_s * restrict cuckoo,
                     cuckoo_sig_t sig)
{
    cuckoo_prefetch1_raw(cuckoo_get_egg(cuckoo, sig, 0));
}

static inline void
cuckoo_prefetch2_sig(const struct cuckoo_s * restrict cuckoo,
                     cuckoo_sig_t sig)
{
    cuckoo_prefetch2_raw(cuckoo_get_egg(cuckoo, sig, 0));
}

static inline cuckoo_sig_t
cuckoo_init_sig(const struct cuckoo_s * restrict cuckoo,
                const void * restrict key)
{
    cuckoo_sig_t sig = cuckoo_hash(key, cuckoo->hash_init, cuckoo->key_len);

    cuckoo_prefetch1_raw(cuckoo_get_egg(cuckoo, sig, 0));
    cuckoo_prefetch1_raw(cuckoo_get_egg(cuckoo, sig, 1));
    cuckoo_prefetch2_raw(cuckoo_get_egg(cuckoo, sig, 2));
    cuckoo_prefetch2_raw(cuckoo_get_egg(cuckoo, sig, 3));
    return sig;
}

static inline struct cuckoo_egg_s *
cuckoo_find_egg_sig(const struct cuckoo_s * restrict cuckoo,
                    cuckoo_sig_t sig,
                    const void * restrict key)
{
    cuckoo_prefetch0_raw(cuckoo_get_egg(cuckoo, sig, 1));

    for (uint32_t cur = 0; cur < CUCKOO_EGG_NUM; cur++) {
        struct cuckoo_egg_s *egg = cuckoo_get_egg(cuckoo, sig, cur);

        if (cuckoo_is_valid(egg)) {
            if (sig == egg->sig) {
                if (CUCKOO_LIKELY(0 == cuckoo_cmp(key,
                                                  egg->key,
                                                  cuckoo->key_len))) {
                    return egg;
                }
            }
	}
    }
    return NULL;
}

static inline struct cuckoo_egg_s *
cuckoo_find_egg(const struct cuckoo_s * restrict cuckoo,
                const void * restrict key)
{
    cuckoo_sig_t sig = cuckoo_init_sig(cuckoo, key);
    return cuckoo_find_egg_sig(cuckoo, sig, key);
}

static inline void *
cuckoo_find_data(struct cuckoo_s * restrict cuckoo,
                 const void * restrict key)
{
    struct cuckoo_egg_s *egg = cuckoo_find_egg(cuckoo, key);

    if (CUCKOO_LIKELY(egg != NULL))
        return egg->data;
    return NULL;
}

/*
 * prottypes
 */
extern cuckoo_sig_t cuckoo_hash_16n_crc(const void *k,
                                        uint32_t init,
                                        unsigned n);

extern size_t cuckoo_sizeof(uint32_t entries, uint32_t key_len);
extern struct cuckoo_s *cuckoo_map(void *m, uint32_t entries,
                                   uint32_t key_len, uint32_t init);
extern void cuckoo_reset(struct cuckoo_s *cuckoo);

extern void *cuckoo_remove_sig(struct cuckoo_s *cuckoo,
                               cuckoo_sig_t sig, const void *key);
extern void *cuckoo_remove(struct cuckoo_s *cuckoo, const void *key);

extern int cuckoo_add_sig(struct cuckoo_s *cuckoo,
                          cuckoo_sig_t sig,
                          const void *key, void *data);
extern int cuckoo_add(struct cuckoo_s *cuckoo, const void *key, void *data);


extern int cuckoo_find_data_bulk(struct cuckoo_s *cuckoo,
                                 const void **keys,
                                 unsigned num,
                                 void *data[]);
extern int cuckoo_walk(struct cuckoo_s *cuckoo,
		       int (*cb)(struct cuckoo_s *,
				 struct cuckoo_egg_s *,
				 void *),
		       void *arg);

#endif /* !_CUCKOO_H_ */
