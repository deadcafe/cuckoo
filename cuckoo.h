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
#define CUCKOO_BLOCKS_SIZE	16
#define CUCKOO_BLOCKS_MAX	4	/* 16 x 4 : 64bytes */

#if 1
# define CUCKOO_LIKELY(x)	__builtin_expect((x), 1)
# define CUCKOO_UNLIKELY(x)	__builtin_expect((x), 0)
#else
# define CUCKOO_LIKELY(x)	(x)
# define CUCKOO_UNLIKELY(x)	(x)
#endif

struct cuckoo_egg_s {
    uint64_t sig;
    void *data;

    volatile uint32_t is_valid;	/* base cuckoo */
    uint32_t cur;	/* current sig point */

    char key[0]__attribute__((aligned(16)));
} __attribute__((aligned(16)));

enum CUCKOO_STATS_E {
    CUCKOO_STATS_ROTATE = 0,
    CUCKOO_STATS_CONFLICT,
    CUCKOO_STATS_RETRY,
    CUCKOO_STATS_EEXIST,
    CUCKOO_STATS_ENOSPC,

    CUCKOO_STATS_NUM,
};

struct cuckoo_s {
    uint32_t mask;
    uint32_t egg_size;
    uint32_t key_blocks;	/* 16 x n blocks */
    uint32_t init;
    uint32_t entries;
    uint32_t nb_data;

    uint64_t (*hash_func)(const void *, uint32_t, unsigned);
    int      (*cmp_func)(const void * restrict, const void * restrict, unsigned);
#ifdef CUCKOO_DEBUG
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

/*
 * cuckoo index
 */
struct cuckoo_index_s {
    uint32_t size;
    uint32_t mask;

    uint32_t head;
    uint32_t tail;
    uint32_t num;	/* nb free slot */
    uint32_t _pad;

    uint32_t free_slot[0];
};

/*****************************************************************************
 * APIs
 *****************************************************************************/
static inline struct cuckoo_egg_s *
cuckoo_get_egg(const struct cuckoo_s * restrict cuckoo,
               uint64_t sig,
               uint32_t pos)
{
    uint64_t v = sig >> (pos * 9);

    v &= cuckoo->mask;
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
                     uint64_t sig)
{
    cuckoo_prefetch0_raw(cuckoo_get_egg(cuckoo, sig, 0));
}

static inline void
cuckoo_prefetch1_sig(const struct cuckoo_s * restrict cuckoo,
                     uint64_t sig)
{
    cuckoo_prefetch1_raw(cuckoo_get_egg(cuckoo, sig, 0));
}

static inline void
cuckoo_prefetch2_sig(const struct cuckoo_s * restrict cuckoo,
                     uint64_t sig)
{
    cuckoo_prefetch2_raw(cuckoo_get_egg(cuckoo, sig, 0));
}

static inline uint64_t
cuckoo_init_sig(const struct cuckoo_s * restrict cuckoo,
                const void * restrict key)
{
    uint64_t sig = cuckoo->hash_func(key, cuckoo->init, cuckoo->key_blocks);

    cuckoo_prefetch1_raw(cuckoo_get_egg(cuckoo, sig, 0));
    cuckoo_prefetch1_raw(cuckoo_get_egg(cuckoo, sig, 1));
    cuckoo_prefetch2_raw(cuckoo_get_egg(cuckoo, sig, 2));
    cuckoo_prefetch2_raw(cuckoo_get_egg(cuckoo, sig, 3));
    return sig;
}

static inline struct cuckoo_egg_s *
cuckoo_find_egg_sig(const struct cuckoo_s * restrict cuckoo,
                    uint64_t sig,
                    const void * restrict key)
{
    cuckoo_prefetch0_raw(cuckoo_get_egg(cuckoo, sig, 1));

    for (uint32_t cur = 0; cur < CUCKOO_EGG_NUM; cur++) {
        struct cuckoo_egg_s *egg = cuckoo_get_egg(cuckoo, sig, cur);

        if (egg->is_valid) {
            if (CUCKOO_LIKELY(sig == egg->sig)) {
                if (CUCKOO_LIKELY(0 == cuckoo->cmp_func(key,
                                                        egg->key,
                                                        cuckoo->key_blocks))) {
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
    uint64_t sig = cuckoo_init_sig(cuckoo, key);
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
extern size_t cuckoo_sizeof(uint32_t entries, uint32_t key_len);
extern struct cuckoo_s *cuckoo_map(void *m, bool use_aes, uint32_t entries,
                                   uint32_t key_len, uint32_t init);
extern void cuckoo_reset(struct cuckoo_s *cuckoo);

extern void *cuckoo_remove_sig(struct cuckoo_s *cuckoo,
                               uint64_t sig, const void *key);
extern void *cuckoo_remove(struct cuckoo_s *cuckoo, const void *key);

extern int cuckoo_add_sig(struct cuckoo_s *cuckoo,
                          uint64_t sig,
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
/*
 * cuckoo index functions
 */
extern size_t cuckoo_index_sizeof(uint32_t count);
extern void cuckoo_index_reset(struct cuckoo_index_s *queue);
extern struct cuckoo_index_s *cuckoo_index_map(void *m, size_t count);

static inline int
cuckoo_free_index(struct cuckoo_index_s *queue,
                  const uint32_t *index,
                  unsigned n)
{
    if (n > (queue->size - queue->num))
        return -1;

    uint32_t tail = queue->tail;
    uint32_t mask = queue->mask;

    for (unsigned i = 0; i < n; i++) {
        queue->free_slot[tail] = index[i];
        tail++;
        tail &= mask;
    }
    queue->tail = tail;
    queue->num += n;
    return 0;
}

static inline int
cuckoo_alloc_index(struct cuckoo_index_s *queue,
                   uint32_t *index,
                   unsigned n)
{
    if (n > queue->num)
        return -1;

    uint32_t head = queue->head;
    uint32_t mask = queue->mask;

    for (unsigned i = 0; i < n; i++) {
        index[i] = queue->free_slot[head];
        head++;
        head &= mask;
    }
    queue->head = head;
    queue->num -= n;
    return 0;
}

#endif /* !_CUCKOO_H_ */
