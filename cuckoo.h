#ifndef _CUCKOO_H_
#define _CUCKOO_H_

#include <stdint.h>
#include <x86intrin.h>

#define CUCKOO_DEBUG


typedef int (*cuckoo_cmp_t)(const void *k1, const void *k2);
typedef uint32_t (*cuckoo_func_t)(const void *key, uint32_t init_val);
typedef void (*cuckoo_copy_t)(void *dst, const void *src);


#define CUCKOO_UNUSED_SIG	0
#define CUCKOO_EGG_NUM		4	/* MUST be pow2 */
#define CUCKOO_EGG_MASK		(CUCKOO_EGG_NUM - 1)
#define CUCKOO_DEPTH_MAX	4

#if 1
# define CUCKOO_LIKELY(x)	__builtin_expect((x), 1)
# define CUCKOO_UNLIKELY(x)	__builtin_expect((x), 0)
#else
# define CUCKOO_LIKELY(x)	(x)
# define CUCKOO_UNLIKELY(x)	(x)
#endif

struct cuckoo_sig_s {
    volatile uint32_t val;	/* base hash */
    uint32_t eid;
    uint32_t egg[CUCKOO_EGG_NUM];
};

struct cuckoo_node_s {
    void *data;
    struct cuckoo_sig_s sig;
    char key[0];
} __attribute__((aligned(16)));

struct cuckoo_key_s {
    uint32_t val[4];
};

struct cuckoo_s {
    uint32_t mask;
    uint32_t node_size;
    uint32_t key_len;
    uint32_t init;

    cuckoo_cmp_t cmp_key;
    cuckoo_func_t get_hash;
    cuckoo_copy_t copy_key;
    size_t nb_data;

#ifdef CUCKOO_DEBUG
    size_t stats[CUCKOO_DEPTH_MAX];
#endif

    void *array[CUCKOO_EGG_NUM];
} __attribute__((aligned(64)));


/*********************************************************************************
 *
 *********************************************************************************/

static inline uint32_t
cuckoo_calc_hash(const struct cuckoo_s *hash,
                 const void *key)
{
    uint32_t sig = hash->get_hash(key, hash->init);
    if (CUCKOO_UNLIKELY(sig == 0))
        sig = 1;
    return sig;
}

static inline struct cuckoo_node_s *
cuckoo_get_node(const struct cuckoo_s *hash,
                const struct cuckoo_sig_s *sig,
                uint32_t eid)
{
    char *array = hash->array[eid];

    return (struct cuckoo_node_s *) &array[sig->egg[eid]];
}

static inline void
cuckoo_prefetch_raw(const volatile void *p)
{
#if 0
    asm volatile ("prefetcht0 %[p]" : : [p] "m" (*(const volatile char *) p));
#else
    (void) p;
#endif
}

static inline void
cuckoo_prefetch(const struct cuckoo_s *hash,
                const struct cuckoo_sig_s *sig)
{
#if 0
    for (uint32_t eid = (sig->eid + 1) & CUCKOO_EGG_MASK;
         eid != sig->eid;
         eid = (eid + 1) & CUCKOO_EGG_MASK) {
        cuckoo_prefetch_raw(cuckoo_get_node(hash, sig, eid));
    }
#else
    (void) hash;
    (void) sig;
#endif
}

static inline uint32_t
cuckoo_init_egg(const struct cuckoo_s *hash,
                const void *key,
                struct cuckoo_sig_s *sig)
{
    const struct cuckoo_key_s *keys = key;

    sig->val = cuckoo_calc_hash(hash, key);

    for (uint32_t eid = 0; eid < CUCKOO_EGG_NUM; eid++) {
        uint64_t b64;

        b64 = keys->val[eid];
        b64 <<= 32;
        b64 |= eid;

        unsigned egg = _mm_crc32_u64(sig->val, b64);
        sig->egg[eid] = (egg & hash->mask) * hash->node_size;
        cuckoo_prefetch_raw(cuckoo_get_node(hash, sig, eid));
    }
    return sig->val;
}

static inline struct cuckoo_node_s *
cuckoo_find_node_sig(const struct cuckoo_s *hash,
                     const struct cuckoo_sig_s *sig,
                     const void *key)
{
    for (uint32_t eid = 0; eid < CUCKOO_EGG_NUM; eid++) {
        struct cuckoo_node_s *node = cuckoo_get_node(hash, sig, eid);

        if (node->sig.val == sig->val) {
            if (CUCKOO_LIKELY(!hash->cmp_key(key, node->key)))
                return node;
        }
    }
    return NULL;
}

static inline struct cuckoo_node_s *
cuckoo_find_node(const struct cuckoo_s *hash,
                 const void *key)
{
    struct cuckoo_sig_s sig;

    cuckoo_init_egg(hash, key, &sig);
    return cuckoo_find_node_sig(hash, &sig, key);
}

static inline void *
cuckoo_find_data(struct cuckoo_s *hash,
                 const void *key)
{
    struct cuckoo_node_s *node = cuckoo_find_node(hash, key);

    if (CUCKOO_LIKELY(node != NULL))
        return node->data;
    return NULL;
}

extern size_t cuckoo_sizeof(uint32_t entries,
                            uint32_t key_len);
extern struct cuckoo_s *cuckoo_map(void *m,
                                   uint32_t entries,
                                   uint32_t key_len,
                                   uint32_t init);

extern void *cuckoo_remove(struct cuckoo_s *hash,
                           const void *key);
extern int cuckoo_add(struct cuckoo_s *hash,
                      const void *key,
                      void *data);


#endif /* !_CUCKOO_H_ */
