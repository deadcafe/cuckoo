#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "cuckoo.h"


/*
 * callback entries
 */
static inline uint32_t
hash_k16(const void *k,
         uint32_t init)
{
    const unsigned long long *p = k;
    init = _mm_crc32_u64(init, *p);
    return _mm_crc32_u64(init, *(p + 1));
}

static inline void
mov_k16(void *dst,
        const void *src)
{
    const __m128i k = _mm_loadu_si128((const __m128i *) src);
    _mm_storeu_si128((__m128i *) dst, k);
}

static inline int
cmp_k16(const void *key1,
        const void *key2)
{
    const __m128i k1 = _mm_loadu_si128((const __m128i *) key1);
    const __m128i k2 = _mm_loadu_si128((const __m128i *) key2);
    const __m128i x = _mm_cmpeq_epi32(k1, k2);
    return (_mm_movemask_epi8(x) != 0xffff);
}

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

    /* node size */
    size  = (sizeof(struct cuckoo_node_s) + key_len);
    size *= entries;

    size += sizeof(struct cuckoo_s);
    return size;
}

struct cuckoo_s *
cuckoo_map(void *m,
           uint32_t entries,
           uint32_t key_len,
           uint32_t init)
{
    struct cuckoo_s *hash = m;

    if (key_len != 16)
        return NULL;

    entries = align32pow2(entries) / CUCKOO_EGG_NUM;

    if (hash) {
        hash->mask = (entries - 1);
        hash->node_size = sizeof(struct cuckoo_node_s) + key_len;
        hash->key_len = key_len;
        hash->init = init;
        hash->cmp_key = cmp_k16;
        hash->get_hash = hash_k16;
        hash->copy_key = mov_k16;
        hash->nb_data = 0;

        size_t array_size = (size_t) hash->node_size * entries;
        char *p = (char *) (hash + 1);
        for (unsigned i = 0; i < CUCKOO_EGG_NUM; i++) {
            hash->array[i] = p + (array_size * i);
            memset(hash->array[i], 0, array_size);
        }
#if 0
        fprintf(stderr, "mask:%08x node_size:%u\n",
                (unsigned)hash->mask, (unsigned)hash->node_size);
#endif
    }
    return hash;
}

static inline void
compiler_barrier(void)
{
    asm volatile ("" : : : "memory");
}

static inline void
cuckoo_write(const struct cuckoo_s *hash,
             struct cuckoo_node_s *node,
             const struct cuckoo_sig_s *sig,
             const void *key,
             void *data)
{
    hash->copy_key(node->key, key);
    mov_k16(node->sig.egg, sig->egg);
    node->data = data;

    /* mb */
    compiler_barrier();
    node->sig.val = sig->val;

#if 0
    fprintf(stderr, "Sig:%u Egg %u: 0:%u 1:%u 2:%u 3:%u\n",
            sig->val, sig->eid, sig->egg[0], sig->egg[1], sig->egg[2], sig->egg[3]);
#endif
}

void *
cuckoo_remove(struct cuckoo_s *hash,
              const void *key)
{
    struct cuckoo_node_s *node = cuckoo_find_node(hash, key);

    if (CUCKOO_LIKELY(node != NULL)) {
        node->sig.val = CUCKOO_UNUSED_SIG;
        hash->nb_data -= 1;
        compiler_barrier();
        return node->data;
    }
    return NULL;
}

/*
 * kickout egg
 */
static int
cuckoo_rotate(struct cuckoo_s *hash,
              struct cuckoo_node_s *src,
              int depth)
{
    struct cuckoo_node_s *dst;
    int ret = depth;

    for (uint32_t eid = (src->sig.eid + 1) & CUCKOO_EGG_MASK;
         eid != src->sig.eid;
         eid = (eid + 1) & CUCKOO_EGG_MASK) {

        dst = cuckoo_get_node(hash, &src->sig, eid);
        if (CUCKOO_LIKELY(dst->sig.val == CUCKOO_UNUSED_SIG)) {
            dst->sig.eid = eid;
            goto end;
        }
        cuckoo_prefetch(hash, &dst->sig);
    }

    if (depth < CUCKOO_DEPTH_MAX - 1) {
        /* all used */
        for (uint32_t eid = (src->sig.eid + 1) & CUCKOO_EGG_MASK;
             eid != src->sig.eid;
             eid = (eid + 1) & CUCKOO_EGG_MASK) {

            dst = cuckoo_get_node(hash, &src->sig, eid);
            ret = cuckoo_rotate(hash, dst, depth + 1);
            if (CUCKOO_UNLIKELY(ret > 0)) {
                dst->sig.eid = eid;
                goto end;
            }
        }
    }
    return -1;

 end:
    cuckoo_write(hash, dst, &src->sig, src->key, src->data);
    src->sig.val = CUCKOO_UNUSED_SIG;
    return ret;
}

int
cuckoo_add(struct cuckoo_s *hash,
           const void *key,
           void *data)
{
    struct cuckoo_sig_s sig;
    struct cuckoo_node_s *dst = NULL;
    struct cuckoo_node_s *empty = NULL;
    int depth = 0;
    uint32_t val = cuckoo_init_egg(hash, key, &sig);

    for (uint32_t eid = 0; eid < CUCKOO_EGG_NUM; eid++) {
        struct cuckoo_node_s *node = cuckoo_get_node(hash, &sig, eid);

        if (CUCKOO_UNLIKELY(node->sig.val == val)) {
            if (CUCKOO_UNLIKELY(!hash->cmp_key(key, node->key))) {
#if 0
                const uint32_t *d = (const uint32_t *) node->key;

                fprintf(stderr, "already exist. sig:%x %x:%x:%x:%x \n",
                        node->sig.val,
                        d[0], d[1], d[2], d[3]);

                d = (const uint32_t *) key;
                fprintf(stderr, "new sig:%x %x:%x:%x:%x \n",
                        sig.val,
                        d[0], d[1], d[2], d[3]);
#endif
                return -1;
            }
        } else if (node->sig.val == CUCKOO_UNUSED_SIG && empty == NULL) {
            empty = node;
            empty->sig.eid = eid;
        }
    }

    if (empty == NULL) {
        for (uint32_t eid = 0; eid < CUCKOO_EGG_NUM; eid++) {
            dst = cuckoo_get_node(hash, &sig, eid);
            cuckoo_prefetch(hash, &dst->sig);

            depth = cuckoo_rotate(hash, dst, 1);
            if (CUCKOO_UNLIKELY(depth > 0)) {
                dst->sig.eid = eid;
                goto end;
            }
        }
        return -1;
    } else {
        dst = empty;
    }

 end:
    cuckoo_write(hash, dst, &sig, key, data);
    hash->nb_data += 1;

#ifdef CUCKOO_DEBUG
    hash->stats[depth] += 1;
#endif
    return 0;
}

