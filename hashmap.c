#include <string.h>

#include "hashmap.h"


size_t
hash_map_sizeof(uint32_t entries,
                uint32_t data_size,
                uint32_t key_len)
{
    size_t size = cuckoo_sizeof(entries << 1, key_len);
    size += idx_queue_sizeof(entries);
    size += sizeof(struct hash_map_s) + data_size * entries;
    return size;
}

struct hash_map_s *
hash_map_init(void *m,
              uint32_t entries,
              uint32_t data_size,
              uint32_t key_len,
              uint32_t hash_init)
{
    struct hash_map_s *hmap;
    struct cuckoo_s *cuckoo;
    struct idx_queue_s *queue;
    uint8_t *p = m;

    cuckoo = cuckoo_map(p, entries, key_len, hash_init);
    p += cuckoo_sizeof(entries, key_len);
    queue = idx_queue_map(p, entries);
    p += idx_queue_sizeof(entries);

    hmap = (struct hash_map_s *) p;
    hmap->cuckoo = cuckoo;
    hmap->queue = queue;
    hmap->data_size = data_size;
    return hmap;
}

uint32_t
hash_map_alloc_idx(struct hash_map_s *hmap)
{
    uint32_t idx = HMAP_NO_ENTRY;

    idx_queue_alloc_idx(hmap->queue, &idx, 1);
    return idx;
}

void
hash_map_free_idx(struct hash_map_s *hmap,
                  uint32_t idx)
{
    idx_queue_free_idx(hmap->queue, &idx, 1);
}

int
hash_map_add(struct hash_map_s *hmap,
             const void *key,
             uint32_t idx)
{
    return cuckoo_add_val(hmap->cuckoo, key, idx);
}

int
hash_map_update(struct hash_map_s *hmap,
                const void *key,
                uint32_t new_idx)
{
    int ret = -1;
    struct cuckoo_egg_s *egg;

    egg = cuckoo_find_egg(hmap->cuckoo, key);
    if (egg) {
        uint32_t old_idx = egg->val;

        /* barrier */
        egg->val = new_idx;
        hash_map_free_idx(hmap, old_idx);
        ret = 0;
    }
    return ret;
}

uint32_t
hash_map_remove(struct hash_map_s *hmap,
                const void *key)
{
    uintptr_t val = (uintptr_t) cuckoo_remove(hmap->cuckoo, key);

    return val;
}

uint32_t
hash_map_find(struct hash_map_s *hmap,
              const void *key)
{
    return cuckoo_find_val(hmap->cuckoo, key);
}

void *
hash_map_get_data(struct hash_map_s *hmap,
                  uint32_t idx)
{
    return &hmap->data_array[idx * hmap->data_size];
}

uint32_t
hash_map_rcu_copy(struct hash_map_s *hmap,
                  uint32_t src_idx)
{
    uint32_t dst_idx = hash_map_alloc_idx(hmap);

    if (dst_idx != HMAP_NO_ENTRY) {
        void *dst = hash_map_get_data(hmap, dst_idx);
        void *src = hash_map_get_data(hmap, src_idx);

        memcpy(dst, src, hmap->data_size);
    }
    return dst_idx;
}

int
hash_map_rcu_sync(struct hash_map_s *hmap,
                  const void *key,
                  uint32_t new_idx)
{
    return hash_map_update(hmap, key, new_idx);
}


