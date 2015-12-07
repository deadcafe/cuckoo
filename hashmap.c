#include "hashmap.h"


size_t
hash_map_sizeof(uint32_t entries,
                uint32_t key_len)
{
    size_t size = cuckoo_sizeof(entries << 1, key_len);
    size += idx_queue_sizeof(entries);
    return size;
}

void
hash_map_init(struct hash_map_s *hmap,
              void *m,
              uint32_t entries,
              uint32_t key_len,
              uint32_t hash_init)
{
    uint8_t *p = m;

    hmap->cuckoo = cuckoo_map(p, entries, key_len, hash_init);
    p += cuckoo_sizeof(entries, key_len);
    hmap->queue = idx_queue_map(p, entries);
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

