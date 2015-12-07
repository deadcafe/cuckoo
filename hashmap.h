#ifndef _HASHMAP_H_
#define _HASHMAP_H_

#include "cuckoo.h"
#include "idx_queue.h"

#define HMAP_NO_ENTRY	CUCKOO_NO_ENTRY

struct hash_map_s {
    struct cuckoo_s *cuckoo;
    struct idx_queue_s *queue;

    unsigned data_size;
    char data_array[0] __attribute__((aligned(64)));
} __attribute__((aligned(64)));

extern size_t hash_map_sizeof(uint32_t entries,
                              uint32_t data_size, uint32_t key_len);
extern struct hash_map_s *hash_map_init(void *m,
                                        uint32_t entries,
                                        uint32_t data_size,
                                        uint32_t key_len,
                                        uint32_t hash_init);
extern uint32_t hash_map_alloc_idx(struct hash_map_s *hmap);
extern void hash_map_free_idx(struct hash_map_s *hmap, uint32_t idx);
extern int hash_map_add(struct hash_map_s *hmap, const void *key,
                        uint32_t idx);
extern int hash_map_update(struct hash_map_s *hmap, const void *key,
                           uint32_t new_idx);
extern uint32_t hash_map_remove(struct hash_map_s *hmap, const void *key);
extern uint32_t hash_map_find(struct hash_map_s *hmap, const void *key);
#endif /* !_HASHMAP_H_ */
