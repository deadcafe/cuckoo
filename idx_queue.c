
#include <sys/types.h>
#include "idx_queue.h"

/*
 * index functions
 */
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
idx_queue_sizeof(uint32_t entries)
{
    size_t size = align32pow2(entries);

    size *= sizeof(uint32_t);
    size += sizeof(struct idx_queue_s);
    return size;
}

void
idx_queue_reset(struct idx_queue_s *queue)
{
    queue->head = 0;
    queue->tail = 0;

    for (uint32_t i = 0; i < queue->nb_entries; i++)
        queue->free_slot[i] = i;
    queue->nb_free = queue->nb_entries;
}

struct idx_queue_s *
idx_queue_map(void *m,
              unsigned entries)
{
    struct idx_queue_s *queue = m;
    uint32_t size = align32pow2(entries);

    queue->nb_entries = entries;
    queue->mask = size - 1;
    idx_queue_reset(queue);
    return queue;
}
