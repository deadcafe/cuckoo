#ifndef _IDX_QUEUE_H_
#define _IDX_QUEUE_H_

#include <sys/types.h>
#include <stdint.h>

/*
 * cuckoo index
 */
struct idx_queue_s {
    uint32_t mask;
    uint32_t nb_entries;

    uint32_t head;
    uint32_t tail;
    uint32_t nb_free;	/* nb free slot */
    uint32_t _pad;

    uint32_t free_slot[0] __attribute__((aligned(64)));
} __attribute__((aligned(64)));

/*
 * cuckoo index functions
 */
extern size_t idx_queue_sizeof(uint32_t entries);
extern void idx_queue_reset(struct idx_queue_s *queue);
extern struct idx_queue_s *idx_queue_map(void *m, uint32_t entries);

static inline int
idx_queue_free_idx(struct idx_queue_s *queue,
                   const uint32_t *buff,
                   unsigned n)
{
    if (n > (queue->nb_entries - queue->nb_free))
        return -1;

    uint32_t tail = queue->tail;
    uint32_t mask = queue->mask;

    for (unsigned i = 0; i < n; i++) {
        queue->free_slot[tail] = buff[i];
        tail++;
        tail &= mask;
    }
    queue->tail = tail;
    queue->nb_free += n;
    return 0;
}

static inline int
idx_queue_alloc_idx(struct idx_queue_s *queue,
                    uint32_t *buff,
                    unsigned n)
{
    if (n > queue->nb_free)
        return -1;

    uint32_t head = queue->head;
    uint32_t mask = queue->mask;

    for (unsigned i = 0; i < n; i++) {
        buff[i] = queue->free_slot[head];
        head++;
        head &= mask;
    }
    queue->head = head;
    queue->nb_free -= n;
    return 0;
}


#endif /* !_IDX_QUEUE_H_ */
