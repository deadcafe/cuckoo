#ifndef _HASHMAP_H_
#define _HASHMAP_H_


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


#endif /* !_HASHMAP_H_ */
