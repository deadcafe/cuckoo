
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cuckoo.h"


/*****************************************************************************
 *
 *****************************************************************************/
struct data_s {
    uint32_t key[4];
    void *val;
};

struct data_s *
create_data(uint32_t cookie,
            size_t num)
{
    struct data_s *data = malloc(sizeof(*data) * num);

    if (data) {
        for (unsigned i = 0; i < num; i++) {
            data[i].key[0] = cookie;
            data[i].key[1] = i;
            data[i].key[2] = i;
            data[i].key[3] = random();
            data[i].val = &data[i];
        }
    }
    return data;
}

static inline uint64_t
rdtsc(void)
{
    union {
        uint64_t tsc_64;
        struct {
            uint32_t lo_32;
            uint32_t hi_32;
        };
    } tsc;
    asm volatile("rdtsc" :
                 "=a" (tsc.lo_32),
                 "=d" (tsc.hi_32));
    return tsc.tsc_64;
}

static inline void
count_hash(const struct cuckoo_s *hash)
{
    unsigned stats[CUCKOO_EGG_NUM];

    memset(stats, 0, sizeof(stats));
    size_t num = hash->nb_data;

    for (unsigned i = 0; i < CUCKOO_EGG_NUM; i++) {
        char *array = hash->array[i];

        for (unsigned n = 0; n < hash->mask + 1; n++) {
            const struct cuckoo_node_s *node =
                (const struct cuckoo_node_s *) &array[hash->node_size * n];

            if (node->sig.val)
                stats[i] += 1;
        }

        num -= stats[i];
        fprintf(stderr, "array %u %u %f\n",
                i, stats[i], (double) stats[i] / (double) (hash->mask + 1));
    }
    if (num)
        fprintf(stderr, "invalif num\n");
}

#if 1
#define MAX_ENTRY	(6291456 * 2)
#else
#define MAX_ENTRY	(1024 << 8)
#endif

int
main(void)
{
    struct cuckoo_s *hash;
    struct data_s *data[2];
    unsigned long sum = 0;

    hash = cuckoo_map(aligned_alloc(16, cuckoo_sizeof(MAX_ENTRY, 16)),
                      MAX_ENTRY, 16, 0);
    if (!hash)
        return 0;

#if 1
    size_t entries = ((hash->mask + 1) * CUCKOO_EGG_NUM) * 0.4;
#else
    size_t entries = 6291456;
#endif


    data[0] = create_data(1, entries);
    for (unsigned i = 0; i < entries; i++) {
        if (cuckoo_add(hash, (data[0])[i].key, (data[0])[i].val)) {
            fprintf(stderr, "failed %u %f\n", i, (double) i / (double) entries);
            return 0;
        }
        sum++;
    }

    data[1] = create_data(2, entries);

    fprintf(stderr, "max entries:%llu array:%u entries:%llu\n\n",
            (hash->mask + 1) * CUCKOO_EGG_NUM,
            hash->mask + 1,
            entries);

    for (unsigned loop = 0; loop < 100; loop++) {

        fprintf(stderr, "<<loop:%u>>\n", loop);
        uint64_t start = rdtsc();
        for (size_t i = 0; i < entries; i++) {
            sum++;

            void *p;
            if ((p = cuckoo_remove(hash, (data[loop & 1])[i].key)) !=
                &(data[loop & 1])[i]) {
                fprintf(stderr, "invalid data:%u %p %p %lu %u\n",
                        i, p,
                        &(data[loop & 1])[i], sum,
                        (data[loop & 1])[i].key[1]);
                return 0;
            }

            (data[loop & 1])[i].key[1] += 1;
            (data[loop & 1])[i].key[2] = loop;

            if (cuckoo_add(hash, (data[(loop + 1) & 1])[i].key,
                           (data[(loop + 1) & 1])[i].val)) {
                fprintf(stderr, "%uth failed %u %f %lu\n",
                        loop, i, (double) i / (double) entries, sum);
                return 0;
            }
        }
        uint64_t end = rdtsc();

        if (hash->nb_data != entries)
            fprintf(stderr, "mismatched nb\n");

#ifdef CUCKOO_DEBUG
        for (unsigned i = 0; i < CUCKOO_DEPTH_MAX; i++)
            fprintf(stderr, "stats[%u]:%u\n", i, hash->stats[i]);

        count_hash(hash);
#endif

        fprintf(stderr, "time:%llu %f\n\n",
                end - start, (double) (end - start) / (double) entries);
    }

    free(hash);
    return 0;
}
