#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <inttypes.h>

#include "cuckoo.h"

/*****************************************************************************
 *
 *****************************************************************************/
struct key_s {
    union {
        uint32_t val32[4];
        uint64_t val64[2];
    } val[1];
} __attribute__((aligned(16)));;

struct data_s {
    cuckoo_sig_t sig;
    void *val;
    struct key_s *key;
    void *_pad;
} __attribute__((aligned(32)));

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


static bool RandomMode;

struct data_s *
create_data(uint32_t cookie,
            unsigned key_size,
            size_t num)
{
    struct data_s *data = calloc(num, sizeof(*data));
    struct key_s *key   = calloc(num, sizeof(*key) * key_size);

    if (data && key) {
        for (size_t i = 0; i < num; i++, key += key_size) {

            key->val[0].val32[0] = cookie;
            if (RandomMode) {
                key->val[0].val32[1] = i;
                key->val[0].val64[1] = random();
            } else {
                key->val[0].val32[1] = 0;
                key->val[0].val64[1] = i;
            }

            data[i].key = key;
            data[i].val = &data[i];
        }
    } else {
        exit(1);
    }
    return data;
}

static int
count_egg(struct cuckoo_s *cuckoo __attribute__((unused)),
	  struct cuckoo_egg_s *egg,
	  void *arg)
{
    unsigned *stats = arg;

    if (cuckoo_is_valid(egg)) {
        stats[cuckoo_get_pos(egg)] += 1;
    }
    return 0;
}

static inline void
count_hash(struct cuckoo_s *hash)
{
    unsigned stats[CUCKOO_EGG_NUM];

    memset(stats, 0, sizeof(stats));

#ifdef CUCKOO_DEBUG
    for (unsigned i = 0; i < CUCKOO_DEPTH_MAX; i++)
        fprintf(stderr, "depth[%u]: %zu\n", i, hash->depth[i]);
#endif

    cuckoo_walk(hash, count_egg, stats);

    for (unsigned i = 0; i < CUCKOO_EGG_NUM; i++) {
        fprintf(stderr, "eggs %u %u %f\n",
                i, stats[i], (double) stats[i] / (double) hash->nb_data);
    }

#ifdef CUCKOO_DEBUG
    fprintf(stderr, "rotate:    %zu\n", hash->stats[CUCKOO_STATS_ROTATE]);
    fprintf(stderr, "conflicts: %zu\n", hash->stats[CUCKOO_STATS_CONFLICT]);
    fprintf(stderr, "retries:   %zu\n", hash->stats[CUCKOO_STATS_RETRY]);
    fprintf(stderr, "exist:     %zu\n", hash->stats[CUCKOO_STATS_EEXIST]);
    fprintf(stderr, "nospc:     %zu\n", hash->stats[CUCKOO_STATS_ENOSPC]);
#endif
    fprintf(stderr, "nb_data:   %"PRIu32"\n", hash->nb_data);
}

static inline void
dump_data(const struct data_s *data,
          unsigned n)
{
    fprintf(stderr,
            "%uth:%p sig:%016llx %p k0:%08x k1:%08x k2:%08x k3:%08x val:%p\n",
            n,
            data,
            (unsigned long long) data->sig,
            data->key,
            data->key->val[0].val32[0],
            data->key->val[0].val32[1],
            data->key->val[0].val32[2],
            data->key->val[0].val32[3],
            data->val);
}

static uint64_t
search_test_bulk(struct cuckoo_s * restrict hash,
                 size_t entries,
                 struct data_s * restrict base,
                 const unsigned bulk_num)
{
    uint64_t start, end;

    start = rdtsc();
    for (unsigned j = 0; j < bulk_num; j++) {
        cuckoo_prefetch0_sig(hash, base[j].sig);
    }

    for (unsigned i = 0; i < entries; i += bulk_num) {

        for (unsigned j = 0; j < bulk_num; j++) {
            struct cuckoo_egg_s *egg;
            struct data_s *data = &base[i + j];

#if 0
            dump_data(data, i + j);
#endif
            egg = cuckoo_find_egg_sig(hash,
                                      data->sig,
                                      data->key);
            if (!egg || egg->data != data->val) {
                dump_data(data, i + j);
                fprintf(stderr, "not found xxx: %u\n", i + j);
                exit(0);
            }

            if (i + j + bulk_num < entries) {
                cuckoo_prefetch1_sig(hash, data[bulk_num].sig);
            }
        }
    }
    end = rdtsc();
    return end - start;
}

static uint64_t
add_test_bulk(struct cuckoo_s * restrict hash,
              size_t entries,
              struct data_s * restrict del_data,
              struct data_s * restrict add_data,
              const unsigned bulk_num)
{
    uint64_t start, end;
    int ret;

    start = rdtsc();
    for (unsigned i = 0; i < entries; i += bulk_num) {

        for (unsigned j = 0; j < bulk_num; j++) {
            cuckoo_prefetch0_sig(hash, del_data[i + j].sig);
            add_data[i + j].sig = cuckoo_init_sig(hash, add_data[i + j].key);
        }

        for (unsigned j = 0; j < bulk_num; j++) {

#if 0
            dump_data(&del_data[i + j], i + j);
#endif
            if (!cuckoo_remove_sig(hash,
                                   del_data[i + j].sig,
                                   del_data[i + j].key)) {
                dump_data(&del_data[i + j], i + j);
                fprintf(stderr, "not found data:%u\n", i + j);
                exit(0);
            }

            del_data[i + j].key->val[0].val32[1] += 1;

	    ret = cuckoo_add_sig(hash,
                                 add_data[i + j].sig,
                                 add_data[i + j].key,
                                 add_data[i + j].val);
            if (ret) {
                dump_data(&add_data[i + j], i + j);
                fprintf(stderr, "failed add: %u %d\n", i + j, ret);
                exit(0);
            }
        }
    }
    end = rdtsc();

    return end - start;
}

#define SWAP(a,b) { typeof(a) c; c = (a); (a) = (b); (b) = c; } while (0)

static int
test(size_t entries_max,
     size_t entries,
     unsigned loop_cnt,
     unsigned bulk_num,
     unsigned key_size,
     uint32_t iv,
     bool use_aes)
{
    struct cuckoo_s *hash;
    struct data_s *add_data, *del_data, *data;
    size_t key_len = (key_size * 16);
    size_t size = cuckoo_sizeof(entries_max, key_len);

    hash = cuckoo_map(aligned_alloc(16, size),
                      use_aes, entries_max, key_len, iv);
    if (!hash)
        return 0;

    add_data = create_data(2, key_size, entries);
    del_data = create_data(5, key_size, entries);

    for (unsigned i = 0; i < entries; i++) {
        data = &add_data[i];

        data->sig = cuckoo_init_sig(hash, data->key);

#if 0
        dump_data(data, i);
#endif

        int ret = cuckoo_add_sig(hash,
                                 data->sig,
                                 data->key,
                                 data->val);
        if (ret) {
            fprintf(stderr, "init failed %u %d %f\n",
                    i, ret,
                    (double) i / (double) entries);
            count_hash(hash);
            return -1;
        }
    }

    fprintf(stderr, "initialized\n");

    uint64_t tm_a = 0, tm_s = 0;
    unsigned disp = loop_cnt / 10;

    for (unsigned loop = 0; loop < loop_cnt; loop++) {

        SWAP(add_data, del_data);

        tm_a += add_test_bulk(hash,
                              entries,
                              del_data,
                              add_data,
                              bulk_num);

        tm_s += search_test_bulk(hash,
                                 entries,
                                 add_data,
                                 bulk_num);

        if (hash->nb_data != entries) {
            fprintf(stderr, "mismatched nb\n");
	    return -1;
	}

        if (disp > 9) {
            if ((loop + 1) % disp)
                continue;
        }

        fprintf(stderr, "<<loop:%u>>\n", loop + 1);
        fprintf(stderr, "max entries:%"PRIu32" entries:%zu %f\n",
                hash->entries,
                entries,
                (double) entries / (double) hash->entries);

        count_hash(hash);

	fprintf(stderr, "del and add time(av): %f\n",
                ((double) tm_a / (double) (loop + 1)) / (double) entries);

        fprintf(stderr, "search time(av): %f\n\n",
                ((double) tm_s / (double) (loop + 1)) / (double) entries);

    }

    fprintf(stderr, "=== End ===\n");
    count_hash(hash);
    fprintf(stderr, "del and add time(av): %f\n",
            ((double) tm_a / (double) loop_cnt) / (double) entries);

    fprintf(stderr, "search time(av): %f\n",
            ((double) tm_s / (double) loop_cnt) / (double) entries);

    fprintf(stderr, "max entries:%"PRIu32" entries:%zu %f\n\n",
            hash->entries,
            entries,
            (double) entries / (double) hash->entries);

    free(hash);
    return 0;
}

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

static void
usage(const char *prog)
{
    fprintf(stderr,
            "%s [-e ENTRIES] [-l LOOPS] [-b BULK_NUM] [-i IV] [-s KEY_SIZE] [-r] [-a]\n",
            prog);
}

int
main(int argc,
     char **argv)
{
    size_t entries = 6291456;
    size_t max;
    unsigned loops = 10;
    int opt;
    char *prog = argv[0];
    unsigned bulk_num = 3;
    uint32_t iv = 0;
    unsigned size = 1;	/* x16 */
    bool use_aes = false;

    while ((opt = getopt(argc, argv, "arb:l:e:i:s:")) != -1) {
        switch (opt) {
        case 'a':
            use_aes = true;
            break;

        case 'b':
            bulk_num = atoi(optarg);
            break;

        case 'l':
            loops = atoi(optarg);
            break;

        case 'e':
            entries = strtoul(optarg, NULL, 10);
            break;

        case 'r':
            RandomMode = true;
            break;

        case 'i':
            iv = atoi(optarg);
            break;

        case 's':
            size = atoi(optarg);
        break;

        default:
            usage(prog);
            exit(0);
        }
    }

    if (bulk_num == 0)
        bulk_num = 1;

    if (size == 0)
        size = 1;

    entries -= (entries % bulk_num);

    max = align32pow2(entries * 2.49);

    fprintf(stderr, "max:%lu entries:%lu %f loops:%u bulk:%u Random:%d\n",
            max, entries, (double) entries / (double) max, loops, bulk_num,
            (int) RandomMode);

    test(max, entries, loops, bulk_num, size, iv, use_aes);

    return 0;
}
