
#include <assert.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>

#include "../cuckoo_hash.h"


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

struct data_s {
    union {
	uint8_t   v8[16];
	uint16_t v16[8];
	uint32_t v32[4];
	uint64_t v64[2];
    };
};

static uint64_t
test(unsigned num,
     unsigned size,
     uint32_t iv,
     unsigned loops,
     bool use_aes,
     bool disp)
{
    char *p = calloc(num, size * 16);
    uint64_t (*hash_func)(const void *, uint32_t, unsigned);

    if (use_aes)
        hash_func = cuckoo_hash_16n_aes;
    else
        hash_func = cuckoo_hash_16n_crc;

    for (unsigned i = 0; i < num; i++) {
        struct data_s *data = (struct data_s *) &p[i * (size * 16)];
	data->v32[3] = i;
    }

    uint64_t s = rdtsc();
    while (loops--) {
	for (unsigned i = 0; i < num; i++) {
            struct data_s *data = (struct data_s *) &p[i * (size * 16)];

	    uint64_t hash = (hash_func)(data,
                                        iv,
                                        size);

	    if (disp)
		fprintf(stderr, "hash:%016llx\n", (unsigned long long) hash);
            data->v64[0]++;
	}
    }
    uint64_t e = rdtsc();
    return e - s;
}

static void
usage(const char *prog)
{
    fprintf(stderr, "%s [-n NUM] [-l LOOPS] [-s SIZE] [-i IV] [-a] [-d]\n", prog);
}

int
main(int argc, char **argv)
{
    bool disp = false;
    bool use_aes = false;
    unsigned loops = 1;
    unsigned num = 1;
    int opt;
    unsigned size = 1;
    uint32_t iv = 0;

    while ((opt = getopt(argc, argv, "adl:n:s:i:")) != -1) {
	switch (opt) {
        case 'a':
            use_aes = true;
            break;

	case 'n':
	    num = atoi(optarg);
	    break;

	case 'd':
	    disp = true;
	    break;

	case 'l':
	    loops = atoi(optarg);
	    break;

        case 's':
            size = atoi(optarg);
            break;

        case 'i':
            iv = atoi(optarg);
            break;

	default:
            usage(argv[0]);
	    return -1;
	}
    }

    if (!num)
	num = 1;
    if (!size)
        size = 1;

    uint64_t t = test(num, size, iv, loops, use_aes, disp);
    fprintf(stderr, "Time:%"PRIu64" %f\n",
	    t, (double) t / (double) loops / (double) num);
    return 0;
}
