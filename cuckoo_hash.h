#ifndef _CUCKOO_HASH_H_
#define _CUCKOO_HASH_H_

#include <stdint.h>



typedef uint32_t cuckoo_sig_t;

#define CUCKOO_SIG_WIDTH	32

static inline uint32_t
cuckoo_sig_rotate(cuckoo_sig_t sig, unsigned r)
{
    cuckoo_sig_t s;
    r &= (CUCKOO_SIG_WIDTH - 1);
    s = (sig >> r) | (sig << (CUCKOO_SIG_WIDTH -r));
    return (uint32_t) (s & 0xffffffff);
}


extern cuckoo_sig_t cuckoo_hash_16n_crc(const void *k,
                                        uint32_t init,
                                        unsigned n);

extern cuckoo_sig_t cuckoo_hash_16n_aes(const void *t,
                                        uint32_t init,
                                        unsigned n);

#endif	/* !_CUCKOO_HASH_H_ */
