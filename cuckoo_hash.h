#ifndef _CUCKOO_HASH_H_
#define _CUCKOO_HASH_H_

#include <stdint.h>

extern uint64_t cuckoo_hash_16n_crc(const void *k,
                                    uint32_t init,
                                    unsigned n);

extern uint64_t cuckoo_hash_16n_aes(const void *t,
                                    uint32_t init,
                                    unsigned n);

#endif	/* !_CUCKOO_HASH_H_ */
