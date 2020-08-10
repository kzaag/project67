#if !defined(P67_HASH_H)
#define P67_HASH_H 1

#include <stdlib.h>
#include <assert.h>

#define P67_FH_FNV1_OFFSET (p67_hash_t)0xcbf29ce484222425
#define P67_FH_FNV1_PRIME (p67_hash_t)0x100000001b3

#define P67_HASH_KEY_MAX_LENGTH 128

typedef unsigned long p67_hash_t;

/* fnv 1a */
static inline p67_hash_t
p67_hash_fn(
    const unsigned char * key, 
    size_t len, 
    int bufferlen)
{
    assert(len > 0 && len <= P67_HASH_KEY_MAX_LENGTH);

    p67_hash_t hash = P67_FH_FNV1_OFFSET;
    while(len-->0) {
        hash ^= *(key++);
        hash *= P67_FH_FNV1_PRIME;
    }
    return (hash % bufferlen);
}

#endif
