#if !defined(PCM_H)
#define PCM_H 1

#include "err.h"

#define P67_SAMPLING_HIGH      48000

#define P67_FRAME_SIZE_DEFAULT 512

typedef void p67_pcm_t;

p67_err
p67_pcm_read(p67_pcm_t * __restrict__ __in, unsigned long frame_size)
    __nonnull((1));

p67_err
p67_pcm_create_in(
        p67_pcm_t ** __restrict__ __pcm, 
        const char * __restrict__ name,
        unsigned int * __restrict__ sampling,
        unsigned long * __restrict__ frame_size)
    __nonnull((1, 2));

void
p67_pcm_free(p67_pcm_t * __restrict__ __pcm)
    __nonnull((1));

#endif