#if !defined(PCM_H)
#define PCM_H 1

#include "err.h"
#include <stdlib.h>

typedef struct p67_pcm p67_pcm_t;

struct p67_pcm {
    void * __hw;
    char * name;
    int name_rdonly;
    unsigned long frame_size;
    unsigned int sampling;
    unsigned int channels;
    unsigned int bits_per_sample;
    int pcm_tp;
};

#define p67_pcm_printf(p) \
    printf("sampling=%u frame_size=%lu channels=%u\n", p.sampling, p.frame_size, p.channels)

#define p67_pcm_act_size(pcm, s) ((s * (pcm).channels * (pcm).bits_per_sample)/8)

#define p67_pcm_buff_size(pcm) (p67_pcm_act_size(pcm, (pcm).frame_size))

#define p67_pcm_in_sync(p1, p2) \
    ((p1).frame_size == (p2).frame_size && (p1).channels == (p2).channels)

#define P67_PCM_NAME_DEFAULT "default"
#define P67_PCM_SAMPLING_48K 48000
#define P67_PCM_SAMPLING_44_1K 44100
#define P67_PCM_UNSPEC 0
#define P67_PCM_BPS_16 16

#define P67_PCM_CHAN_MONO 1
#define P67_PCM_CHAN_STEREO 2

#define P67_PCM_TP_I 1
#define P67_PCM_TP_O 2

#define P67_PCM_INTIIALIZER_IN \
    {NULL, NULL, 0, P67_PCM_UNSPEC, P67_PCM_UNSPEC, P67_PCM_UNSPEC, P67_PCM_BPS_16, P67_PCM_TP_I}

#define P67_PCM_INTIIALIZER_OUT \
    {NULL, NULL, 0, P67_PCM_UNSPEC, P67_PCM_UNSPEC, P67_PCM_UNSPEC, P67_PCM_BPS_16, P67_PCM_TP_O}

p67_err
p67_pcm_write(
            p67_pcm_t * __restrict__ pcm, 
            void * __restrict__ buff, 
            size_t * __restrict__ buffl)
    __nonnull((1, 2));

p67_err
p67_pcm_read(
            p67_pcm_t * __restrict__ __in, 
            void * __restrict__ buff,
            size_t * __restrict__ buffl)
    __nonnull((1, 2, 3));

p67_err
p67_pcm_create_io(p67_pcm_t * __restrict__ __pcm)
    __nonnull((1));

void
p67_pcm_free(p67_pcm_t * __restrict__ __pcm)
    __nonnull((1));

void
p67_pcm_recover(p67_pcm_t * pcm);

p67_err
p67_pcm_update(p67_pcm_t * pcm);

#endif