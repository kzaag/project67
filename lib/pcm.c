#include <alloca.h>
#include <alsa/asoundlib.h>

#include "pcm.h"
#include "err.h"

void
p67_pcm_free(p67_pcm_t * __pcm)
{
    if(__pcm == NULL) return;
    snd_pcm_t * pcm = (snd_pcm_t *)__pcm;
    snd_pcm_drain(pcm);
    snd_pcm_close(pcm);
}

p67_err
p67_pcm_read(p67_pcm_t * __in, unsigned long frame_size)
{
    ssize_t r;
    char b[frame_size*2];
    FILE * fp;

    snd_pcm_t * in = (snd_pcm_t *)__in;
    if((fp = fopen("1.raw", "wb+")) == NULL)
        return p67_err_eerrno;

    while(1) {
        r = snd_pcm_readi(in, b, frame_size);
        if(r < 0) {
            fprintf(stderr, "%s\n", snd_strerror(r));
            if(r == -EPIPE)
                snd_pcm_prepare(in);
            continue;
        }
        if(fwrite(b, 1, r, fp) != (size_t)r) 
            return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_pcm_create_in(
        p67_pcm_t ** __pcm, 
        const char * name,
        unsigned int * sampling,
        unsigned long * frame_size)
{
    int ret;
    snd_pcm_hw_params_t * params;
    int tmp;
    snd_pcm_t ** pcm = (snd_pcm_t **)__pcm;

    if((ret = snd_pcm_open(
            pcm, name, SND_PCM_STREAM_CAPTURE, 0)) != 0) goto end;

    snd_pcm_hw_params_malloc(&params);

    snd_pcm_hw_params_any(*pcm, params);

    if((ret = snd_pcm_hw_params_set_access(
             *pcm, params, SND_PCM_ACCESS_RW_INTERLEAVED)) != 0) goto end;

    if((ret = snd_pcm_hw_params_set_format(
        *pcm, params, SND_PCM_FORMAT_S16_LE)) != 0) goto end;

    if((ret = snd_pcm_hw_params_set_channels(*pcm, params, 1)) != 0) goto end;

    if((ret = snd_pcm_hw_params_set_rate_near(
                    *pcm, params, sampling, &tmp)) != 0) goto end;

    if((ret = snd_pcm_hw_params_set_period_size_near(
                    *pcm, params, frame_size, &tmp)) != 0) goto end;

    if((ret = snd_pcm_hw_params(*pcm, params)) != 0) goto end;

    return 0;

end:
    fprintf(stderr, "%s\n", snd_strerror(ret));
    return p67_err_einval;
}
