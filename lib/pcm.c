#include <alloca.h>
#include <alsa/asoundlib.h>

#include "pcm.h"
#include "err.h"


void
p67_pcm_free(p67_pcm_t * __pcm)
{
    if(__pcm == NULL) return;
    if(__pcm->__hw != NULL) {
        snd_pcm_drain((snd_pcm_t *)__pcm->__hw);
        snd_pcm_close((snd_pcm_t *)__pcm->__hw);
        __pcm->__hw = NULL;
    }
    if(__pcm->name != NULL && __pcm->name_rdonly != 0) {
        free(__pcm->name);
    }
}

p67_err
p67_pcm_write(p67_pcm_t * pcm, void * buff, size_t * buffl)
{
    ssize_t ret;
    p67_err err = 0;
    ret = snd_pcm_writei((snd_pcm_t *)pcm->__hw, buff, *buffl);
    if(ret <= 0) {
        if(ret == -EPIPE) {
            snd_pcm_prepare((snd_pcm_t *)pcm->__hw);
            err = p67_err_eagain;
        } else {
            err = p67_err_epcm | p67_err_eerrno;
        }
    }
    *buffl = ret;
    return err;
}

p67_err
p67_pcm_read(p67_pcm_t * pcm, void * buff, size_t * buffl)
{
    ssize_t ret;
    p67_err err = 0;
    ret = snd_pcm_readi((snd_pcm_t *)pcm->__hw, buff, *buffl);
    if(ret < 0) {
        if(ret == -EPIPE) {
            snd_pcm_prepare((snd_pcm_t *)pcm->__hw);
            err = p67_err_eagain;
        } else {
            err = p67_err_epcm | p67_err_eerrno;
        }
    }
    *buffl = ret;
    return err;
}

p67_err
p67_pcm_create_io(p67_pcm_t * __pcm)
{
    snd_pcm_hw_params_t * params;
    int tmp, fmt, ret;
    const char * name;
    if(__pcm->name != NULL) 
        name = __pcm->name; 
    else
        name = P67_PCM_NAME_DEFAULT;

    snd_pcm_t ** pcm = (snd_pcm_t **)&__pcm->__hw;

    switch(__pcm->pcm_tp) {
    case P67_PCM_TP_I:
        ret = snd_pcm_open(pcm, name, SND_PCM_STREAM_CAPTURE, 0);
        break;
    case P67_PCM_TP_O:
        ret = snd_pcm_open(pcm, name, SND_PCM_STREAM_PLAYBACK, 0);
        break;
    default:
        return p67_err_einval;
    }

    if(ret != 0) goto end;

    snd_pcm_hw_params_alloca(&params);

    snd_pcm_hw_params_any(*pcm, params);

    if((ret = snd_pcm_hw_params_set_access(
             *pcm, params, SND_PCM_ACCESS_RW_INTERLEAVED)) != 0) goto end;

    switch(__pcm->bits_per_sample) {
    case P67_PCM_PBS_16:
        fmt = SND_PCM_FORMAT_S16_LE;
        break;
    default:
        goto end;
    }

    if((ret = snd_pcm_hw_params_set_format(
        *pcm, params, fmt)) != 0) goto end;

    if((ret = snd_pcm_hw_params_set_channels(
                    *pcm, params, __pcm->channels)) != 0) goto end;

    if((ret = snd_pcm_hw_params_set_rate_near(
                    *pcm, params, &__pcm->sampling, &tmp)) != 0) goto end;

    if(__pcm->frame_size > 0) {
        if((ret = snd_pcm_hw_params_set_period_size_near(
                    *pcm, params, &__pcm->frame_size, &tmp)) != 0) goto end;
    }

    //snd_pcm_set_params(*pcm, fmt, SND_PCM_ACCESS_RW_INTERLEAVED, __pcm->channels, , 1, 500000)

    if((ret = snd_pcm_hw_params(*pcm, params)) != 0) goto end;

    if(__pcm->frame_size <= 0) {
        if((ret = snd_pcm_hw_params_get_period_size(
                        params, &__pcm->frame_size, &tmp)) != 0) goto end;
        if(__pcm->frame_size <= 0) {
            ret = -1;
            goto end;
        }
    }

    return 0;

end:
    if(ret != 0)
        fprintf(stderr, "%s\n", snd_strerror(ret));
    return p67_err_eerrno | p67_err_epcm;
}
