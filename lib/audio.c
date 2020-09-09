#include <stdlib.h>

#include <p67/cmn.h>
#include <p67/audio.h>

#define p67_audio_read(hptr, buff, buffl) \
    (pa_simple_read((hptr)->__hw, (buff), (buffl), p67_audio_error_location()) < 0 ? p67_err_eaudio : 0)

#define p67_audio_write(hptr, buff, buffl) \
    (pa_simple_write((hptr)->__hw, (buff), (buffl), p67_audio_error_location()) < 0 ? p67_err_eaudio : 0)

static __thread p67_audio_err_t __audio_err = 0;
static __thread p67_audio_codecs_err_t __codecs_err = 0;

/* max compressed frame size */
#define P67_AUDIO_CODECS_MAX_CFRAME_SIZE 1276

p67_audio_err_t *
p67_audio_error_location(void)
{
    return &__audio_err;
}

p67_audio_codecs_err_t *
p67_audio_codecs_error_location(void)
{
    return &__codecs_err;
}

const p67_audio_fmt_info_t p67_audio_fmts[1] = {
    { PA_SAMPLE_S16LE, 16 }
};

union p67_codecs_opus {
    OpusEncoder * enc;
    OpusDecoder * dec;
};

struct p67_audio {
    p67_audio_config_t config;
    char * name;
    pa_simple * __hw;
    void * codecs_buffer;
    union p67_codecs_opus codecs;
    int dir;
    p67_cmn_refcount_fields(_)
};

P67_CMN_NO_PROTO_ENTER
void
p67_audio_codecs_destroy(
P67_CMN_NO_PROTO_EXIT
    p67_audio_t * audio)
{
    if(!audio) 
        return;
    
    switch(audio->dir) {
    case P67_AUDIO_DIR_I:
        if(audio->codecs.enc)
            opus_encoder_destroy(audio->codecs.enc);
        break;
    case P67_AUDIO_DIR_O:
        if(audio->codecs.dec)
            opus_decoder_destroy(audio->codecs.dec);
        break;
    default:
        break;
    }

    free(audio->codecs_buffer);
}

P67_CMN_NO_PROTO_ENTER
void
__p67_audio_free(
P67_CMN_NO_PROTO_EXIT
    p67_audio_t * audio)
{
    if(!audio)
        return;
    if(audio->__hw)
        pa_simple_free(audio->__hw);
    p67_audio_codecs_destroy(audio);
    free(audio->name);
    free(audio);
}

void
p67_audio_free(p67_audio_t * audio) {
    p67_cmn_refcount_free(audio, _, __p67_audio_free);
}

p67_audio_t *
p67_audio_refcpy(p67_audio_t * audio) {
    p67_cmn_refcount_refcpy(audio, _);
}

P67_CMN_NO_PROTO_ENTER
p67_err
p67_audio_create_codecs(
P67_CMN_NO_PROTO_EXIT
    p67_audio_t * audio)
{
    if(!audio || audio->config.fmt != P67_AUDIO_FMT_S16LE)
        return p67_err_einval;

    switch(audio->dir) {
    case P67_AUDIO_DIR_I:
        audio->codecs.enc = opus_encoder_create(
                    audio->config.rate,
                    audio->config.channels, 
                    OPUS_APPLICATION_AUDIO,
                    p67_audio_codecs_error_location());
        opus_encoder_ctl(
            audio->codecs.enc, 
            OPUS_SET_BITRATE(
                audio->config.rate * 
                audio->config.fmt->bits_per_sample * 
                audio->config.channels));
        break;
    case P67_AUDIO_DIR_O:
        audio->codecs.dec = opus_decoder_create(
                    audio->config.rate, 
                    audio->config.channels,
                    p67_audio_codecs_error_location());
        break;
    default:
        return p67_err_einval;
    }

    if(p67_audio_codecs_err != 0) {
        return p67_err_eacodecs;
    }

    audio->codecs_buffer = malloc(
        p67_audio_config_buffer_size(&audio->config));
    if(!audio->codecs_buffer) {
        p67_audio_codecs_destroy(audio);
        return p67_err_eerrno;
    }

    return 0;
}

p67_audio_t * 
p67_audio_create(
    p67_audio_dir_t dir, 
    const char * device_name, 
    const p67_audio_config_t * config)
{
    char name[8], sname[8];
    pa_buffer_attr attr;
    pa_sample_spec ss;
    int err = 0;

    p67_audio_t * ret = malloc(sizeof(p67_audio_t));
    if(!ret)
        return NULL;

    if(device_name)
        ret->name = p67_cmn_strdup(device_name);
    else
        ret->name = NULL;
    ret->dir = dir;
    ret->codecs.dec = NULL;
    p67_cmn_refcount_init(ret, _);

    p67_audio_config_cpy_with_defaults(config, ret->config)

    ss.channels = ret->config.channels;
    ss.rate = ret->config.rate;
    ss.format = ret->config.fmt->id;
    attr.fragsize = p67_audio_config_buffer_size(&ret->config);

    switch(dir) {
    case P67_AUDIO_DIR_I:
        attr.maxlength = 5 * attr.fragsize;
        attr.minreq = (uint32_t)-1;
        attr.prebuf = (uint32_t)-1;
        attr.tlength = (uint32_t)-1;
        sprintf(name, "p671");
        sprintf(sname, "sp671");
        break;
    case P67_AUDIO_DIR_O:
        attr.prebuf = 10 * attr.fragsize;
        attr.tlength = 5 * attr.fragsize;
        attr.minreq = (uint32_t)-1;
        attr.maxlength = (uint32_t)-1;
        sprintf(name, "p672");
        sprintf(sname, "sp672");
        break;
    default:
        free(ret);
        return NULL;
    }

    ret->__hw = pa_simple_new(
        NULL,               /* pulseaudio server */ 
        name,
        dir,                /* I/O */
        ret->name,    /* device name */
        sname,
        &ss,                /* ctx */
        NULL,
        &attr, //dir == PA_DIRECTION_INPUT ? &attr : NULL, /* buffer attributes */
        &err);

    if(err != 0) {
        free(ret);
        p67_audio_err = err;
        return NULL;
    }

    if((err = p67_audio_create_codecs(ret))) {
        free(ret);
        return NULL;
    }

    return ret;
}

/*

P67_CMN_NO_PROTO_ENTER
int
p67_audio_config_buffer_size(
P67_CMN_NO_PROTO_EXIT
    const p67_audio_config_t * config)
{
    return config->fmt->bits_per_sample / 8 *
        config->channels *
        config->frame_size;
}
*/

p67_err
p67_audio_create_buff(p67_audio_t * h, void ** buf, int * buffl)
{
    int bl = p67_audio_config_buffer_size(&h->config);
    if(buffl != NULL)
        *buffl = bl;
    if(buf != NULL)
        if((*buf = malloc(bl)) == NULL) return p67_err_eerrno;
    return 0;
}

P67_CMN_NO_PROTO_ENTER
p67_err
p67_audio_codecs_encode(
P67_CMN_NO_PROTO_EXIT
            p67_audio_t * cptr, 
            const unsigned char * decompressed_frame,
            unsigned char * compressed_frame, 
            int * outsize)
{
    int ix;
    opus_int16 * tb = (opus_int16 *)cptr->codecs_buffer;

    for (ix=0;ix<cptr->config.frame_size*cptr->config.channels;ix++) {
        tb[ix] = decompressed_frame[
            p67_audio_fmt_bytes_per_sample(cptr->config.fmt)*ix+1]<<8 | 
                 decompressed_frame[
                     p67_audio_fmt_bytes_per_sample(cptr->config.fmt)*ix];
    }

    *outsize = opus_encode(
                    cptr->codecs.enc, 
                    tb, 
                    cptr->config.frame_size, 
                    compressed_frame, 
                    *outsize);

    if(*outsize == 1)
        return p67_err_eagain;

    if(*outsize < 0) {
        p67_audio_codecs_err = *outsize;
        return p67_err_eacodecs;
    }

    return 0;
}

P67_CMN_NO_PROTO_ENTER
p67_err
p67_audio_codecs_decode(
P67_CMN_NO_PROTO_EXIT
            p67_audio_t * cptr,
            const unsigned char * compressed_frame, int csize,
            unsigned char * decompressed_frame)
{
    int ix, err = 0;
    opus_int16 * tb = (opus_int16 *)cptr->codecs_buffer;

    if((err = opus_decode(
                cptr->codecs.dec, 
                compressed_frame, 
                csize, 
                tb, 
                cptr->config.frame_size, 
                compressed_frame == NULL ? 1 : 0)) < 0) {
        p67_audio_codecs_err = err;
        return p67_err_eacodecs;
    }

    for(ix=0;ix<cptr->config.frame_size*cptr->config.channels;ix++) {
        decompressed_frame[
            p67_audio_fmt_bytes_per_sample(cptr->config.fmt)*ix] = tb[ix]&0xFF;
        decompressed_frame[
            p67_audio_fmt_bytes_per_sample(cptr->config.fmt)*ix+1] = (tb[ix]>>8)&0xFF;
    }

    return 0;
}


p67_err
p67_audio_write_qdp(
    p67_thread_sm_t * tsm,
    p67_addr_t * addr,
    p67_audio_t * input,
    uint8_t utp)
{
    p67_qdp_hdr_t hdr;
    p67_qdp_hdr_align_zero(hdr.__align);
    hdr.qdp_utp = utp;
    hdr.qdp_stp = P67_DML_STP_QDP_DAT;
    p67_err err = 0;
    unsigned char compressed_frame[
        sizeof(hdr)+P67_AUDIO_CODECS_MAX_CFRAME_SIZE];
    unsigned char decompressed_frame[
        p67_audio_config_buffer_size(&input->config)];
    int cb;
    // it would take around 8 years of stereo streaming with 48k sampling to overflow this variable
    // so we should be ok with using 32bits
    // proof: 
    // lseq/second = 400 (400 frames per second)
    // uint32 limit = 4294967295
    // amount of seconds to overflow = 4294967295 / 400
    register uint32_t seq = 1;

    // if(input->__hw != NULL) {
    //     // if hardware is already allocated, flush or drain buffer and reenter loop
    //     return p67_err_einval;
    // } else {
    //     if((err = p67_audio_create_io(input)) != 0)
    //         goto end;
    // }

    while(1) {

        if(tsm != NULL && p67_thread_sm_stop_requested(tsm)) {
            err = 0;
            break;
        }

        if((err = p67_audio_read(
                input, decompressed_frame, sizeof(decompressed_frame))) != 0) 
            goto end;

        cb = P67_AUDIO_CODECS_MAX_CFRAME_SIZE;
        
        if((err = p67_audio_codecs_encode(
                input, decompressed_frame, compressed_frame+sizeof(hdr), &cb)) != 0)
           goto end;

        hdr.qdp_seq = htonl(seq++);
        memcpy(compressed_frame, &hdr, sizeof(hdr));

        if((err = p67_net_write_msg(
                addr, compressed_frame, cb+sizeof(hdr))) != 0) 
            goto end;
        // if((err = p67_net_write_msg(
        //         addr, compressed_frame, cb+sizeof(hdr))) != 0) 
        //     goto end;
    }

end:
    if(tsm) p67_thread_sm_stop_notify(tsm);
    return err;
}

p67_err
p67_audio_read_qdp(
    p67_thread_sm_t * tsm,
    p67_qdp_ctx_t * s,
    p67_audio_t * output)
{
    unsigned char compressed_frame[
        P67_AUDIO_CODECS_MAX_CFRAME_SIZE];
    int dsz = p67_audio_config_buffer_size(&output->config);
    unsigned char decompressed_frame[dsz];
    p67_err err = 0;
    int st;
    int interval = ((output->config.frame_size * 1e6) / output->config.rate) / 2;
    int q_min_len = 20 * s->q_chunk_size;
    int size;

    // if(output->__hw != NULL) {
    //     // TODO: if hardware is already allocated, flush or drain buffer and reenter loop
    //     return p67_err_einval;
    // } else {
    //     if((err = p67_audio_create_io(output)) != 0)
    //         goto end;
    // }

    /*
        wait up until stream arrives.
        temp solution
    */
    while(1) {
        st = p67_qdp_space_taken(s);
        if(st >= q_min_len) {
            break;
        }
        p67_cmn_sleep_micro(interval);
    }

    while(1) {

        if(tsm != NULL && p67_thread_sm_stop_requested(tsm)) {
            err = 0;
            break;
        }

        st = p67_qdp_space_taken(s);
        if(st < q_min_len) {
            p67_cmn_sleep_micro(interval);
            continue;
        }

        size = s->q_chunk_size;

        err = p67_qdp_deque(s, compressed_frame, &size);
        if(err != 0 && err != p67_err_eagain) {
            p67_cmn_sleep_micro(interval);
            continue;
        }

        if((err = p67_audio_codecs_decode(
                output, 
                err == p67_err_eagain ? NULL : compressed_frame, 
                size,  
                decompressed_frame)) != 0) goto end;

        if((err = p67_audio_write(
                output, decompressed_frame, dsz)) != 0) goto end;
    }

end:
    if(tsm) p67_thread_sm_stop_notify(tsm);
    return err;
}

typedef struct p67_audio_read_qdp_ctx {
    p67_thread_sm_t * tsm;
    p67_qdp_ctx_t * s;
    p67_audio_t * output;
} p67_audio_read_qdp_ctx_t;

P67_CMN_NO_PROTO_ENTER
void
p67_audio_read_qdp_ctx_free(
P67_CMN_NO_PROTO_EXIT
    p67_audio_read_qdp_ctx_t * ctx)
{
    if(!ctx) return;
    p67_qdp_free(ctx->s);
    p67_audio_free(ctx->output);
    free(ctx);
}

P67_CMN_NO_PROTO_ENTER
void *
p67_audio_run_read_qdp(
P67_CMN_NO_PROTO_EXIT
   void * args) 
{
    p67_audio_read_qdp_ctx_t * ctx = (p67_audio_read_qdp_ctx_t *)args;
    p67_err err;
    err = p67_audio_read_qdp(ctx->tsm, ctx->s, ctx->output);
    if(err != 0) {
        p67_err_print_err("terminating read_qdp with error/s: ", err);
    }
    p67_audio_read_qdp_ctx_free(ctx);
    return NULL;
}

p67_err
p67_audio_start_read_qdp(
        p67_thread_sm_t * tsm,
        p67_qdp_ctx_t * s,
        p67_audio_t * output) {
    
    p67_audio_read_qdp_ctx_t * ctx;
    ctx = malloc(sizeof(*ctx));
    if(!ctx) return p67_err_eerrno;
    ctx->output = p67_audio_refcpy(output);
    ctx->s = p67_qdp_refcpy(s);
    ctx->tsm = tsm;
    return p67_thread_sm_start(ctx->tsm, p67_audio_run_read_qdp, ctx);
}

typedef struct p67_audio_write_qdp_ctx {
    p67_thread_sm_t * tsm;
    p67_addr_t * addr;
    p67_audio_t * input;
    uint8_t utp;
} p67_audio_write_qdp_ctx_t;

P67_CMN_NO_PROTO_ENTER
void
p67_audio_write_qdp_ctx_free(
P67_CMN_NO_PROTO_EXIT
    p67_audio_write_qdp_ctx_t * ctx)
{
    if(!ctx) return;
    p67_addr_free(ctx->addr);
    p67_audio_free(ctx->input);
    free(ctx);
}

P67_CMN_NO_PROTO_ENTER
void *
p67_audio_run_write_qdp(
P67_CMN_NO_PROTO_EXIT
   void * args) 
{
    p67_audio_write_qdp_ctx_t * ctx = (p67_audio_write_qdp_ctx_t *)args;
    p67_err err;
    err = p67_audio_write_qdp(ctx->tsm, ctx->addr, ctx->input, ctx->utp);
    if(err != 0) {
        p67_err_print_err("terminating write_qdp with error/s: ", err);
    }
    p67_audio_write_qdp_ctx_free(ctx);
    return NULL;
}

p67_err
p67_audio_start_write_qdp(
        p67_thread_sm_t * tsm,
        p67_addr_t * addr,
        p67_audio_t * input,
        uint8_t utp) 
{    
    p67_audio_write_qdp_ctx_t * ctx;
    ctx = malloc(sizeof(*ctx));
    if(!ctx) return p67_err_eerrno;
    ctx->input = p67_audio_refcpy(input);
    ctx->addr = p67_addr_ref_cpy(addr);
    ctx->tsm = tsm;
    ctx->utp = utp;
    return p67_thread_sm_start(ctx->tsm, p67_audio_run_write_qdp, ctx);
}
