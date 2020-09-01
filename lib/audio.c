#include <pulse/error.h>
#include <stdlib.h>
#include <stdio.h>

#include <p67/audio.h>

static __thread p67_audio_err_t __audio_err = 0;
static __thread p67_audio_err_t __codecs_err = 0;

p67_audio_err_t *
p67_audio_error_location(void)
{
    return &__audio_err;
}

p67_audio_err_t *
p67_audio_codecs_error_location(void)
{
    return &__codecs_err;
}

p67_err
p67_audio_create_io(p67_audio_t * hw)
{
    pa_buffer_attr attr;
    pa_sample_spec ss;
    int err = 0, fmt_bytes;
    enum pa_sample_format fmt;
    pa_direction_t dir;
    p67_audio_err = 0;
    char name[5];
    char sname[6];

    switch(hw->audio_fmt) {
    case P67_AUDIO_FMT_S16LE:
        fmt = PA_SAMPLE_S16LE;
        fmt_bytes = 2;
        break;
    default:
        return p67_err_einval;
    }

    switch(hw->audio_dir) {
    case P67_AUDIO_DIR_I:
        dir = PA_DIRECTION_INPUT;
        sprintf(name, "p671");
        sprintf(sname, "sp671");
        break;
    case P67_AUDIO_DIR_O:
        dir = PA_DIRECTION_OUTPUT;
        sprintf(name, "p672");
        sprintf(sname, "sp672");
        break;
    default:
        return p67_err_einval;
    }

    ss.format = fmt;
    ss.channels = hw->channels;
    ss.rate = hw->rate;

    attr.fragsize = hw->frame_size * hw->channels * fmt_bytes;
    if(dir == PA_DIRECTION_INPUT) {
        attr.maxlength = 5 * attr.fragsize;
        attr.minreq = (uint32_t)-1;
        attr.prebuf = (uint32_t)-1;
        attr.tlength = (uint32_t)-1;
    } else {
        attr.prebuf = 10 * attr.fragsize;
        attr.tlength = 5 * attr.fragsize;
        attr.minreq = (uint32_t)-1;
        attr.maxlength = (uint32_t)-1;
    }

    hw->__hw = pa_simple_new(
        NULL,               /* pulseaudio server */ 
        name,        
        dir,                /* I/O */ 
        hw->name,           /* device name */
        sname, 
        &ss,                /* ctx */
        NULL,  
        &attr, //dir == PA_DIRECTION_INPUT ? &attr : NULL, /* buffer attributes */ 
        &err);

    if(err != 0) {
        p67_audio_err = err;
        return p67_err_eaudio;
    }

    return 0;
}

p67_err
p67_audio_create_buff(p67_audio_t * h, void ** buf, int * buffl)
{   
    int bl=P67_AUDIO_BUFFER_SIZE(*h);
    if(buffl != NULL)
        *buffl = bl;
    if(buf != NULL)
        if((*buf = malloc(bl)) == NULL) return p67_err_eerrno;
    return 0;
}

void
p67_audio_codecs_destroy(p67_audio_codecs_t * cptr)
{
    switch(cptr->audio_dir) {
    case P67_AUDIO_DIR_I:
        if(cptr->opus.enc != NULL)
            opus_encoder_destroy(cptr->opus.enc);
        break;
    case P67_AUDIO_DIR_O:
        if(cptr->opus.dec != NULL)
            opus_decoder_destroy(cptr->opus.dec);
        break;
    default:
        break;
    }

    free(cptr->__tmpbuf);
}

p67_err
p67_audio_codecs_create(p67_audio_codecs_t * cptr)
{
    if(cptr->audio_fmt != P67_AUDIO_FMT_S16LE)
        return p67_err_einval;

    switch(cptr->audio_dir) {
    case P67_AUDIO_DIR_I:
        cptr->opus.enc = opus_encoder_create(
                    cptr->rate, 
                    cptr->channels, 
                    OPUS_APPLICATION_AUDIO,
                    p67_audio_codecs_error_location());
        opus_encoder_ctl(
            cptr->opus.enc, 
            OPUS_SET_BITRATE(cptr->rate * P67_AUDIO_FMT_S16LE_BITS_PER_SAMPLE * cptr->channels));
        break;
    case P67_AUDIO_DIR_O:
        cptr->opus.dec = opus_decoder_create(
                    cptr->rate, 
                    cptr->channels,
                    p67_audio_codecs_error_location());
        break;
    default:
        return p67_err_einval;
    }

    if(p67_audio_codecs_err != 0)
        return p67_err_eacodecs;
    cptr->__tmpbuf = malloc(cptr->channels * cptr->frame_size * P67_AUDIO_FMT_S16LE_BYTES_PER_SAMPLE);
    if(cptr->__tmpbuf == NULL) {
        p67_audio_codecs_destroy(cptr);
        return p67_err_eerrno;
    }

    return 0;
}

p67_err
p67_audio_codecs_encode(
            p67_audio_codecs_t * cptr, 
            const unsigned char * decompressed_frame,
            unsigned char * compressed_frame, 
            int * outsize)
{
    int ix;
    opus_int16 * tb = (opus_int16 *)cptr->__tmpbuf;

    for (ix=0;ix<cptr->frame_size*cptr->channels;ix++) {
        tb[ix] = decompressed_frame[P67_AUDIO_FMT_S16LE_BYTES_PER_SAMPLE*ix+1]<<8 | 
                 decompressed_frame[P67_AUDIO_FMT_S16LE_BYTES_PER_SAMPLE*ix];
    }

    *outsize = opus_encode(
                    cptr->opus.enc, 
                    tb, 
                    cptr->frame_size, 
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

p67_err
p67_audio_codecs_decode(
            p67_audio_codecs_t * cptr, 
            const unsigned char * compressed_frame, int csize,
            unsigned char * decompressed_frame)
{
    int ix, err = 0;
    opus_int16 * tb = (opus_int16 *)cptr->__tmpbuf;

    if((err = opus_decode(
                cptr->opus.dec, 
                compressed_frame, 
                csize, 
                tb, 
                cptr->frame_size, 
                compressed_frame == NULL ? 1 : 0)) < 0) {
        p67_audio_codecs_err = err;
        return p67_err_eacodecs;
    }

    for(ix=0;ix<cptr->frame_size*cptr->channels;ix++) {
        decompressed_frame[P67_AUDIO_FMT_S16LE_BYTES_PER_SAMPLE*ix] = tb[ix]&0xFF;
        decompressed_frame[P67_AUDIO_FMT_S16LE_BYTES_PER_SAMPLE*ix+1] = (tb[ix]>>8)&0xFF;
    }

    return 0;
}

p67_err
p67_audio_write_qdp(
    p67_addr_t * addr,
    p67_audio_t * input, 
    p67_audio_codecs_t * encoder, 
    uint8_t utp)
{
    p67_qdp_hdr_t hdr;
    p67_qdp_hdr_align_zero(hdr.__align);
    hdr.qdp_utp = utp;
    hdr.qdp_stp = P67_DML_STP_QDP_DAT;
    p67_err err = 0;
    unsigned char compressed_frame[sizeof(hdr)+P67_AUDIO_MAX_CFRAME_SZ];
    unsigned char decompressed_frame[P67_AUDIO_BUFFER_SIZE(*input)];
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
        if((err = p67_audio_read(
                input, decompressed_frame, sizeof(decompressed_frame))) != 0) 
            goto end;

        cb = P67_AUDIO_MAX_CFRAME_SZ;
        
        if((err = p67_audio_codecs_encode(
                encoder, decompressed_frame, compressed_frame+sizeof(hdr), &cb)) != 0)
           goto end;

        hdr.qdp_seq = htonl(seq++);
        memcpy(compressed_frame, &hdr, sizeof(hdr));

        if((err = p67_net_write_msg(
                addr, compressed_frame, cb+sizeof(hdr))) != 0) 
            goto end;
        if((err = p67_net_write_msg(
                addr, compressed_frame, cb+sizeof(hdr))) != 0) 
            goto end;
    }

end:
    return err;
}

p67_err
p67_audio_read_qdp(
    p67_qdp_ctx_t * s,
    p67_audio_t * output, 
    p67_audio_codecs_t * decoder)
{
    p67_err err = 0;
    unsigned char compressed_frame[P67_AUDIO_MAX_CFRAME_SZ];
    int dsz = P67_AUDIO_BUFFER_SIZE(*output);
    unsigned char decompressed_frame[dsz];
    int st;

    int interval = ((output->frame_size * 1e6) / output->rate) / 2;
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
                decoder, 
                err == p67_err_eagain ? NULL : compressed_frame, 
                size,  
                decompressed_frame)) != 0) goto end;

        if((err = p67_audio_write(
                output, decompressed_frame, dsz)) != 0) goto end;
    }

end:
    return err;
}
