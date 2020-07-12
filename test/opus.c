#include <opus/opus.h>
#include <p67/pcm.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

int
main()
{
    int ix;

    const int OPUS_INT_SIZE=2;
    const int FRAME_SIZE = 120;
    const int MAX_FRAME_SIZE=1276;
    const int CHANNELS=2;
    int buffering = 0;
    opus_int16 input_frame[FRAME_SIZE*CHANNELS];
    opus_int16 output_frame[FRAME_SIZE*CHANNELS];
    unsigned char compressed_frame[MAX_FRAME_SIZE];
    unsigned char decompressed_frame[FRAME_SIZE*OPUS_INT_SIZE*CHANNELS];

    opus_int32 cb;
    p67_err err;

    p67_pcm_t i = P67_PCM_INTIIALIZER_IN, o = P67_PCM_INTIIALIZER_OUT;

    i.frame_size = FRAME_SIZE;
    o.frame_size = i.frame_size;
    i.bits_per_sample = 16;
    o.bits_per_sample = i.bits_per_sample;
    i.channels = CHANNELS;
    o.channels = i.channels;
    i.sampling = 48000;
    o.sampling = i.sampling;

    OpusEncoder * enc = opus_encoder_create(i.sampling, i.channels, OPUS_APPLICATION_AUDIO, &cb);
    OpusDecoder * dec = opus_decoder_create(i.sampling, i.channels, &cb);

    if(opus_encoder_ctl(enc, OPUS_SET_PACKET_LOSS_PERC(10)) != OPUS_OK) {
        printf("no1\n");
    }

    opus_encoder_ctl(enc, OPUS_SET_BITRATE(i.sampling * 16 * i.channels));

    p67_pcm_create_io(&i);
    p67_pcm_create_io(&o);

    p67_pcm_recover(&i);

    static int c = 0;

    while(1) {
        p67_pcm_read(&i, decompressed_frame, &(size_t){FRAME_SIZE});

        // if(!(c++ % 10)) {
        //     bzero(decompressed_frame, FRAME_SIZE*CHANNELS*2);
        //     err = p67_pcm_write(&o, decompressed_frame, &(size_t){FRAME_SIZE});
        //     continue;   
        // }

        for (ix=0;ix<FRAME_SIZE*CHANNELS;ix++) 
            input_frame[ix]=decompressed_frame[OPUS_INT_SIZE*ix+1]<<8|decompressed_frame[OPUS_INT_SIZE*ix];
        cb = opus_encode(enc, input_frame, FRAME_SIZE, compressed_frame, MAX_FRAME_SIZE);
        if(!(c++ % 10)) {
        //     //cb = opus_decode(dec, compressed_frame, cb, input_frame, FRAME_SIZE, 1);
             cb = opus_decode(dec, NULL, 0, input_frame, FRAME_SIZE, 0);
        //     //buffering = 0;
        } else {
        memset(compressed_frame+cb, 0, MAX_FRAME_SIZE-cb);
        cb = opus_decode(dec, compressed_frame, cb, input_frame, FRAME_SIZE, 0);
        }

        if(cb < 0) {
            break;
        }

        for(ix=0;ix<FRAME_SIZE*CHANNELS;ix++) {
            decompressed_frame[OPUS_INT_SIZE*ix]=input_frame[ix]&0xFF;
            decompressed_frame[OPUS_INT_SIZE*ix+1]=(input_frame[ix]>>8)&0xFF;
        }
        err = p67_pcm_write(&o, decompressed_frame, &(size_t){FRAME_SIZE});
        if(err == p67_err_epipe) {
            // buffering
            o.sampling = 44100;
            p67_pcm_update(&o);
            buffering = 1;
            printf("buffering\n");
        } else if(buffering) {
            o.sampling = 48000;
            p67_pcm_update(&o);
            buffering = 0;
            printf("recover\n");
        }
    }
}