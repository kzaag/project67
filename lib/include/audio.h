#if !defined(P67_AUDIO_H)
#define P67_AUDIO_H 1

#include <pulse/simple.h>
#include <pulse/error.h>
#include <opus/opus.h>

#include "err.h"
#include "sfd.h"
#include "dml/qdp.h"

/*
    using pulseaudio allows user to control hw in much more stable way than with alsa, 
    but pulseaudio is really slow thus creates delay of about 70miliseconds just by iteself.
    combined that with our jitter buffer, this is really poor solution. 
    we should consider implementing and supporting low-level audio library
         such as alsa, or xplatform ports - portaudio, libsoundio
*/

/* max compressed frame size */
#define P67_AUDIO_MAX_CFRAME_SZ 1276

#define P67_AUDIO_FMT_S16LE 1
#define P67_AUDIO_FMT_S16LE_BITS_PER_SAMPLE 16
#define P67_AUDIO_FMT_S16LE_BYTES_PER_SAMPLE 2

#define P67_AUDIO_DIR_I 1
#define P67_AUDIO_DIR_O 2

#define P67_AUDIO_DEFAULT_CHANNELS   2
#define P67_AUDIO_DEFAULT_RATE       48000
#define P67_AUDIO_DEFAULT_FRAME_SIZE 120

typedef struct p67_audio {
    int audio_dir;
    const char * name;
    int audio_fmt;
    uint8_t channels;
    uint32_t rate;
    int frame_size;
    int bytes_per_sample;

    pa_simple * __hw;
} p67_audio_t;

#define P67_AUDIO_INITIALIZER_I {                     \
            .audio_dir=P67_AUDIO_DIR_I,             \
            .name=NULL,                             \
            .audio_fmt=P67_AUDIO_FMT_S16LE,             \
            .channels=P67_AUDIO_DEFAULT_CHANNELS,        \
            .rate=P67_AUDIO_DEFAULT_RATE,                \
            .frame_size=P67_AUDIO_DEFAULT_FRAME_SIZE, \
            .bytes_per_sample=P67_AUDIO_FMT_S16LE_BYTES_PER_SAMPLE, \
            .__hw = NULL,                                \
        }

#define P67_AUDIO_INITIALIZER_O {                     \
            .audio_dir=P67_AUDIO_DIR_O,             \
            .name=NULL,                             \
            .audio_fmt=P67_AUDIO_FMT_S16LE,             \
            .channels=P67_AUDIO_DEFAULT_CHANNELS,        \
            .rate=P67_AUDIO_DEFAULT_RATE,                \
            .frame_size=P67_AUDIO_DEFAULT_FRAME_SIZE, \
            .bytes_per_sample=P67_AUDIO_FMT_S16LE_BYTES_PER_SAMPLE, \
            .__hw = NULL,                                \
        }

#define P67_AUDIO_BUFFER_SIZE(h) \
    (((h).bytes_per_sample * (h).channels * (h).frame_size))

typedef int p67_audio_err_t;

p67_audio_err_t *
p67_audio_error_location(void);

p67_audio_err_t *
p67_audio_codecs_error_location(void);

#define p67_audio_err (*p67_audio_error_location())
#define p67_audio_codecs_err (*p67_audio_codecs_error_location())

p67_err
p67_audio_create_io(p67_audio_t * h);

#define p67_audio_read(hptr, buff, buffl) \
    (pa_simple_read((hptr)->__hw, (buff), (buffl), p67_audio_error_location()) < 0 ? p67_err_eaudio : 0)

#define p67_audio_write(hptr, buff, buffl) \
    (pa_simple_write((hptr)->__hw, (buff), (buffl), p67_audio_error_location()) < 0 ? p67_err_eaudio : 0)

p67_err
p67_audio_create_buff(p67_audio_t * h, void ** buff, int * buffl);

#define p67_audio_free_hw(h) pa_simple_free((h).__hw)

#define p67_audio_drain(h) pa_simple_drain((h).__hw)

#define p67_audio_strerror() pa_strerror(p67_audio_err)


union p67_codecs_opus {
    OpusEncoder * enc;
    OpusDecoder * dec;
};

#define P67_CODECS_DIR_ENCODER 1
#define P67_CODECS_DIR_DECODER 2

/*
    not meant to be used in multithreaded environment 
    (__tmpbuf is shared and used during encode / decode)
*/
typedef struct p67_audio_codecs {
    union p67_codecs_opus opus;
    int audio_dir;
    int audio_fmt;
    uint8_t channels;
    uint32_t rate;
    int frame_size;
    void * __tmpbuf;
} p67_audio_codecs_t;

#define P67_AUDIO_CODECS_INITIALIZER_ENCODER { \
    .opus.enc = NULL, \
    .audio_dir=P67_AUDIO_DIR_I, \
    .audio_fmt=P67_AUDIO_FMT_S16LE, \
    .channels=P67_AUDIO_DEFAULT_CHANNELS, \
    .rate=P67_AUDIO_DEFAULT_RATE, \
    .frame_size=P67_AUDIO_DEFAULT_FRAME_SIZE, \
}

#define P67_AUDIO_CODECS_INITIALIZER_DECODER { \
    .opus.enc = NULL, \
    .audio_dir=P67_AUDIO_DIR_O, \
    .audio_fmt=P67_AUDIO_FMT_S16LE, \
    .channels=P67_AUDIO_DEFAULT_CHANNELS, \
    .rate=P67_AUDIO_DEFAULT_RATE, \
    .frame_size=P67_AUDIO_DEFAULT_FRAME_SIZE, \
}

#define P67_AUDIO_CODECS_INITIALIZER_AUDIO(hv) { \
    .opus.enc = NULL, \
    .audio_dir=hv.audio_dir, \
    .audio_fmt=hv.audio_fmt, \
    .channels=hv.channels, \
    .rate=hv.rate, \
    .frame_size=hv.frame_size \
}

p67_err
p67_audio_codecs_create(p67_audio_codecs_t * cptr);

void
p67_audio_codecs_destroy(p67_audio_codecs_t * cptr);

p67_err
p67_audio_codecs_encode(
            p67_audio_codecs_t * cptr, 
            const unsigned char * decompressed_frame,
            unsigned char * compressed_frame, 
            int * outsize);

p67_err
p67_audio_codecs_decode(
            p67_audio_codecs_t * cptr, 
            const unsigned char * compressed_frame, int csize,
            unsigned char * decompressed_frame);

/*
    stream audio to the remote
*/
p67_err
p67_audio_write_qdp(
    p67_addr_t * addr,
    p67_audio_t * input, 
    p67_audio_codecs_t * encoder, 
    uint8_t utp);

/*
    accept incoming stream and play it back
*/
p67_err
p67_audio_read_qdp(
    p67_qdp_ctx_t * s,
    p67_audio_t * output, 
    p67_audio_codecs_t * decoder);

#endif