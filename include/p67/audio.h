#if !defined(P67_AUDIO_H)
#define P67_AUDIO_H 1

#include <stdint.h>

#include <pulse/simple.h>
#include <pulse/error.h>
#include <opus/opus.h>
#include <p67/dml/qdp.h>
#include <p67/err.h>

typedef int p67_audio_codecs_err_t; 
typedef int p67_audio_err_t;

typedef pa_stream_direction_t p67_audio_dir_t;

p67_audio_err_t *
p67_audio_error_location(void);

p67_audio_codecs_err_t *
p67_audio_codecs_error_location(void);

#define P67_AUDIO_DIR_I PA_STREAM_RECORD
#define P67_AUDIO_DIR_O PA_STREAM_PLAYBACK

#define p67_audio_err (*p67_audio_error_location())
#define p67_audio_codecs_err (*p67_audio_codecs_error_location())

#define P67_AUDIO_DEFAULT_CHANNELS   2
#define P67_AUDIO_DEFAULT_RATE       48000
#define P67_AUDIO_DEFAULT_FRAME_SIZE 120

#define p67_audio_drain(h) pa_simple_drain((h).__hw)

#define p67_audio_strerror() pa_strerror(p67_audio_err)

typedef struct p67_audio_fmt_info p67_audio_fmt_info_t;

struct p67_audio_fmt_info {
    int id;
    int bits_per_sample;
};

#define p67_audio_fmt_bytes_per_sample(fmt_ptr) \
    ((fmt_ptr)->bits_per_sample / 8)

extern const p67_audio_fmt_info_t p67_audio_fmts[];

#define P67_AUDIO_FMT_S16LE (p67_audio_fmts)

typedef struct p67_audio_config {
    const p67_audio_fmt_info_t * fmt;
    uint8_t channels;
    uint32_t rate;
    int frame_size;
} p67_audio_config_t;

typedef struct p67_audio p67_audio_t;

#define p67_audio_create_i(name, config) \
    p67_audio_create(P67_AUDIO_DIR_I, name, config)

#define p67_audio_create_o(name, config) \
    p67_audio_create(P67_AUDIO_DIR_O, name, config)

p67_audio_t * 
p67_audio_create(
    p67_audio_dir_t dir, const char * name, const p67_audio_config_t * config);

p67_err
p67_audio_create_buff(p67_audio_t * h, void ** buf, int * buffl);

void
p67_audio_free(p67_audio_t * audio);

#define p67_audio_config_buffer_size(config_ptr)        \
     (   ((config_ptr)->fmt->bits_per_sample / 8) *       \
         (config_ptr)->channels *                         \
         (config_ptr)->frame_size                         \
     )

#define p67_audio_config_cpy_with_defaults(src_ptr, dst_val) \
    {   \
        (dst_val).channels = (src_ptr) ?  \
            (src_ptr)->channels : P67_AUDIO_DEFAULT_CHANNELS; \
        (dst_val).fmt = (src_ptr) ?                            \
            (src_ptr)->fmt : P67_AUDIO_FMT_S16LE;                      \
        (dst_val).frame_size = (src_ptr) ?                     \
            (src_ptr)->frame_size : P67_AUDIO_DEFAULT_FRAME_SIZE;      \
        (dst_val).rate = (src_ptr) ?                           \
            (src_ptr)->rate : P67_AUDIO_DEFAULT_RATE;              \
    }

#define p67_audio_rw_terminate(tsm) p67_thread_sm_terminate(tsm, 100)

/*
#define p67_audio_config_buffer_size(config_val)        \
     (   ((config_val).fmt->bits_per_sample / 8) *       \
         (config_val).channels *                         \
         (config_val).frame_size                         \
     )
    
int
p67_audio_config_buffer_size(const p67_audio_config_t * config);

*/

p67_audio_t *
p67_audio_refcpy(p67_audio_t * audio);

p67_err
p67_audio_write_qdp(
    p67_thread_sm_t * tsm,
    p67_addr_t * addr,
    p67_audio_t * input,
    uint8_t utp);

p67_err
p67_audio_read_qdp(
    p67_thread_sm_t * tsm,
    p67_qdp_ctx_t * s,
    p67_audio_t * output);

p67_err
p67_audio_start_read_qdp(
        p67_thread_sm_t * tsm,
        p67_qdp_ctx_t * s,
        p67_audio_t * output);

p67_err
p67_audio_start_write_qdp(
        p67_thread_sm_t * tsm,
        p67_addr_t * addr,
        p67_audio_t * input,
        uint8_t utp);

#define p67_audio_err_mask \
    (p67_err_eaudio | p67_err_eacodecs | p67_err_eerrno)

#endif
