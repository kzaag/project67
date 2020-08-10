#if !defined P67_STREAM_H
#define P67_STREAM_H 1

#include "../err.h"

typedef struct p67_audio_stream p67_audio_stream_t;

p67_err
p67_audio_stream_create(p67_audio_stream_t ** s);

p67_err
p67_audio_stream_write(p67_audio_stream_t * s, p67_conn_pass_t * pass);

p67_err
p67_audio_stream_read(p67_audio_stream_t * s);

void
p67_audio_stream_free(p67_audio_stream_t * s);

p67_err
stream_read_callback(
        p67_conn_t * conn, const char * msg, int msgl, void * args);

#endif
