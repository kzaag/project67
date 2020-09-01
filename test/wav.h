#if !defined(WAV_H)
#define WAV_H

#include <p67/audio.h>

#define rjmp(cnd, err, val, lbl) if(cnd) { err = val; goto lbl; }  

p67_err
get_p67_pcm_from_wav_file(
    p67_audio_t * out, 
    off_t * dataOffset,
    char ** fc, size_t * cl, 
    const char * wavpath);

#endif