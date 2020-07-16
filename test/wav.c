#include <p67/audio.h>
#include <p67/err.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include "wav.h"

/*
    it would be much better to not load whole file at once and read it in chunks. 
    should add support for this here
*/
p67_err
get_p67_pcm_from_wav_file(
    p67_audio_t * out, 
    off_t * data_offset,
    char ** fc, size_t * cl, 
    const char * wavpath)
{
    if(cl != NULL) *cl = 0;
    if(fc != NULL) *fc = NULL;

    struct __attribute__((packed)) {
        char id[4];
        unsigned int len;
        char type[4];
    } wavhdr;
    struct __attribute__((packed)) {
        char id[4];
        unsigned int len;
    } chunk;
    struct __attribute__((packed)) {
        short           tag;
        unsigned short	channels;
	    unsigned int	samples_per_sec;
	    unsigned int	avgBytes;
	    unsigned short	align;
	    unsigned short	bitsPerSample;
    } fmt;
    ssize_t rd;
    const char * wave = "WAVE";
    p67_err err;
    int iffidl = 4, mfd = 0;

    if((mfd = open(wavpath, O_RDONLY, 0)) < 0) {
        err = p67_err_eerrno;
        goto end;
    }


    /* lseek(mfd, 44, 0); */
    rd = read(mfd, (void *)&wavhdr, sizeof(wavhdr));
    rjmp(rd < 0, err, p67_err_eerrno, end);
    rjmp(rd == 0 || rd != sizeof(wavhdr), err, p67_err_einval, end);
    rjmp(memcmp(wavhdr.id, "RIFF", 4) != 0, err, p67_err_einval, end);
    rjmp(memcmp(wavhdr.type, "WAVE", 4) != 0, err, p67_err_einval, end);

    while(1) {
        rd = read(mfd, (void *)&chunk, sizeof(chunk));
        if(rd == 0) break;
        rjmp(rd < 0, err, p67_err_eerrno, end);
        rjmp(rd != sizeof(chunk), err, p67_err_einval, end);
        if(memcmp(chunk.id, "data", 4) == 0) {
            if(fc != NULL && cl != NULL) {
                if(*fc == NULL) {
                    rjmp((*fc = malloc(chunk.len)) == NULL, err, p67_err_eerrno, end);
                    rd = read(mfd, *fc, chunk.len);
                }
                else {
                    rjmp((*fc = realloc(*fc, *cl+chunk.len)) == NULL, err, p67_err_eerrno, end);
                    rd = read(mfd, *fc+*cl, chunk.len);
                }
                *cl += chunk.len;
                rjmp(rd < 0, err, p67_err_eerrno, end);
                rjmp(rd == 0 || rd != chunk.len, err, p67_err_einval, end);
            } else if(data_offset != NULL) {
                *data_offset = lseek(mfd, 0, 1);
                rjmp(*data_offset < 0, err, p67_err_eerrno, end);
            }
        } else if(memcmp(chunk.id, "fmt", 3) == 0 && sizeof(fmt) <= chunk.len) {
            rd = read(mfd, &fmt, sizeof(fmt));
            rjmp(rd < 0, err, p67_err_eerrno, end);
            rjmp(rd == 0 || rd != sizeof(fmt), err, p67_err_einval, end);
            rjmp(fmt.tag != 1, err, p67_err_eerrno, end);
            if(sizeof(fmt) < chunk.len) {
                rd = lseek(mfd, chunk.len, chunk.len-sizeof(fmt));
                rjmp(rd == -1, err, p67_err_eerrno, end);
            }
        } else {
            //if(chunk.len & 1) chunk.len++;
            rd = lseek(mfd, chunk.len, 1);
            rjmp(rd == -1, err, p67_err_eerrno, end);
        }
    }


    rjmp(fc != NULL && *fc == NULL, err, p67_err_einval, end);

    close(mfd);

    out->channels = fmt.channels;
    out->rate = fmt.samples_per_sec;
    out->bytes_per_sample = fmt.bitsPerSample / 8;
    out->audio_dir = P67_AUDIO_DIR_O;

    if((err = p67_audio_create_io(out)) != 0) goto end;

end:
    if(err != 0) {
        if(fc != NULL && *fc != NULL) free(*fc);
        if(mfd > 0) close(mfd);
    }
    return err;
}