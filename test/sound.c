#include <p67/pcm.h>
#include <p67/err.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#define rjmp(cnd, err, val, lbl) if(cnd) { err = val; goto lbl; }  

int
run_music(const char * wavpath)
{
    p67_pcm_t out = P67_PCM_INTIIALIZER_OUT;
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
    char * fc = NULL;
    size_t fcl = 0, c = 0, wr = 0;
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
            if(fc == NULL) {
                rjmp((fc = malloc(chunk.len)) == NULL, err, p67_err_eerrno, end);
                rd = read(mfd, fc, chunk.len);
            }
            else {
                rjmp((fc = realloc(fc, fcl+chunk.len)) == NULL, err, p67_err_eerrno, end);
                rd = read(mfd, fc+fcl, chunk.len);
            }
            fcl += chunk.len;
            rjmp(rd < 0, err, p67_err_eerrno, end);
            rjmp(rd == 0 || rd != chunk.len, err, p67_err_einval, end);
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

    close(mfd);

    out.channels = fmt.channels;
    out.sampling = fmt.samples_per_sec;
    out.bits_per_sample = fmt.bitsPerSample;

    if((err = p67_pcm_create_io(&out)) != 0) goto end;

    do {
        if(wr <= 0) wr = out.frame_size;
        if((err = p67_pcm_write(&out, fc+c, &wr)) != 0 && err != p67_err_eagain)
            goto end;
        c+=wr*out.channels*out.bits_per_sample/8;
    } while(c < fcl);///

end:
    p67_pcm_free(&out);
    if(fc != NULL) free(fc);
    if(mfd > 0) close(mfd);
    if(err != 0) p67_err_print_err(NULL, err);
    return err == 0 ? 0 : 2;
}

int
run_echo()
{
    p67_err err = 0;
    p67_pcm_t in = P67_PCM_INTIIALIZER_IN, out = P67_PCM_INTIIALIZER_OUT;
    char * buff = NULL;
    size_t rd;

    if((err = p67_pcm_create_io(&in)) != 0) goto end;
    if((err = p67_pcm_create_io(&out)) != 0) goto end;

    if(!p67_pcm_in_sync(in, out)) {
        printf("pcm devices not synced.\n");
        err = p67_err_einval;
        goto end;
    }

    if((buff = malloc(p67_pcm_buff_size(in))) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }

    while(1) {
        rd = in.frame_size;
        if((err = p67_pcm_read(&in, buff, &rd)) != 0 && err != p67_err_eagain)
            goto end;
        if((err = p67_pcm_write(&out, buff, &rd)) != 0 && err != p67_err_eagain)
            goto end;
    }

end:
    if(buff != NULL) free(buff);
    if(err != 0) p67_err_print_err(NULL, err);
    p67_pcm_free(&in);
    p67_pcm_free(&out);
    return err == 0 ? 0 : 2;
}

int
main(int argc, char ** args)
{
    switch(argc) {
    case 1:
    default:
        return run_echo();
    case 2:
        return run_music(args[1]);
    }
    
}