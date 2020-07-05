#include <p67/pcm.h>
#include <p67/err.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include "wav.h"

int
run_music(const char * wavpath)
{
    p67_pcm_t out = P67_PCM_INTIIALIZER_OUT;
    p67_err err;
    long offset;
    size_t wr = 0, c = 0;
    size_t fcl = 0;
    char * fc = NULL;

    if((err = get_p67_pcm_from_wav_file(&out, NULL, &fc, &fcl, wavpath)) != 0)
        goto end;

    do {
        if(wr <= 0) wr = out.frame_size;
        if((err = p67_pcm_write(&out, fc+c, &wr)) != 0)
            goto end;
        c+=p67_pcm_act_size(out, wr);
    } while(c < fcl);

end:
    if(fc != NULL) free(fc);
    p67_pcm_free(&out);
    if(err != 0) p67_err_print_err(NULL, err);
    return err == 0 ? 0 : 2;
}

int
run_echo()
{
    p67_err err = 0;
    p67_pcm_t in = P67_PCM_INTIIALIZER_IN, out = P67_PCM_INTIIALIZER_OUT;
    //in.sampling = P67_PCM_SAMPLING_44_1K;
    //out.sampling = P67_PCM_SAMPLING_44_1K;
    char * buff = NULL;
    size_t rd;

    if((err = p67_pcm_create_io(&in)) != 0) goto end;
    if((err = p67_pcm_create_io(&out)) != 0) goto end;

    if(!p67_pcm_in_sync(in, out)) {
        printf("pcm devices not in sync.\n");
        err = p67_err_einval;
        goto end;
    }

    if((buff = malloc(p67_pcm_buff_size(in))) == NULL) {
        err = p67_err_eerrno;
        goto end;
    }

    while(1) {
        rd = in.frame_size;
        if((err = p67_pcm_read(&in, buff, &rd)) != 0)
            goto end;
        if((err = p67_pcm_write(&out, buff, &rd)) != 0)
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