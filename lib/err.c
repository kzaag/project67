#include <errno.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include "audio.h"

#include "err.h"

void
p67_err_print_err(const char * hdr, p67_err err)
{
    unsigned long sslerr;
    char errbuf[128];
    char fb = 0;
    int sslp;

    if(hdr == NULL) hdr = &fb;

    if(err == p67_err_eok) return;
    
    sslp = 0;
    if(err & p67_err_essl) {
        while((sslerr = ERR_get_error()) != 0) {
            ERR_error_string_n(sslerr, errbuf, 128);
            fprintf(stderr, "%s%s\n", hdr, errbuf);
            sslp = 1;
        }
        if(sslp == 0) fprintf(stderr, "%sUnknown OpenSSL error.\n", hdr); 
    }

    if((err & p67_err_eerrno) && errno != 0) {
        fprintf(stderr, "%sErrno: %s\n", hdr, strerror(errno));
    }

    if(err & p67_err_einval) {
        fprintf(stderr, "%sInvalid argument\n", hdr);
    }

    if(err & p67_err_eaconn) {
        fprintf(stderr, "%sAlready connected\n", hdr);
    }

    if(err & p67_err_enconn) {
        fprintf(stderr, "%sConnection gone\n", hdr);
    }

    if(err & p67_err_enetdb) {
        fprintf(stderr, "%sCouldnt obtain address information\n", hdr);
    }

    if(err & p67_err_easync) {
        fprintf(stderr, "%sAsync state changed\n", hdr);
    }

    if(err & p67_err_etime) {
        fprintf(stderr, "%sTimeout\n", hdr);
    }

    if(err & p67_err_eint) {
        fprintf(stderr, "%sOperation has been interrupted\n", hdr);
    }
    
    if(err & p67_err_eaudio) {
        if(p67_audio_err != 0) {
            fprintf(stderr, "%s%s\n", hdr, p67_audio_strerror());
        } else {
            fprintf(stderr, "%sUnkown audio error\n", hdr);
        }
    }

    if(err & p67_err_epipe) {
        fprintf(stderr, "%sBroken pipe\n", hdr);
    }

    if(err & p67_err_eagain) {
        fprintf(stderr, "%sResource temporarily unavailable\n", hdr);
    }

    if(err & p67_err_enomem) {
        fprintf(stderr, "%sBuffer too small\n", hdr);
    }

    if(err & p67_err_eacodecs) {
        if(p67_audio_codecs_err != 0) {
            fprintf(stderr, "%s%s\n", hdr, opus_strerror(p67_audio_codecs_err));
        } else {
            fprintf(stderr, "%sUnkown audio codecs error\n", hdr);
        }
    }

    if(err & p67_err_etlvf) {
        fprintf(stderr, "%sInvalid TLV format\n", hdr);
    }

    if(err & p67_err_eot) {
        fprintf(stderr, "%sEnd of transmission\n", hdr);
    }

    if(err & p67_err_epdpf) {
        fprintf(stderr, "%sInvalid pudp format\n", hdr);
    }

}
