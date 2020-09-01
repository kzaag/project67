#include <errno.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

#include <p67/audio.h>
#include <p67/err.h>

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
            p67_errlog("%s%s\n", hdr, errbuf);
            sslp = 1;
        }
        if(sslp == 0) p67_errlog("%sUnknown OpenSSL error.\n", hdr); 
    }

    if((err & p67_err_eerrno) && errno != 0) {
        p67_errlog("%sErrno: %s\n", hdr, strerror(errno));
    }

    if(err & p67_err_einval) {
        p67_errlog("%sInvalid argument\n", hdr);
    }

    if(err & p67_err_eaconn) {
        p67_errlog("%sAlready connected\n", hdr);
    }

    if(err & p67_err_enconn) {
        p67_errlog("%sConnection gone\n", hdr);
    }

    if(err & p67_err_enetdb) {
        p67_errlog("%sCouldnt obtain address information\n", hdr);
    }

    if(err & p67_err_easync) {
        p67_errlog("%sAsync state changed\n", hdr);
    }

    if(err & p67_err_etime) {
        p67_errlog("%sTimeout\n", hdr);
    }

    if(err & p67_err_eint) {
        p67_errlog("%sOperation has been interrupted\n", hdr);
    }
    
    if(err & p67_err_eaudio) {
        if(p67_audio_err != 0) {
            p67_errlog("%s%s\n", hdr, p67_audio_strerror());
        } else {
            p67_errlog("%sUnkown audio error\n", hdr);
        }
    }

    if(err & p67_err_epipe) {
        p67_errlog("%sBroken pipe\n", hdr);
    }

    if(err & p67_err_eagain) {
        p67_errlog("%sResource temporarily unavailable\n", hdr);
    }

    if(err & p67_err_enomem) {
        p67_errlog("%sBuffer too small\n", hdr);
    }

    if(err & p67_err_eacodecs) {
        if(p67_audio_codecs_err != 0) {
            p67_errlog("%s%s\n", hdr, opus_strerror(p67_audio_codecs_err));
        } else {
            p67_errlog("%sUnkown audio codecs error\n", hdr);
        }
    }

    if(err & p67_err_etlvf) {
        p67_errlog("%sInvalid TLV format\n", hdr);
    }

    if(err & p67_err_eot) {
        p67_errlog("%sEnd of transmission\n", hdr);
    }

    if(err & p67_err_epdpf) {
        p67_errlog("%sInvalid pudp format\n", hdr);
    }

}
