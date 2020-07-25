#if !defined(P67_ERR)
#define P67_ERR 1

#define p67_err_mask_all(err) { err = (p67_err_essl | p67_err_eerrno); }

enum p67_err {
    /* no error */
    p67_err_eok    = 0,
    p67_err_essl   = 0x1,   /* error in ssl */
    p67_err_eerrno = 0x2,   /* syscall ( linux / unix ) */
    p67_err_einval = 0x4,   /* argument */
    p67_err_eaconn = 0x8,   /* already connected */
    p67_err_enconn = 0x10,  /* connection gone */
    p67_err_enetdb = 0x20,  /* getaddrinfo */
    p67_err_easync = 0x40,  /* async state changed */
    p67_err_etime  = 0x80, /* Timeout */
    p67_err_eint   = 0x100, /* Interrupted */
    p67_err_eaudio = 0x200,  /* audio fault*/
    p67_err_epipe = 0x400,  /* Broken pipe */
    p67_err_eagain = 0x800,  /* EAGAIN */
    p67_err_enomem = 0x1000,  /* not enough memory */
    p67_err_eacodecs = 0x2000,  /* audio codecs error */
    p67_err_etlvf = 0x4000,     /* invalid tlv format */
    p67_err_eot = 0x8000,   /* end of transmission */
    /* these values can be used for other libraries and executables to define their own errors and handlings */
    p67_err__prev__  = 0xFFFFF,
    p67_err__next__  = 0x100000
};

typedef enum p67_err p67_err;

void
p67_err_print_err(const char * hdr, p67_err err);

#define p67_err_print_all(hdr) p67_err_print_err(hdr, p67_err_essl | p67_err_eerrno)

#endif
