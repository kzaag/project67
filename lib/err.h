#if !defined(P67_ERR)
#define P67_ERR 1

#define p67_err_mask_all(err) { err = (p67_err_essl | p67_err_eerrno); }

enum p67_err {
    /* no error */
    p67_err_eok    = 0,
    p67_err_essl   = 1,   /* error in ssl */
    p67_err_eerrno = 2,   /* syscall ( linux / unix ) */
    p67_err_einval = 4,   /* argument */
    p67_err_eaconn = 8,   /* already connected */
    p67_err_enconn = 16,  /* connection gone */
    p67_err_enetdb = 32,  /* getaddrinfo */
    p67_err_easync = 64,  /* async state changed */
    p67_err_etime  = 128, /* Timeout */
    p67_err_eint   = 256, /* Interrupted */
    p67_err_epcm   = 512,  /* Sound hw / driver fault */
    p67_err_epipe = 1024,  /* Broken pipe */
    p67_err_eagain = 2048,  /* EAGAIN */
    p67_err_enomem = 4096  /* not enough memory */
};

typedef enum p67_err p67_err;

void
p67_err_print_err(const char * hdr, p67_err err);

#define p67_err_print_all(hdr) p67_err_print_err(hdr, p67_err_essl | p67_err_eerrno)

#endif
