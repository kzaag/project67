#if !defined(P67_ERR)
#define P67_ERR 1

#define p67_err_mask_all(err) { err = (p67_err_essl | p67_err_eerrno); }

enum p67_err {
    /* no error */
    p67_err_eok = 0,
    p67_err_essl = 1,    /* error in ssl */
    p67_err_eerrno = 2,  /* syscall ( linux / unix ) */
    p67_err_einval = 4,  /* argument */
    p67_err_eaconn = 8,  /* already connected */
    p67_err_enconn = 16, /* connection gone */
    p67_err_enetdb  = 32  /* getaddrinfo */
};

typedef enum p67_err p67_err;

void
p67_err_print_err(p67_err err);

#define p67_err_print_all() p67_err_print_err(p67_err_essl | p67_err_eerrno)

#endif
