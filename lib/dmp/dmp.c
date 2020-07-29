#include "dmp.h"

const p67_dmp_hdr_store_t *
p67_dmp_parse_hdr(
    const unsigned char * const msg,
    const int msg_size, 
    p67_err * err)
{
    p67_dmp_hdr_store_t * hdr;
    p67_err __err = 0;
    uint16_t stp;

    // assign val to the __err variable and jump to the end if cnd is true
    #define ejmp(cnd, val) \
            if(cnd) { __err = val; goto end; }

    ejmp(msg == NULL, p67_err_einval);

    hdr = (p67_dmp_hdr_store_t *)msg;

    ejmp((long unsigned)msg_size < sizeof(hdr->cmn), p67_err_epdpf);

    stp = p67_cmn_ntohs(hdr->cmn.cmn_stp);

    switch(stp) {
    case P67_DMP_STP_PDP_ACK:
        ejmp((long unsigned)msg_size < sizeof(hdr->ack), p67_err_epdpf);
        break;
    case P67_DMP_STP_PDP_URG:
        ejmp((long unsigned)msg_size < sizeof(hdr->urg), p67_err_epdpf);
        break;
    case P67_DMP_STP_DAT:
        ejmp((long unsigned)msg_size < sizeof(hdr->dat), p67_err_epdpf);
        break;
    default:
        ejmp(1, p67_err_epdpf);
    }

end:
    if(__err != 0) {
        if(err != NULL) 
            *err = __err;
        return NULL;
    }

    return hdr;
}

p67_err
p67_dmp_handle_msg(
    p67_conn_t * conn, 
    const char * msg, int msgl, 
    void * args)
{
    (void)args;
    p67_err err = 0;
    int wh = 0;
    const p67_dmp_hdr_store_t * msg_hdr;
    uint16_t stp;

    if((msg_hdr = p67_dmp_parse_hdr(
                (unsigned char *)msg, msgl, NULL)) == NULL)
        return p67_err_epdpf;

    stp = p67_cmn_ntohs(msg_hdr->cmn.cmn_stp);

    switch(stp) {
    case P67_DMP_STP_PDP_ACK:
        /* ACKs remove URG messages from pending queue */
        err = p67_dmp_pdp_urg_remove(p67_cmn_ntohl(msg_hdr->ack.ack_mid));
        break;
    case P67_DMP_STP_PDP_URG:
        err = p67_dmp_pdp_write_ack_for_urg(conn, &msg_hdr->urg);
        break;
    case P67_DMP_STP_DAT:
        /* DATs are ignored */
        break;
    default:
        err = p67_err_einval;
        break;
    }

    if(err != 0){
        p67_err_print_err("ERR in pudp handle message: ", err);
        return 0;
    }

    if(wh == 1)
        return 0;

    // signal that message still needs to be processed.
    return p67_err_eagain;
}

