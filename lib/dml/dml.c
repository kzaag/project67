#include "dml.h"

const p67_dml_hdr_store_t *
p67_dml_parse_hdr(
    const unsigned char * const msg,
    const int msg_size, 
    p67_err * err)
{
    p67_dml_hdr_store_t * hdr;
    p67_err __err = 0;

    // assign val to the __err variable and jump to the end if cnd is true
    #define ejmp(cnd, val) \
            if(cnd) { __err = val; goto end; }

    ejmp(msg == NULL, p67_err_einval);

    hdr = (p67_dml_hdr_store_t *)msg;

    ejmp((long unsigned)msg_size < sizeof(hdr->cmn), p67_err_epdpf);

    switch(hdr->cmn.cmn_stp) {
    case P67_DML_STP_PDP_ACK:
        ejmp((long unsigned)msg_size < sizeof(hdr->ack), p67_err_epdpf);
        break;
    case P67_DML_STP_PDP_URG:
        ejmp((long unsigned)msg_size < sizeof(hdr->urg), p67_err_epdpf);
        break;
    case P67_DML_STP_DAT:
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
p67_dml_handle_msg(
    p67_conn_t * conn, 
    const char * msg, int msgl, 
    void * args)
{
    (void)args;
    p67_err err = 0;
    int wh = 0;
    const p67_dml_hdr_store_t * msg_hdr;

    if((msg_hdr = p67_dml_parse_hdr(
                (unsigned char *)msg, msgl, NULL)) == NULL)
        return p67_err_epdpf;

    switch(msg_hdr->cmn.cmn_stp) {
    case P67_DML_STP_PDP_ACK:
    case P67_DML_STP_PDP_PACK:
        /* ACKs remove URG messages from pending queue */
        err = p67_pdp_urg_remove(
                p67_cmn_ntohs(msg_hdr->ack.ack_mid), 
                (unsigned char *)msg, msgl,
                msg_hdr->cmn.cmn_stp == P67_DML_STP_PDP_PACK ? 1 : 0);
        if(err == 0) 
            wh = 1;
        else if(err == p67_err_eagain) 
            err = 0;
        break;
    case P67_DML_STP_PDP_URG:
        err = p67_pdp_write_ack_for_urg(conn, &msg_hdr->urg);
        break;
    case P67_DML_STP_DAT:
        /* DATs are effectively NOOPs on DML */
        break;
    default:
        err = p67_err_einval;
        break;
    }

    if(err != 0){
        p67_err_print_err("error/s occured in dml handle message: ", err);
        return 0;
    }

    if(wh == 1)
        return 0;

    // signal that message still needs to be processed.
    return p67_err_eagain;
}

p67_err
p67_dml_pretty_print(const unsigned char * msg, int msgl)
{
    const p67_dml_hdr_store_t * hdr;
    p67_err err;

    if((hdr = p67_dml_parse_hdr(msg, msgl, &err)) == NULL)
        return err;

    switch(hdr->cmn.cmn_stp) {
    case P67_DML_STP_PDP_ACK:
        printf("ACK, utp: %d, payload length: %d bytes\n", 
            hdr->cmn.cmn_utp,
            msgl-(int)sizeof(p67_pdp_ack_hdr_t));
        break;
    case P67_DML_STP_PDP_URG:
        printf("URG, utp: %d, payload length: %d bytes\n", 
            hdr->cmn.cmn_utp,
            msgl-(int)sizeof(p67_pdp_urg_hdr_t));
        break;
    case P67_DML_STP_DAT:
        printf("DAT, utp: %d, payload length: %d bytes\n", 
            hdr->cmn.cmn_utp,
            msgl-(int)sizeof(p67_dml_dat_hdr_t));
        break;
    default:
        err = p67_err_einval;
        break;
    }

    return 0;
}
