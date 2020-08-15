#include "tlv.h"
#include "../conn.h"

/*
    generate ack message and write status_fragment fragment into it
*/
p67_err
p67_web_tlv_respond_with_status(
    const p67_pdp_urg_hdr_t * urg,
    p67_addr_t * addr,
    p67_web_status status)
{
    p67_pckt_t ack[
        sizeof(p67_pdp_ack_hdr_t) + 
        sizeof(p67_web_tlv_status_fragment_t)];
    int err;

    err = p67_web_tlv_add_status_fragment(
        ack + sizeof(p67_pdp_ack_hdr_t), 
        sizeof(ack) - sizeof(p67_pdp_ack_hdr_t),
        status);

    if(err < 0) return -err;

    err = p67_pdp_generate_ack_from_hdr(
        urg, NULL, 0, ack, sizeof(p67_pdp_ack_hdr_t));

    if(err != 0) return err;

    p67_conn_write_once(addr, (p67_pckt_t *)ack, sizeof(ack));

    return err;
}

p67_err
p67_web_tlv_status_str(
    const p67_pckt_t * msg, int msgl,
    char * buff, int buffl)
{
    if(!msg || !buff)
        return p67_err_einval;

    const p67_dml_hdr_store_t * pdphdr 
        = p67_dml_parse_hdr(msg, msgl, NULL);

    if(!pdphdr)
        return p67_err_epdpf;

    if(pdphdr->cmn.cmn_stp != P67_DML_STP_PDP_ACK &&
                pdphdr->cmn.cmn_stp != P67_DML_STP_PDP_URG)
        return p67_err_epdpf;

    const p67_web_status * status;
    const p67_tlv_header_t * hdr;
    p67_err err;

    switch(pdphdr->cmn.cmn_stp) {
    case P67_DML_STP_PDP_ACK:
        msg += sizeof(p67_pdp_ack_hdr_t);
        msgl -= sizeof(p67_pdp_ack_hdr_t);
        break;
    case P67_DML_STP_PDP_URG:
        msg += sizeof(p67_pdp_urg_hdr_t);
        msgl -= sizeof(p67_pdp_urg_hdr_t);
        break;
    }

    if((err = p67_tlv_next(&msg, &msgl, &hdr, (const unsigned char **)&status)) != 0)
        return err;

    if(hdr->tlv_vlength != sizeof(*status) || hdr->tlv_key[0] != 's')
        return p67_err_etlvf;

    int wrote = 0;

    switch(pdphdr->cmn.cmn_stp) {
    case P67_DML_STP_PDP_ACK:
        wrote += snprintf(
            buff + wrote, buffl - wrote, 
            "ACK/%u ", pdphdr->ack.ack_utp);
        break;
    case P67_DML_STP_PDP_URG:
        wrote += snprintf(
            buff + wrote, buffl - wrote, 
            "URG/%u ", pdphdr->ack.ack_utp);
        break;
    }

    if(wrote > buffl)
        return 0;

    if(pdphdr->ack.ack_utp >= 49 && pdphdr->ack.ack_utp <= 122) {
        wrote += snprintf(
            buff + wrote, buffl - wrote, 
            "(%c) ", pdphdr->ack.ack_utp);
        if(wrote > buffl)
            return 0;
    }

    p67_web_status_str(p67_cmn_ntohs(*status), buff+wrote, buffl-wrote);

    return 0;
}
