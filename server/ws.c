#include <stdlib.h>
#include <string.h>

#include <p67/dml/dml.h>
#include <p67/web/tlv.h>

#include <server/ws.h>
#include <server/session.h>
#include <server/redirect.h>
#include <server/login.h>

#define P67_WS_UTP_PATH_LOGIN 'l'
#define P67_WS_UTP_PATH_CALL  'c'

P67_CMN_NO_PROTO_ENTER
p67_err
p67_ws_cb(
P67_CMN_NO_PROTO_EXIT
    p67_addr_t * addr, p67_pckt_t * msg, int msgl, void * args)
{
    if(!args) return p67_err_einval;

    const p67_dml_hdr_store_t * h;
    p67_err err;

    if((h = p67_dml_parse_hdr(msg, msgl, NULL)) == NULL)
        return p67_err_epdpf;

    switch(h->cmn.cmn_stp) {
    case P67_DML_STP_PDP_PACK:

        return p67_dml_handle_msg(addr, msg, msgl, NULL);

    case P67_DML_STP_PDP_ACK:

        switch(h->cmn.cmn_utp) {
        case P67_WS_UTP_PATH_CALL:
            return p67_ws_redirect_handle_ack(
                (p67_ws_session_t *)args, addr, msg, msgl);
        default:
            return p67_dml_handle_msg(addr, msg, msgl, NULL);
        }

    case P67_DML_STP_PDP_URG:

        switch(h->cmn.cmn_utp) {
        case P67_WS_UTP_PATH_LOGIN:
        
            err = p67_ws_login_handle_urg(
                addr, (p67_ws_session_t *)args, msg, msgl);
            return err;

        case P67_WS_UTP_PATH_CALL:
            
            err = p67_ws_redirect_handle_urg(
                (p67_ws_session_t *)args, addr, msg, msgl);
            return err;
        
        case 0:
            /* if not utp specified respond with empty ack */
            return p67_dml_handle_msg(addr, msg, msgl, NULL);
        default:
            /* respond with ack + p67_web_status_not_found */
            return p67_web_tlv_respond_with_status(
                &h->urg, addr, p67_web_status_not_found);
        }

    default:
        return p67_err_epdpf;
    }

    return p67_err_einval;
}

p67_err
p67_ws_create_cb_ctx(p67_net_cb_ctx_t * ctx)
{
    assert(ctx);

    p67_hashcntl_t * login_cache;
    p67_net_cb_ctx_t ret;
    p67_err err;

    err = p67_ws_login_cache_create(&login_cache);
    if(err) return err;

    ret.cb = p67_ws_cb;
    ret.gen_args = p67_ws_session_create_arg_fn;
    ret.free_args = p67_ws_session_free_arg_fn;
    ret.args = login_cache;

    *ctx = ret;

    return 0;
}

