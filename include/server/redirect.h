#if !defined(P67_REDIRECT_H)
#define P67_REDIRECT_H 1

#include <p67/net.h>
#include <server/session.h>

/*
    A                         WEBSERVER                        B

    --------------------------->
    URG = { 
        * p  cstr  A service
          U  cstr  B username
        * m  cstr  message to B
    }


                                     --------------------------->
                                     URG = {
                                         p cstr  A service
                                         a cstr  A ip
                                       * m cstr  message to B
                                       * u cstr  A username
                                }

    <---------------------------
      PACK = {}

                                <---------------------------
                                 [optional] PACK = {}

                                                        (B decides whether to accept 
                                                        or reject call from A
                                                        this part may take long time
                                                        thus the optional PACKs )

                                <---------------------------
                                ACK = {
                                    s uint16_t response status
                                }

    <----------------------------
    ACK = {
        s  uint16_t response status
      * P  cstr B service
      * A  cstr B address
    }

*/

p67_err
p67_ws_redirect_handle_urg(
    p67_ws_session_t * session,
    p67_addr_t * src_addr,
    const p67_pckt_t * msg, int msgl);

p67_err
p67_ws_redirect_handle_ack(
    p67_ws_session_t * session,
    p67_addr_t * addr,
    const p67_pckt_t * msg, int msgl);

#endif