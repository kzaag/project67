#if !defined(P67_REDIRECT_H)
#define P67_REDIRECT_H 1

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

typedef struct p67_ws_redirect_ctx p67_ws_redirect_ctx_t; 

#endif