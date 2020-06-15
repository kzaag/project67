#if !defined(NET_H)
#define NET_H

#include "err.h"

typedef struct conn p67_conn_t;
typedef int (* p67_callback)(p67_conn_t *, void *, int, void*);

p67_err
p67_conn_assign_callback(
                p67_conn_t * conn, 
                p67_callback callback, 
                void * args);

p67_conn_t *
p67_conn_new(void);

void
p67_conn_free(p67_conn_t * conn);

p67_err
p67_conn_shutdown(p67_conn_t * conn);

p67_err
p67_conn_read(p67_conn_t * conn);

p67_err
p67_conn_connect(
            p67_conn_t * conn, 
            const char * hostname, 
            const char * service,
            const char * accepted_chain);

p67_err
p67_conn_listen(
    const char * hostname, 
    const char * service, 
    const char * certpath, 
    const char * keypath,
    p67_callback callback,
    void * callback_args);

#endif
