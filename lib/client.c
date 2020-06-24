#include <pthread.h>

#include "haddr.h"
#include "hash.h"
#include "client.h"
#include "err.h"
#include "conn.h"

pthread_mutex_t __lock = PTHREAD_MUTEX_INITIALIZER;

p67_err
p67_client_disconnect(p67_conn_t * cext)
{
    p67_conn_t * conn;
    p67_err err;

    pthread_mutex_lock(&__lock);

    if((conn = p67_hash_conn_lookup(cext)) == NULL) {
        return p67_err_enconn;
    }

    p67_conn_shutdown(conn);

    if((err = p67_hash_conn_remove(conn)) != 0) return err;

    pthread_mutex_unlock(&__lock);

    return 0;
}

p67_err
p67_client_connect(p67_conn_t * conn)
{
    p67_err err;
    p67_conn_t * act_conn;

    pthread_mutex_lock(&__lock);

    if((err = p67_hash_conn_insert(conn, &act_conn)) != 0) {
        pthread_mutex_unlock(&__lock);
        return err;
    }

    if((err = p67_conn_connect(act_conn)) != 0) {
        p67_hash_conn_remove(act_conn);
        pthread_mutex_unlock(&__lock);
        return err;
    }

    pthread_mutex_unlock(&__lock);

    return 0;
}

