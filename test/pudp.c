#include <p67/p67.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>

p67_err
process_message(p67_conn_t * conn, const char * msg, int msgl, void * args)
{
    switch (msg[0]) {
    case P67_PUDP_HDR_ACK:
        if(msgl < 5)
            return p67_err_einval;
        printf("ACK received with payload (%d bytes): %*.*s\n", 
            msgl-5, msgl-5, msgl-5, msg+5);
        return p67_pudp_handle_msg(conn, msg, msgl, NULL);
    case P67_PUDP_HDR_URG:    
        if(msgl < 5)
            return p67_err_einval;
        printf("URG received with payload (%d bytes): %*.*s\n", 
            msgl-5, msgl-5, msgl-5, msg+5);
        return p67_pudp_handle_msg(conn, msg, msgl, NULL);
    default:
        printf("Unknown message received with payload (%d bytes): %*.*s\n", 
            msgl, msgl, msgl, msg);
        break;
    }
    return 0;
}

void
pudp_evt_callback(p67_conn_pass_t * pass, int evt, void * arg)
{
    char buff[120];
    printf("EVT: %s\n", p67_pudp_evt_str(buff, sizeof(buff), evt));
    if(evt == P67_PUDP_EVT_ERROR) {
        p67_err_print_err("err: ", *(p67_err*)arg);
    }
}

int
main(int argc, char ** argv)
{
    p67_conn_pass_t pass = P67_CONN_PASS_INITIALIZER;
    p67_err err;
    int len;
    int sigterm = P67_PUDP_EVT_NONE;
    
    char keypath[] = "p2pcert";
    char certpath[] = "p2pcert.cert";
    
    pass.local.rdonly = 1;
    pass.remote.rdonly = 1;
    pass.certpath = certpath;
    pass.keypath = keypath;
    pass.args = NULL;
    pass.handler = process_message;

    if(argc < 3) {
        printf("Usage: ./p67pudp [source port] [dest port]\n");
        return 2;
    }

    p67_lib_init();

    if((err = p67_addr_set_localhost4_udp(&pass.local, argv[1])) != 0)
        goto end;

    if((err = p67_addr_set_host_udp(&pass.remote, IP4_LO1, argv[2])))
        goto end;

    if((err = p67_net_start_connect_and_listen(&pass)) != 0)
        goto end;

    getchar();
    
    const char cstr[] = "hello";
    char msg[5 + 5];
    p67_pudp_urg(msg);
    memcpy(msg + 5, cstr, 5);

    if((err = p67_pudp_write_urg(&pass, msg, 10, 0, &sigterm, pudp_evt_callback)) != 0)
        goto end; 

    if((err = p67_mutex_wait_for_change(&sigterm, P67_PUDP_EVT_NONE, -1)) != 0)
        goto end;

    char buff[120];
    printf("\nFinished with EVT=\"%s\".\n\n", p67_pudp_evt_str(buff, sizeof(buff), sigterm));

    err = p67_net_async_terminate(&pass);

end:
    if(err != 0) p67_err_print_err("Error occurred: ", err);
    p67_lib_free();
    if(err == 0) return 0; else return 2;
}
