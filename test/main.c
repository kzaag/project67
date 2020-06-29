#include <p67/net.h>
#include <p67/sfd.h>
#if !defined(__USE_XOPEN_EXTENDED)
#define __USE_XOPEN_EXTENDED
#endif
#include <string.h>

int
main()
{
    // p67_client_t * client = calloc(sizeof(p67_client_t), 1);
    // client->cert.certpath = strdup("server_cert.pem");
    // client->cert.keypath = strdup("server_private_key");
    // client->cert.trusted_chain_path = strdup("chain.pem");
    // p67_addr_set_host(&client->local_addr, "127.0.0.1", "2000");
    // p67_addr_set_host(&client->remote_addr, "127.0.0.1", "2020");
    
    // p67_err_print_err(p67_client_start_serve(client));

    // p67_err_print_err(p67_client_connect(client, 0));

    // getchar();

    // p67_err_print_err(p67_client_connect(client, 0));

    // getchar();

    // free(client->cert.certpath);
    // free(client->cert.keypath);
    // free(client->cert.trusted_chain_path);
    // p67_addr_free(&client->local_addr);
    // p67_addr_free(&client->remote_addr);
    // free(client);
}