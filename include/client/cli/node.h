#if !defined(CLI_NODE_H)
#define CLI_NODE_H 1

#include <p67/net.h>

typedef struct p67_ext_node p67_ext_node_t;

#define P67_EXT_NODE_PRINT_FLAGS_ALL 1

void
p67_ext_node_print(p67_node_t * node, int print_flags);

void
p67_ext_node_print_all(int print_flags);

p67_node_t *
p67_ext_node_insert(
    p67_addr_t * addr,
    const char * trused_pk,
    int state,
    const char * username);

#define p67_ext_node_remove(addr) p67_node_remove(addr)

p67_net_cb_ctx_t
p67_ext_node_p2p_cb(void);

p67_node_t *
p67_ext_node_find_by_name(char * username);

p67_err
p67_ext_node_start_connect(
    p67_node_t * node, 
    p67_addr_t * local_addr, p67_net_cred_t * local_cred, p67_net_cb_ctx_t cbctx);

p67_err
p67_ext_node_insert_and_connect(
    p67_addr_t * addr,
    const char * trusted_pk_path,
    const char * username,
    p67_addr_t * local_addr,
    p67_net_cred_t * cred,
    p67_net_cb_ctx_t cbctx);

#endif
