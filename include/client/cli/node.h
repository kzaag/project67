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
    int trusted_pk_l,
    int state,
    char * username);

#define p67_ext_node_remove(addr) p67_node_remove(addr)

p67_net_cb_ctx_t
p67_ext_node_p2p_cb(void);

p67_node_t *
p67_ext_node_find_by_name(char * username);

#endif
