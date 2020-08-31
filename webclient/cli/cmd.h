#if !defined(P67_COMMANDS_H)
#define P67_COMMANDS_H

typedef struct p67_cmd_ctx {
    p67_addr_t * local_addr;
    p67_addr_t * ws_remote_addr;
    p67_net_cred_t * cred;

} p67_cmd_ctx_t;

#define p67_cmd_ctx_free(c) \
    { \
        p67_addr_free((c)->local_addr); \
        p67_addr_free((c)->ws_remote_addr); \
        p67_net_cred_free((c)->cred); \
    }

int
p67_cmd_execute(
    p67_hashcntl_t * commands,
    p67_cmd_ctx_t * ctx,
    int argc, char ** argv);

p67_hashcntl_t *
p67_cmd_new(void);

#endif
