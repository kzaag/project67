#if !defined(P67_COMMANDS_H)
#define P67_COMMANDS_H

typedef struct p67_cmd_ctx {
    p67_conn_ctx_t ws_conn_ctx;
    p67_conn_ctx_t p2p_listener_ctx;
} p67_cmd_ctx_t;

int
p67_cmd_execute(
    p67_hashcntl_t * commands,
    p67_cmd_ctx_t * ctx,
    int argc, char ** argv);

p67_hashcntl_t *
p67_cmd_new(void);

#endif
