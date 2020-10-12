#if !defined(CLI_CALL_H)
#define CLI_CALL_H 1 

#include <p67/net.h>
#include <p67/dml/pdp.h>

typedef struct p67_call_entry p67_call_entry_t;

struct p67_call_entry {
    p67_pdp_urg_hdr_t req;
    p67_addr_t * server_addr;
    p67_addr_t * peer_addr;
    char * username;
    int usernamel;
};

p67_err
p67_call_add_pending(
    p67_addr_t * server_addr,
    p67_addr_t * peer_addr,
    const char * username,
    int usernamel,
    const p67_pdp_urg_hdr_t * urg);

p67_err
p67_call_remove(const char * username);

p67_call_entry_t *
p67_call_lookup(const char * username);

void
p67_call_print_entry(p67_hashcntl_entry_t * he);

void
p67_call_print_all(void);

#endif

