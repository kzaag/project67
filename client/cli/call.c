#include <p67/hashcntl.h>
#include <client/cli/call.h>
#include <p67/log.h>
#include <string.h>

static p67_hashcntl_t * __call_tbl = NULL;
p67_async_t __call_tbl_lock = P67_ASYNC_INTIIALIZER;

void
p67_call_entry_free(p67_hashcntl_entry_t * e);

P67_CMN_NO_PROTO_ENTER
p67_hashcntl_t *
__p67_call_get_tbl(void)
{
    p67_hashcntl_getter_fn(
        __call_tbl_lock, 
        __call_tbl, 
        17, p67_call_entry_free, 
        "couldnt initialize pending call cache");
}
P67_CMN_NO_PROTO_EXIT

#define p67_call_tbl (__p67_call_get_tbl())

void
p67_call_entry_free(p67_hashcntl_entry_t * e)
{
    if(!e) return;
    p67_call_entry_t * ee = (p67_call_entry_t *)e->value;
    p67_addr_free(ee->server_addr);
    p67_addr_free(ee->peer_addr);
    free(e);
}

void
p67_call_print_entry(p67_hashcntl_entry_t * he)
{
    assert(he);
    p67_call_entry_t * e = (p67_call_entry_t *)he->value;
    assert(e);
    p67_log("REF=%s:%s ADDR=%s:%s USERNAME=%s\n",
        e->server_addr->hostname,
        e->server_addr->service,
        e->peer_addr->hostname,
        e->peer_addr->service,
        e->username);
}

void
p67_call_print_all(void)
{
    p67_hashcntl_foreach(p67_call_tbl, p67_call_print_entry);
}

p67_err
p67_call_add_pending(
    p67_addr_t * server_addr,
    p67_addr_t * peer_addr,
    const char * username,
    int usernamel,
    const p67_pdp_urg_hdr_t * urg)
{
    assert(server_addr);
    assert(username);
    assert(usernamel > 0);
    assert(urg);

    p67_hashcntl_entry_t * e = malloc(
        sizeof(p67_hashcntl_entry_t) + 
        sizeof(p67_call_entry_t) +
        usernamel+1);
    if(!e) return p67_err_eerrno;

    e->key = (char*)e+sizeof(p67_hashcntl_entry_t)+sizeof(p67_call_entry_t);
    e->keyl = usernamel+1;
    e->next = NULL;
    e->ts = 0;
    e->value = (char*)e+sizeof(p67_hashcntl_entry_t);
    e->valuel = sizeof(p67_call_entry_t);

    memcpy(e->key, username, usernamel+1);
    
    p67_call_entry_t * ce = (p67_call_entry_t *)e->value;
    ce->req = *urg;
    ce->server_addr = p67_addr_ref_cpy(server_addr);
    ce->peer_addr = p67_addr_ref_cpy(peer_addr);
    ce->username = e->key;
    ce->usernamel = e->keyl;

    p67_err err = p67_hashcntl_add(p67_call_tbl, e);

    if(err) {
        p67_call_entry_free(e);
    }

    return err;
}

p67_err
p67_call_remove(const char * username)
{
    return p67_hashcntl_remove_and_free(
        p67_call_tbl, username, strlen(username)+1);
}

p67_call_entry_t *
p67_call_lookup(const char * username)
{
    p67_hashcntl_entry_t * e = p67_hashcntl_lookup(
        p67_call_tbl, username, strlen(username)+1);
    if(!e) return NULL;
    return (p67_call_entry_t *)e->value;
}
