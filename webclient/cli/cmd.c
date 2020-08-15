#include <p67/err.h>
#include <p67/conn_ctx.h>
#include <p67/dml.h>
#include <p67/web/status.h>
#include <p67/web/tlv.h>
#include <p67/hashcntl.h>

#include <signal.h>

#include "cmd.h"

typedef int (* p67_cmd_hndl)(
    p67_cmd_ctx_t * ctx, int argc, char ** argv);

typedef struct p67_cmd_entry {
    char * command;
    size_t commandl;
    p67_cmd_hndl handler;
    char __padd[sizeof(size_t)+sizeof(p67_hashcntl_entry_t *)];
} p67_cmd_entry_t;

p67_cmn_static_assert_size(p67_cmd_entry_t, p67_hashcntl_entry_t);

/*
    this is neccesary to use function pointers directly in hash entries.
    if building on cpu arch whch doesnt support it,
    then you must replace all assignments and reads from entries.
*/
p67_cmn_static_assert(
    uchar_ptr_sz, sizeof(unsigned char *) == sizeof(p67_cmd_hndl));

void
p67_cmd_free(p67_hashcntl_entry_t * e)
{
    free(e);
}

p67_err
p67_cmd_add(p67_hashcntl_t * ctx, char * name, p67_cmd_hndl hndl)
{
    int namelen = strlen(name);
    p67_hashcntl_entry_t * entry = malloc(sizeof(p67_hashcntl_entry_t) + namelen);
    if(!entry)
        return p67_err_eerrno;
    char * key = ((char *)entry) + sizeof(p67_hashcntl_entry_t);
    memcpy(key, name, namelen);
    entry->key = key;
    entry->keyl = namelen;
    entry->next = NULL;
    entry->value = (char *)hndl;
    entry->valuel = 0;
    return p67_hashcntl_add(ctx, entry);
}

int
p67_cmd_login(p67_cmd_ctx_t * ctx, int argc, char ** argvs)
{
    p67_err err;
    unsigned char msg[120];
    int len = 120;

    unsigned char * msgp = msg;
    int ix = 0;

    if(p67_pdp_generate_urg_for_msg(NULL, 0, msgp, len, 'l') == NULL)
        return p67_err_einval;

    msgp += P67_PDP_URG_OFFSET;
    ix += P67_PDP_URG_OFFSET;
    
    if(ix >= len)
        return p67_err_enomem;

    char buff[32];
    int bl = 0;
    char tmp;

    if(argc < 2) {
        printf("username: ");
        while((tmp = getchar()) != EOF && tmp != '\n') {
            if(bl >= (sizeof(buff) - 1)) break;
            buff[bl++] = tmp;
        }
    }

    if((err = p67_tlv_add_fragment(
                msgp, len-ix, "u\0", 
                argc < 2 ? buff : argvs[1], 
                argc < 2 ? bl : strlen(argvs[1]))) < 0)
        return -err;
    ix += err;
    msgp+=err;

    if(argc < 3) {
        printf("password: ");
        bl = 0;
        while((tmp = getchar()) != EOF && tmp != '\n') {
            if(bl >= (sizeof(buff) - 1)) break;
            buff[bl++] = tmp;
        }
    }

    if((err = p67_tlv_add_fragment(
                msgp, len-ix, "p\0", 
                argc < 3 ? buff : argvs[2], 
                argc < 3 ? bl : strlen(argvs[2]))) < 0)
        return -err;
    ix += err;
    msgp+=err;

    p67_async_t sig = P67_ASYNC_INTIIALIZER;

    // p67_epoch_t start, end;

    // p67_cmn_time_ms(&start);

    char res[80];
    int resl = 80;

    if((err = p67_pdp_write_urg(
            ctx->conn_ctx.remote_addr, msg, ix, -1, &sig, (void **)&res, &resl)) != 0)
        return err;

    p67_mutex_wait_for_change(&sig, 0, -1);

    // p67_cmn_time_ms(&end);

    // printf(
    //     "login took %llu ms. PDP status is: %s\n",
    //     end-start,
    //     p67_pdp_evt_str(buff, sizeof(buff), sig));

    if(sig == P67_PDP_EVT_GOT_ACK) {
        char buff[P67_WEB_TLV_STATUS_BUFFL];
        if((err = p67_web_tlv_status_str(res, resl, buff, P67_WEB_TLV_STATUS_BUFFL)) != 0)
            return err;
        printf("%s\n", buff);
    } else {
        char c[32];
        printf("%s\n", p67_pdp_evt_str(c, sizeof(c), sig));
        return p67_err_eagain;
    }


    return 0;
}

int 
p67_cmd_call(p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    p67_err err;
    unsigned char msg[120];
    int len = 120;

    unsigned char * msgp = msg;
    int ix = 0;

    if(argc < 2) {
        printf("must provide target\n");
        return 1;
    }

    if(p67_pdp_generate_urg_for_msg(NULL, 0, msgp, len, 'c') == NULL)
        return p67_err_einval;

    msgp += P67_PDP_URG_OFFSET;
    ix += P67_PDP_URG_OFFSET;
    
    if(ix >= len)
        return p67_err_enomem;

    printf("calling...\n");

    if((err = p67_tlv_add_fragment(msgp, len-ix, "N", argv[1], strlen(argv[1]))) < 0)
        return -err;
    ix += err;
    msgp+=err;

    if((err = p67_tlv_add_fragment(
            msgp, len-ix, "h", "some hint", sizeof("some hint")-1)) < 0)
        return -err;
    ix += err;
    msgp+=err;

    p67_async_t sig = P67_ASYNC_INTIIALIZER;

    // p67_epoch_t start, end;

    // p67_cmn_time_ms(&start);

    const unsigned char * res, * resptr;
    int resl;

    if((err = p67_pdp_write_urg(
            ctx->conn_ctx.remote_addr, msg, ix, -1, &sig, (void **)&res, &resl)) != 0)
        return err;

    p67_mutex_wait_for_change(&sig, 0, 20000);

    //p67_cmn_time_ms(&end);

    if(sig == P67_PDP_EVT_GOT_ACK) {
        //p67_dml_pretty_print(res, resl);
        const p67_tlv_header_t * tlv_hdr;
        const unsigned char * value;
        resptr = res;
        resptr += sizeof(p67_pdp_ack_hdr_t);
        resl -= sizeof(p67_pdp_ack_hdr_t);
        if((err = p67_tlv_next(
                &resptr, &resl, 
                &tlv_hdr, &value)) != 0)
            return err;
        if(tlv_hdr->tlv_key[0] != 's' || tlv_hdr->tlv_vlength != 2)
            return p67_err_etlvf;
        if((err = p67_tlv_pretty_print_fragment(tlv_hdr, value)) != 0)
            return err;
        uint16_t werr = p67_cmn_ntohs(*(uint16_t *)value);
        if(werr != 0)
            return p67_err_eagain;
    } else {
        char c[32];
        printf("%s\n", p67_pdp_evt_str(c, sizeof(c), sig));
    }

    return 0;
}

int p67_cmd_echo(p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    int i;
    //printf("%d\n",_argc);
    for(i = 0; i < argc; i++) {
        printf("(%lu) %s\n",strlen(argv[i]), argv[i]);
    }
}

int
p67_cmd_exit(p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    raise(SIGINT);
}

int
p67_cmd_help(p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    printf("?, help, echo, exit, call, login\n");
}

p67_hashcntl_t *
p67_cmd_new(void)
{
    p67_err err;
    p67_hashcntl_t * ret = p67_hashcntl_new(0, p67_cmd_free, NULL);
    if(!ret) return NULL;
    
    if((err = p67_cmd_add(ret, "?", p67_cmd_help)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "help", p67_cmd_help)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "echo", p67_cmd_echo)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "exit", p67_cmd_exit)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "call", p67_cmd_call)) != 0) return NULL;
    if((err = p67_cmd_add(ret, "login", p67_cmd_login)) != 0) return NULL;

    return ret;
}

int
p67_cmd_execute(
    p67_hashcntl_t * commands, p67_cmd_ctx_t * ctx, int argc, char ** argv)
{
    if(argc < 1)
        return -1;
    p67_hashcntl_entry_t * entry;
    entry = p67_hashcntl_lookup(commands, argv[0], strlen(argv[0]));
    if(entry) {
        return ((p67_cmd_hndl)entry->value)(ctx, argc, argv);
    } else {
        printf("command: \"%s\" not found.\n", argv[0]);
        return -1;
    }
}
