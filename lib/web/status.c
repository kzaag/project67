#include "status.h"

#include <stdio.h>

/*
    evaluates to true if buffer run out of space.
    else increment wr to allow another round
*/
#define ssnprintf(b, bl, wr, ...) \
    ((wr += snprintf(b, bl - wr, __VA_ARGS__)) >= bl)

void
p67_web_status_str(p67_web_status werr, char * b, int bl)
{
    int wrote = 0, sw = 0;

    if(ssnprintf(b, bl, wrote, "{ ")) return;

    if(werr & p67_web_status_ok) {
        if(ssnprintf(b, bl, wrote, "OK")) {
            return;
        }
        sw=1;
    }

    #define handle_status(s, sm) \
        if(werr & s) {  \
            if(sw) if(ssnprintf(b, bl, wrote, ", ")) return; \
            if(ssnprintf(b, bl, wrote, sm)) return; \
            sw = 1; \
        }

    handle_status(p67_web_status_bad_request, "Bad request");
    handle_status(p67_web_status_unauthorized, "Unauthorized");
    handle_status(p67_web_status_not_found, "Not found");
    handle_status(p67_web_status_server_fault, "Server fault");

    if(ssnprintf(b, bl, wrote, " }")) return;
}
