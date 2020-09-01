#include <stdio.h>

#include <p67/web/status.h>

/*
    evaluates to true if buffer run out of space.
    else increment wr to allow another round
*/
#define ssnprintf(b, bl, wr, ...) \
    ((wr += snprintf(b, bl - wr, __VA_ARGS__)) >= bl)

void
p67_web_status_str(p67_web_status s, char * b, int bl)
{
    switch(s) {
    case p67_web_status_ok:
        snprintf(b, bl, "OK");
        break;
    case p67_web_status_bad_request:
        snprintf(b, bl, "Bad request");
        break;
    case p67_web_status_not_found:
        snprintf(b, bl, "Not found");
        break;
    case p67_web_status_unauthorized:
        snprintf(b, bl, "Unauthorized");
        break;
    case p67_web_status_server_fault:
        snprintf(b, bl, "Server fault");
        break;
    case p67_web_status_not_modified:
        snprintf(b, bl, "Not modified");
        break;
    case p67_web_status_forbidden:
        snprintf(b, bl, "Forbidden");
        break;
    default:
        snprintf(b, bl, "Unknown status code: %u", s);
    }
}
