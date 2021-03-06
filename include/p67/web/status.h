#if !defined(P67_WEB_STATUS_H)
#define P67_WEB_STATUS_H 1

#include <stdint.h>

typedef uint16_t p67_web_status;
#define p67_web_status_ok           0  /* 200 */
#define p67_web_status_bad_request  1  /* 400 */
#define p67_web_status_unauthorized 2  /* 401 */
#define p67_web_status_forbidden    4  /* 403 */
#define p67_web_status_not_found    8  /* 404 */
#define p67_web_status_server_fault 16  /* 500 */
#define p67_web_status_not_modified 32 /* 304 */



#define P67_WEB_STATUS_STR_BUFFL 32

void
p67_web_status_str(p67_web_status werr, char * b, int bl);

#endif
