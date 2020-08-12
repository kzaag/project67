#if !defined(P67_WEB_STATUS_H)
#define P67_WEB_STATUS_H 1

#include <stdint.h>

typedef uint16_t p67_web_status;
#define p67_web_status_ok           0 /* 200 */
#define p67_web_status_bad_request  1 /* 400 */
#define p67_web_status_unauthorized 2 /* 401 */
#define p67_web_status_not_found    4 /* 404 */
#define p67_web_status_server_fault 8 /* 500 */


#define P67_WEB_STATUS_STR_BUFFL 72

void
p67_web_status_str(p67_web_status werr, char * b, int bl);

#endif
