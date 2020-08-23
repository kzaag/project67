#if !defined(P67_BUFFER_H)
#define P67_BUFFER_H 1

typedef struct p67_buffer p67_buffer_t;

p67_buffer_t *
p67_buffer_new(const char * src, int len);

const char * 
p67_buffer_cstr(const p67_buffer_t * buff);

unsigned char *
p67_buffer_arr(const p67_buffer_t * b, int * len);

p67_buffer_t *
p67_buffer_ref_cpy(p67_buffer_t * src);

void
p67_buffer_free(p67_buffer_t * b);

#endif