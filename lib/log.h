#if !defined(P67_LOG)
#define P67_LOG 1

#if defined(DEBUG) 

#define p67_log_debug(...) printf(__VA_ARGS__)

#else

#define p67_log_debug(...) (void)0

#endif

#define p67_log(...) printf(__VA_ARGS__)

#endif
