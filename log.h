#if !defined(P67_LOG)
#define P67_LOG 1

#if defined(DEBUG) 

#define DLOG(...) printf(__VA_ARGS__)

#else

#define DLOG(...) (void)0

#endif

#define LOG(...) printf(__VA_ARGS__)

#endif
