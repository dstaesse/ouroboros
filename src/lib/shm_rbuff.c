#if (defined (SHM_RBUFF_LOCKLESS) && \
     (defined(__GNUC__) || defined (__clang__)))
#include "shm_rbuff_ll.c"
#else
#include "shm_rbuff_pthr.c"
#endif
