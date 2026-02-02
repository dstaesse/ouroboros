# Check for explicit_bzero in string.h
# glibc requires _DEFAULT_SOURCE to expose it; harmless on other platforms
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_DEFAULT_SOURCE)
check_symbol_exists(explicit_bzero "string.h" HAVE_EXPLICIT_BZERO)
