# netmap support (kernel bypass). Explicit opt-in.
find_path(NETMAP_C_INCLUDE_DIR
  net/netmap_user.h
  HINTS /usr/include /usr/local/include)

mark_as_advanced(NETMAP_C_INCLUDE_DIR)

set(ENABLE_NETMAP FALSE CACHE BOOL
  "Use netmap for Ethernet PoAs, overriding raw sockets or BPF")

if(ENABLE_NETMAP)
  if(NOT NETMAP_C_INCLUDE_DIR)
    message(FATAL_ERROR "ENABLE_NETMAP is set, but netmap was not found.")
  endif()

  message(STATUS "Netmap support for Ethernet PoAs enabled")

  set(HAVE_NETMAP TRUE)

  unset(HAVE_RAW_SOCKETS)
  unset(HAVE_BPF)
endif()
