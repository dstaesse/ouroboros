# netmap support (optional acceleration)
find_path(NETMAP_C_INCLUDE_DIR
  net/netmap_user.h
  HINTS /usr/include /usr/local/include)

mark_as_advanced(NETMAP_C_INCLUDE_DIR)

if (NOT HAVE_RAW_SOCKETS AND NOT HAVE_BPF AND NETMAP_C_INCLUDE_DIR)
  set(DISABLE_NETMAP FALSE CACHE BOOL
    "Disable netmap support for ETH IPCPs")
  if (NOT DISABLE_NETMAP)
    message(STATUS "Netmap support for Ethernet IPCPs enabled")
    set(HAVE_NETMAP TRUE)
  else ()
    message(STATUS "Netmap support for Ethernet IPCPs disabled by user")
    unset(HAVE_NETMAP)
  endif ()
endif ()
