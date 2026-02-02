# Berkeley Packet Filter support (BSD/macOS only)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_path(BPF_C_INCLUDE_DIR
    net/bpf.h
    HINTS /usr/include /usr/local/include)

  mark_as_advanced(BPF_C_INCLUDE_DIR)

  if(BPF_C_INCLUDE_DIR)
    set(DISABLE_BPF FALSE CACHE BOOL
      "Disable Berkeley Packet Filter support for Ethernet IPCPs")
    if(NOT DISABLE_BPF)
      message(STATUS "Berkeley Packet Filter support for Ethernet IPCPs enabled")
      set(HAVE_BPF TRUE)
    else()
      message(STATUS "Berkeley Packet Filter support for Ethernet IPCPs disabled by user")
      unset(HAVE_BPF)
    endif()
  endif()
endif()
