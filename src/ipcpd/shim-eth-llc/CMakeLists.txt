get_filename_component(CURRENT_SOURCE_PARENT_DIR
  ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(CURRENT_BINARY_PARENT_DIR
  ${CMAKE_CURRENT_BINARY_DIR} DIRECTORY)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CURRENT_SOURCE_PARENT_DIR})
include_directories(${CURRENT_BINARY_PARENT_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

find_path(NETMAP_C_INCLUDE_DIR
  net/netmap_user.h
  HINTS /usr/include /usr/local/include
)

mark_as_advanced(NETMAP_C_INCLUDE_DIR)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(DISABLE_RAW_SOCKETS FALSE CACHE BOOL
    "Disable raw socket support for LLC shim")
  if (NOT DISABLE_RAW_SOCKETS)
    message(STATUS "Raw socket support for shim-eth-llc enabled")
    set(HAVE_RAW_SOCKETS TRUE PARENT_SCOPE)
  else ()
    message(STATUS "Raw socket support for shim-eth-llc disabled by user")
  endif ()
endif ()

if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_path(BPF_C_INCLUDE_DIR
            net/bpf.h
            HINTS /usr/include /usr/local/include
  )

  mark_as_advanced(BPF_C_INCLUDE_DIR)

  if (BPF_C_INCLUDE_DIR)
    set(DISABLE_BPF FALSE CACHE BOOL
        "Disable Berkeley Packet Filter support for LLC shim")
    if (NOT DISABLE_BPF)
      message(STATUS "Berkeley Packet Filter support "
                     "for shim-eth-llc enabled")
      set(HAVE_BPF TRUE PARENT_SCOPE)
    else ()
      message(STATUS "Berkeley Packet Filter support "
                     "for shim-eth-llc disabled by user")
    endif ()
  endif ()
endif ()

if (NETMAP_C_INCLUDE_DIR)
  set(DISABLE_NETMAP FALSE CACHE BOOL
      "Disable netmap support for LLC shim")
  if (NOT DISABLE_NETMAP)
    message(STATUS "Netmap support for shim-eth-llc enabled")
    set(HAVE_NETMAP TRUE PARENT_SCOPE)
    test_and_set_c_compiler_flag_global(-std=c99)
  else ()
    message(STATUS "Netmap support for shim-eth-llc disabled by user")
  endif ()
endif ()

if (HAVE_NETMAP OR HAVE_BPF OR HAVE_RAW_SOCKETS)
  message(STATUS "Supported raw Ethernet API found, building shim-eth-llc")
  protobuf_generate_c(SHIM_ETH_LLC_PROTO_SRCS SHIM_ETH_LLC_PROTO_HDRS
    shim_eth_llc_messages.proto)

  set(SHIM_ETH_LLC_SOURCES
    # Add source files here
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
  )

  set(IPCP_SHIM_ETH_LLC_TARGET ipcpd-shim-eth-llc CACHE INTERNAL "")

  add_executable(ipcpd-shim-eth-llc ${SHIM_ETH_LLC_SOURCES} ${IPCP_SOURCES}
    ${SHIM_ETH_LLC_PROTO_SRCS})

  if (HAVE_BPF AND NOT APPLE)
    target_include_directories(ipcpd-shim-eth-llc PUBLIC ${BPF_C_INCLUDE_DIR})
  endif ()

  if (HAVE_NETMAP AND NOT APPLE)
    target_include_directories(ipcpd-shim-eth-llc PUBLIC
      ${NETMAP_C_INCLUDE_DIR})
  endif ()

  target_link_libraries(ipcpd-shim-eth-llc LINK_PUBLIC ouroboros
    ${PROTOBUF_C_LIBRARY})

  include(AddCompileFlags)
  if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_compile_flags(ipcpd-shim-eth-llc -DCONFIG_OUROBOROS_DEBUG)
  endif (CMAKE_BUILD_TYPE MATCHES Debug)

  install(TARGETS ipcpd-shim-eth-llc RUNTIME DESTINATION sbin)
endif ()
