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

find_path(BPF_C_INCLUDE_DIR
  net/bpf.h
  HINTS /usr/include /usr/local/include
  )

if (NOT CMAKE_SYSTEM_NAME STREQUAL "Linux" AND
    NOT BPF_C_INCLUDE_DIR STREQUAL "BPF_C_INCLUDE_DIR-NOTFOUND")
  message(STATUS "Found Berkeley Packet Filter headers in ${BPF_C_INCLUDE_DIR}")
  set(HAVE_BPF "1" CACHE STRING "Have Berkeley Packet Filter")
endif ()

if (NOT NETMAP_C_INCLUDE_DIR STREQUAL "NETMAP_C_INCLUDE_DIR-NOTFOUND")
  message(STATUS "Found netmap headers in ${NETMAP_C_INCLUDE_DIR}")
  set(HAVE_NETMAP "1" CACHE STRING "Have netmap")
  test_and_set_c_compiler_flag_global(-std=c99)
endif ()

if (HAVE_NETMAP OR HAVE_BPF OR CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(STATUS "Supported raw Ethernet API found, building shim-eth-llc")
  protobuf_generate_c(SHIM_ETH_LLC_PROTO_SRCS SHIM_ETH_LLC_PROTO_HDRS
    shim_eth_llc_messages.proto)

  set(SHIM_ETH_LLC_SOURCES
    # Add source files here
    ${CMAKE_CURRENT_SOURCE_DIR}/main.c
  )

  set(IPCP_SHIM_ETH_LLC_TARGET ipcpd-shim-eth-llc
      CACHE STRING "IPCP_SHIM_ETH_LLC_TARGET")

  add_executable(ipcpd-shim-eth-llc ${SHIM_ETH_LLC_SOURCES} ${IPCP_SOURCES}
    ${SHIM_ETH_LLC_PROTO_SRCS})

  if (HAVE_BPF AND NOT APPLE)
    target_include_directories(ipcpd-shim-eth-llc PUBLIC ${BPF_C_INCLUDE_DIR})
  endif ()

  if (HAVE_NETMAP AND NOT APPLE)
    target_include_directories(ipcpd-shim-eth-llc PUBLIC ${NETMAP_C_INCLUDE_DIR})
  endif ()

  target_link_libraries(ipcpd-shim-eth-llc LINK_PUBLIC ouroboros
    ${PROTOBUF_C_LIBRARY})

  include(AddCompileFlags)
  if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_compile_flags(ipcpd-shim-eth-llc -DCONFIG_OUROBOROS_DEBUG)
  endif (CMAKE_BUILD_TYPE MATCHES Debug)

  install(TARGETS ipcpd-shim-eth-llc RUNTIME DESTINATION sbin)
endif ()
