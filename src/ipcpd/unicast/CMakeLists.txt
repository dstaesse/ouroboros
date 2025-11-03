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

set(IPCP_UNICAST_TARGET ipcpd-unicast CACHE INTERNAL "")
set(IPCP_UNICAST_MPL 10000 CACHE STRING
    "Default maximum packet lifetime for the unicast IPCP, in ms")
set(DEBUG_PROTO_DHT FALSE CACHE BOOL
  "Add DHT protocol message output to debug logging")
set(DEBUG_PROTO_LS FALSE CACHE BOOL
  "Add link state protocol message output to debug logging")

protobuf_generate_c(DHT_PROTO_SRCS DHT_PROTO_HDRS dir/dht.proto)

math(EXPR PFT_EXPR "1 << 12")
set(PFT_SIZE ${PFT_EXPR} CACHE STRING
  "Size of the PDU forwarding table")
if (HAVE_FUSE)
  set(IPCP_FLOW_STATS TRUE CACHE BOOL
    "Enable flow statistics tracking in IPCP")
    if (IPCP_FLOW_STATS)
       message(STATUS "IPCP flow statistics enabled")
    else ()
       message(STATUS "IPCP flow statistics disabled")
    endif ()
endif ()

set(IPCP_UNICAST_SOURCE_FILES
  # Add source files here
  addr-auth.c
  ca.c
  connmgr.c
  dir.c
  dt.c
  fa.c
  main.c
  pff.c
  routing.c
  psched.c
  # Add policies last
  addr-auth/flat.c
  ca/mb-ecn.c
  ca/nop.c
  dir/dht.c
  pff/simple.c
  pff/alternate.c
  pff/multipath.c
  pff/pft.c
  routing/link-state.c
  routing/graph.c
  )

add_executable(ipcpd-unicast ${IPCP_UNICAST_SOURCE_FILES} ${IPCP_SOURCES} ${COMMON_SOURCES}
  ${DHT_PROTO_SRCS} ${LAYER_CONFIG_PROTO_SRCS})
target_link_libraries(ipcpd-unicast LINK_PUBLIC ouroboros-dev)

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(ipcpd-unicast -DCONFIG_OUROBOROS_DEBUG)
endif ()

install(TARGETS ipcpd-unicast RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

if(BUILD_TESTS)
  add_subdirectory(pff/tests)
  add_subdirectory(routing/tests)
  add_subdirectory(dir/tests)
endif ()
