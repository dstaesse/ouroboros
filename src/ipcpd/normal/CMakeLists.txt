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

set(IPCP_NORMAL_TARGET ipcpd-normal CACHE INTERNAL "")

protobuf_generate_c(FLOW_ALLOC_SRCS FLOW_ALLOC_HDRS flow_alloc.proto)
protobuf_generate_c(ENROLL_PROTO_SRCS ENROLL_PROTO_HDRS enroll.proto
  ${CMAKE_SOURCE_DIR}/src/lib/ipcp_config.proto)
protobuf_generate_c(KAD_PROTO_SRCS KAD_PROTO_HDRS kademlia.proto)

# Add GPB sources of policies last
protobuf_generate_c(LS_PROTO_SRCS LS_PROTO_HDRS pol/link_state.proto)

math(EXPR PFT_EXPR "1 << 12")
set(PFT_SIZE ${PFT_EXPR} CACHE STRING
  "Size of the PDU forwarding table")

set(SOURCE_FILES
  # Add source files here
  addr_auth.c
  connmgr.c
  dht.c
  dir.c
  dt.c
  dt_pci.c
  enroll.c
  fa.c
  main.c
  pff.c
  routing.c
  sdu_sched.c
  # Add policies last
  pol/alternate_pff.c
  pol/flat.c
  pol/link_state.c
  pol/graph.c
  pol/simple_pff.c
  )

add_executable(ipcpd-normal ${SOURCE_FILES} ${IPCP_SOURCES}
  ${FLOW_ALLOC_SRCS} ${LS_PROTO_SRCS} ${KAD_PROTO_SRCS} ${ENROLL_PROTO_SRCS})
target_link_libraries(ipcpd-normal LINK_PUBLIC ouroboros-dev ouroboros-irm)

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  add_compile_flags(ipcpd-normal -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ipcpd-normal RUNTIME DESTINATION sbin)

add_subdirectory(pol/tests)

if (NOT GNU)
  add_subdirectory(tests)
endif ()
