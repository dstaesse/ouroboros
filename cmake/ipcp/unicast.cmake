set(UNICAST_SOURCE_DIR "${IPCP_SOURCE_DIR}/unicast")
set(UNICAST_BINARY_DIR "${IPCP_BINARY_DIR}/unicast")

set(IPCP_UNICAST_TARGET ipcpd-unicast CACHE INTERNAL "")

set(IPCP_UNICAST_MPL 100 CACHE STRING
  "Default maximum packet lifetime for the Unicast IPCP, in ms")
set(PFT_SIZE 256 CACHE STRING
  "Prefix forwarding table size for the Unicast IPCP")
set(DEBUG_PROTO_DHT FALSE CACHE BOOL
  "Add DHT protocol debug logging")
set(DEBUG_PROTO_LS FALSE CACHE BOOL
  "Add link state protocol debug logging")

# Generate DHT protobuf files
protobuf_generate_c(DHT_PROTO_SRCS DHT_PROTO_HDRS "${UNICAST_SOURCE_DIR}/dir/dht.proto")

set (UNICAST_SOURCES
  "${UNICAST_SOURCE_DIR}/addr-auth.c"
  "${UNICAST_SOURCE_DIR}/ca.c"
  "${UNICAST_SOURCE_DIR}/connmgr.c"
  "${UNICAST_SOURCE_DIR}/dir.c"
  "${UNICAST_SOURCE_DIR}/dt.c"
  "${UNICAST_SOURCE_DIR}/fa.c"
  "${UNICAST_SOURCE_DIR}/main.c"
  "${UNICAST_SOURCE_DIR}/pff.c"
  "${UNICAST_SOURCE_DIR}/routing.c"
  "${UNICAST_SOURCE_DIR}/psched.c"
  "${UNICAST_SOURCE_DIR}/addr-auth/flat.c"
  "${UNICAST_SOURCE_DIR}/ca/mb-ecn.c"
  "${UNICAST_SOURCE_DIR}/ca/nop.c"
  "${UNICAST_SOURCE_DIR}/dir/dht.c"
  "${UNICAST_SOURCE_DIR}/pff/simple.c"
  "${UNICAST_SOURCE_DIR}/pff/alternate.c"
  "${UNICAST_SOURCE_DIR}/pff/multipath.c"
  "${UNICAST_SOURCE_DIR}/pff/pft.c"
  "${UNICAST_SOURCE_DIR}/routing/link-state.c"
  "${UNICAST_SOURCE_DIR}/routing/graph.c"
)

add_executable(${IPCP_UNICAST_TARGET}
  ${UNICAST_SOURCES}
  ${IPCP_SOURCES}
  ${COMMON_SOURCES}
  ${DHT_PROTO_SRCS}
)
target_include_directories(${IPCP_UNICAST_TARGET} PRIVATE ${IPCP_INCLUDE_DIRS})
target_include_directories(${IPCP_UNICAST_TARGET} PRIVATE "${UNICAST_SOURCE_DIR}")
target_link_libraries(${IPCP_UNICAST_TARGET} PUBLIC ouroboros-dev)

include(utils/AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(${IPCP_UNICAST_TARGET} -DCONFIG_OUROBOROS_DEBUG)
endif ()

install(TARGETS ${IPCP_UNICAST_TARGET} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
