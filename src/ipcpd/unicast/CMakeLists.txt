# Unicast IPCP build configuration

protobuf_generate_c(DHT_PROTO_SRCS DHT_PROTO_HDRS
  "${CMAKE_CURRENT_SOURCE_DIR}/dir/dht.proto")

set(UNICAST_SOURCES
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

add_executable(${IPCP_UNICAST_TARGET}
  ${UNICAST_SOURCES}
  ${IPCP_SOURCES}
  ${COMMON_SOURCES}
  ${DHT_PROTO_SRCS}
)

target_include_directories(${IPCP_UNICAST_TARGET} PRIVATE ${IPCP_INCLUDE_DIRS})
target_include_directories(${IPCP_UNICAST_TARGET} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_include_directories(${IPCP_UNICAST_TARGET} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${IPCP_UNICAST_TARGET} PRIVATE ouroboros-dev)

ouroboros_target_debug_definitions(${IPCP_UNICAST_TARGET})

install(TARGETS ${IPCP_UNICAST_TARGET} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

if(BUILD_TESTS)
  add_subdirectory(dir/tests)
  add_subdirectory(pff/tests)
  add_subdirectory(routing/tests)
endif()
