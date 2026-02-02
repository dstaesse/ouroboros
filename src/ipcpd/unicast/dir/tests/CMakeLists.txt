get_filename_component(CURRENT_SOURCE_PARENT_DIR
  ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(CURRENT_BINARY_PARENT_DIR
  ${CMAKE_CURRENT_BINARY_DIR} DIRECTORY)

get_filename_component(PARENT_PATH ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(PARENT_DIR ${PARENT_PATH} NAME)

compute_test_prefix()

create_test_sourcelist(${PARENT_DIR}_tests test_suite.c
  # Add new tests here
  dht_test.c
)

protobuf_generate_c(DHT_PROTO_SRCS KAD_PROTO_HDRS ${CURRENT_SOURCE_PARENT_DIR}/dht.proto)
add_executable(${PARENT_DIR}_test ${${PARENT_DIR}_tests}
  ${DHT_PROTO_SRCS})

target_include_directories(${PARENT_DIR}_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CURRENT_SOURCE_PARENT_DIR}
  ${CURRENT_BINARY_PARENT_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/src/ipcpd
  ${CMAKE_BINARY_DIR}/src/ipcpd
  ${CMAKE_SOURCE_DIR}/src/ipcpd/unicast
  ${CMAKE_BINARY_DIR}/src/ipcpd/unicast
)

disable_test_logging_for_target(${PARENT_DIR}_test)

target_link_libraries(${PARENT_DIR}_test ouroboros-common)
add_dependencies(build_tests ${PARENT_DIR}_test)

ouroboros_register_tests(TARGET ${PARENT_DIR}_test TESTS ${${PARENT_DIR}_tests})
