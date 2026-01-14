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

# Add includes for ipcp and unicast module files
include_directories(${CMAKE_SOURCE_DIR}/src/ipcpd)
include_directories(${CMAKE_BINARY_DIR}/src/ipcpd)
include_directories(${CMAKE_SOURCE_DIR}/src/ipcpd/unicast)
include_directories(${CMAKE_BINARY_DIR}/src/ipcpd/unicast)

get_filename_component(PARENT_PATH ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(PARENT_DIR ${PARENT_PATH} NAME)

create_test_sourcelist(${PARENT_DIR}_tests test_suite.c
  # Add new tests here
  dht_test.c
  )

protobuf_generate_c(DHT_PROTO_SRCS KAD_PROTO_HDRS ../dht.proto)
add_executable(${PARENT_DIR}_test ${${PARENT_DIR}_tests}
  ${DHT_PROTO_SRCS})

disable_test_logging_for_target(${PARENT_DIR}_test)
target_link_libraries(${PARENT_DIR}_test ouroboros-common)

add_dependencies(build_tests ${PARENT_DIR}_test)

set(tests_to_run ${${PARENT_DIR}_tests})
if(CMAKE_VERSION VERSION_LESS "3.29.0")
  remove(tests_to_run test_suite.c)
else ()
  list(POP_FRONT tests_to_run)
endif()

foreach (test ${tests_to_run})
  get_filename_component(test_name ${test} NAME_WE)
  add_test(${test_name} ${C_TEST_PATH}/${PARENT_DIR}_test ${test_name})
endforeach (test)
