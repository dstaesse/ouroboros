get_filename_component(PARENT_SOURCE_PATH ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(PARENT_BINARY_PATH ${CMAKE_CURRENT_BINARY_DIR} DIRECTORY)
get_filename_component(PARENT_DIR ${PARENT_SOURCE_PATH} NAME)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${PARENT_SOURCE_PATH})
include_directories(${PARENT_BINARY_PATH})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

create_test_sourcelist(${PARENT_DIR}_tests test_suite.c
                       # Add new tests here
                       shim_udp_test.c
)

add_executable(${PARENT_DIR}_test EXCLUDE_FROM_ALL ${IPCP_SOURCES} ${${PARENT_DIR}_tests})
target_link_libraries(${PARENT_DIR}_test ouroboros)

include(MacroAddCompileFlags)
MACRO_ADD_COMPILE_FLAGS(${PARENT_DIR}_test -DMAKE_CHECK)

add_dependencies(check ${PARENT_DIR}_test)

set(tests_to_run ${${PARENT_DIR}_tests})
remove(tests_to_run test_suite.c)

foreach(test ${tests_to_run})
  get_filename_component(test_name ${test} NAME_WE)
  add_test(${test_name} ${C_TEST_PATH}/${PARENT_DIR}_test ${test_name})
endforeach(test)
