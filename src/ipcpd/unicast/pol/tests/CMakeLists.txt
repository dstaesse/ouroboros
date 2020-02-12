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

get_filename_component(PARENT_PATH ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(PARENT_DIR ${PARENT_PATH} NAME)

create_test_sourcelist(${PARENT_DIR}_tests test_suite.c
  # Add new tests here
  graph_test.c
  hashtable_test.c
  )

add_executable(${PARENT_DIR}_test EXCLUDE_FROM_ALL ${${PARENT_DIR}_tests})
target_link_libraries(${PARENT_DIR}_test ouroboros-common)

add_dependencies(check ${PARENT_DIR}_test)

set(tests_to_run ${${PARENT_DIR}_tests})
remove(tests_to_run test_suite.c)

foreach (test ${tests_to_run})
  get_filename_component(test_name ${test} NAME_WE)
  add_test(${test_name} ${C_TEST_PATH}/${PARENT_DIR}_test ${test_name})
endforeach (test)
