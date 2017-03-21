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

create_test_sourcelist(${src_folder}_tests test_suite.c
  # Add new tests here
  timerwheel_test.c
  )

add_executable(${src_folder}_test EXCLUDE_FROM_ALL ${${src_folder}_tests})
target_link_libraries(${src_folder}_test ouroboros)

add_dependencies(check ${src_folder}_test)

set(tests_to_run ${${src_folder}_tests})
remove(tests_to_run test_suite.c)

foreach (test ${tests_to_run})
  get_filename_component(test_name ${test} NAME_WE)
  add_test(${test_name} ${C_TEST_PATH}/${src_folder}_test ${test_name})
endforeach (test)
