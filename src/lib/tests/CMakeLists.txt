get_filename_component(PARENT_PATH ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(PARENT_DIR ${PARENT_PATH} NAME)

create_test_sourcelist(${PARENT_DIR}_tests test_suite.c
  # Add new tests here
  bitmap_test.c
  btree_test.c
  crc32_test.c
  hashtable_test.c
  md5_test.c
  rib_test.c
  sha3_test.c
  )

add_executable(${PARENT_DIR}_test EXCLUDE_FROM_ALL ${${PARENT_DIR}_tests})
target_link_libraries(${PARENT_DIR}_test ouroboros)

add_dependencies(check ${PARENT_DIR}_test)

set(tests_to_run ${${PARENT_DIR}_tests})
remove(tests_to_run test_suite.c)

foreach (test ${tests_to_run})
  get_filename_component(test_name ${test} NAME_WE)
  add_test(${test_name} ${C_TEST_PATH}/${PARENT_DIR}_test ${test_name})
endforeach (test)
