get_filename_component(PARENT_PATH ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(PARENT_DIR ${PARENT_PATH} NAME)

create_test_sourcelist(${PARENT_DIR}_tests test_suite.c
  # Add new tests here
  auth_test.c
  bitmap_test.c
  btree_test.c
  crc32_test.c
  crypt_test.c
  hash_test.c
  md5_test.c
  sha3_test.c
  shm_rbuff_test.c
  sockets_test.c
  time_test.c
  tpm_test.c
  )

add_executable(${PARENT_DIR}_test ${${PARENT_DIR}_tests})

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
  add_test(${test_name} ${CMAKE_CURRENT_BINARY_DIR}/${PARENT_DIR}_test ${test_name})
endforeach (test)

set_property(TEST auth_test PROPERTY SKIP_RETURN_CODE 1)
set_property(TEST crypt_test PROPERTY SKIP_RETURN_CODE 1)
