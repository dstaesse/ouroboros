get_filename_component(PARENT_PATH ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(PARENT_DIR ${PARENT_PATH} NAME)

compute_test_prefix()

create_test_sourcelist(${PARENT_DIR}_tests test_suite.c
  # Add new tests here
  auth_test.c
  auth_test_pqc.c
  bitmap_test.c
  btree_test.c
  crc32_test.c
  crypt_test.c
  hash_test.c
  kex_test.c
  kex_test_pqc.c
  md5_test.c
  sha3_test.c
  shm_rbuff_test.c
  sockets_test.c
  time_test.c
  tpm_test.c
  )

add_executable(${PARENT_DIR}_test ${${PARENT_DIR}_tests})

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
  add_test(${TEST_PREFIX}/${test_name} ${CMAKE_CURRENT_BINARY_DIR}/${PARENT_DIR}_test ${test_name})
endforeach (test)

set_property(TEST ${TEST_PREFIX}/auth_test PROPERTY SKIP_RETURN_CODE 1)
set_property(TEST ${TEST_PREFIX}/auth_test_pqc PROPERTY SKIP_RETURN_CODE 1)
set_property(TEST ${TEST_PREFIX}/crypt_test PROPERTY SKIP_RETURN_CODE 1)
set_property(TEST ${TEST_PREFIX}/kex_test PROPERTY SKIP_RETURN_CODE 1)
set_property(TEST ${TEST_PREFIX}/kex_test_pqc PROPERTY SKIP_RETURN_CODE 1)
