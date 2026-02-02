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
  sockets_test.c
  time_test.c
  tpm_test.c
  )

add_executable(${PARENT_DIR}_test ${${PARENT_DIR}_tests})

disable_test_logging_for_target(${PARENT_DIR}_test)
target_link_libraries(${PARENT_DIR}_test ouroboros-common)

add_dependencies(build_tests ${PARENT_DIR}_test)

ouroboros_register_tests(TARGET ${PARENT_DIR}_test TESTS ${${PARENT_DIR}_tests})
