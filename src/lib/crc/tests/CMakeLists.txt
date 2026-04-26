get_filename_component(PARENT_PATH ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(PARENT_DIR ${PARENT_PATH} NAME)

compute_test_prefix()

create_test_sourcelist(${PARENT_DIR}_tests test_suite.c
  # Add new tests here
  crc8_test.c
  crc16_test.c
  crc32_test.c
  crc64_test.c
  )

add_executable(${PARENT_DIR}_test ${${PARENT_DIR}_tests})

disable_test_logging_for_target(${PARENT_DIR}_test)
target_link_libraries(${PARENT_DIR}_test ouroboros-common)

add_dependencies(build_tests ${PARENT_DIR}_test)

ouroboros_register_tests(TARGET ${PARENT_DIR}_test TESTS ${${PARENT_DIR}_tests})
