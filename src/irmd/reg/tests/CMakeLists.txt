get_filename_component(PARENT_PATH ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(PARENT_DIR ${PARENT_PATH} NAME)

compute_test_prefix()

create_test_sourcelist(${PARENT_DIR}_tests test_suite.c
  # Add new tests here
  flow_test.c
  ipcp_test.c
  name_test.c
  proc_test.c
  prog_test.c
  reg_test.c
)

add_executable(${PARENT_DIR}_test ${${PARENT_DIR}_tests})

target_include_directories(${PARENT_DIR}_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/src/irmd
  ${CMAKE_BINARY_DIR}/src/irmd
)

disable_test_logging_for_target(${PARENT_DIR}_test)
target_link_libraries(${PARENT_DIR}_test PRIVATE ouroboros-common)
ouroboros_target_debug_definitions(${PARENT_DIR}_test)

add_dependencies(build_tests ${PARENT_DIR}_test)

ouroboros_register_tests(TARGET ${PARENT_DIR}_test TESTS ${${PARENT_DIR}_tests})
