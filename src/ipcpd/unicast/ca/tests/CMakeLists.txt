get_filename_component(CURRENT_SOURCE_PARENT_DIR
  ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(CURRENT_BINARY_PARENT_DIR
  ${CMAKE_CURRENT_BINARY_DIR} DIRECTORY)

get_filename_component(UNICAST_SOURCE_DIR ${CURRENT_SOURCE_PARENT_DIR} DIRECTORY)
get_filename_component(UNICAST_BINARY_DIR ${CURRENT_BINARY_PARENT_DIR} DIRECTORY)

get_filename_component(PARENT_PATH ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(PARENT_DIR ${PARENT_PATH} NAME)

compute_test_prefix()

create_test_sourcelist(${PARENT_DIR}_tests test_suite.c
  # Add new tests here
  mb_ecn_test.c
  ca_test.c
  )

add_executable(${PARENT_DIR}_test ${${PARENT_DIR}_tests}
  ${UNICAST_SOURCE_DIR}/ca.c
  ${UNICAST_SOURCE_DIR}/cap.c
  ${CURRENT_SOURCE_PARENT_DIR}/nop.c
  )

target_include_directories(${PARENT_DIR}_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CURRENT_SOURCE_PARENT_DIR}
  ${CURRENT_BINARY_PARENT_DIR}
  ${UNICAST_SOURCE_DIR}
  ${UNICAST_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/src/ipcpd
  ${CMAKE_BINARY_DIR}/src/ipcpd
)

disable_test_logging_for_target(${PARENT_DIR}_test)
target_link_libraries(${PARENT_DIR}_test PRIVATE ouroboros-common)

add_dependencies(build_tests ${PARENT_DIR}_test)

ouroboros_register_tests(TARGET ${PARENT_DIR}_test TESTS ${${PARENT_DIR}_tests})

# The lab includes mb-ecn.c for its statics, so it needs its own binary
create_test_sourcelist(${PARENT_DIR}_lab_tests test_lab_suite.c
  mb_ecn_lab_test.c
  )

add_executable(${PARENT_DIR}_lab_test ${${PARENT_DIR}_lab_tests}
  ${UNICAST_SOURCE_DIR}/cap.c
  )

target_include_directories(${PARENT_DIR}_lab_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CURRENT_SOURCE_PARENT_DIR}
  ${CURRENT_BINARY_PARENT_DIR}
  ${UNICAST_SOURCE_DIR}
  ${UNICAST_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_SOURCE_DIR}/src/ipcpd
  ${CMAKE_BINARY_DIR}/src/ipcpd
)

disable_test_logging_for_target(${PARENT_DIR}_lab_test)
target_link_libraries(${PARENT_DIR}_lab_test PRIVATE ouroboros-common)

if(MB_ECN_LAB_FULL)
  target_compile_definitions(${PARENT_DIR}_lab_test PRIVATE MB_ECN_LAB_FULL)
endif()

add_dependencies(build_tests ${PARENT_DIR}_lab_test)

ouroboros_register_tests(TARGET ${PARENT_DIR}_lab_test
                         TESTS ${${PARENT_DIR}_lab_tests})
