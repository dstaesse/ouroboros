get_filename_component(PARENT_PATH ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(PARENT_DIR ${PARENT_PATH} NAME)

get_filename_component(OAP_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}" DIRECTORY)
get_filename_component(OAP_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}" DIRECTORY)
get_filename_component(IRMD_SOURCE_DIR "${OAP_SOURCE_DIR}" DIRECTORY)
get_filename_component(IRMD_BINARY_DIR "${OAP_BINARY_DIR}" DIRECTORY)

compute_test_prefix()

create_test_sourcelist(${PARENT_DIR}_tests test_suite.c
  # Add new tests here
  oap_test.c
)

create_test_sourcelist(${PARENT_DIR}_pqc_tests test_suite_pqc.c
  # PQC-specific tests
  oap_test_pqc.c
)

# OAP test needs io.c compiled with OAP_TEST_MODE
set(OAP_TEST_SOURCES
  ${OAP_SOURCE_DIR}/io.c
  ${OAP_SOURCE_DIR}/hdr.c
  ${OAP_SOURCE_DIR}/auth.c
  ${OAP_SOURCE_DIR}/srv.c
  ${OAP_SOURCE_DIR}/cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/common.c
)

# Regular test executable (ECDSA)
add_executable(${PARENT_DIR}_test ${${PARENT_DIR}_tests} ${OAP_TEST_SOURCES})
set_source_files_properties(${OAP_TEST_SOURCES}
  PROPERTIES COMPILE_DEFINITIONS "OAP_TEST_MODE"
)

disable_test_logging_for_target(${PARENT_DIR}_test)
target_link_libraries(${PARENT_DIR}_test ouroboros-irm)
target_include_directories(${PARENT_DIR}_test PRIVATE
  ${IRMD_SOURCE_DIR}
  ${IRMD_BINARY_DIR}
)

# PQC test executable (ML-DSA)
add_executable(${PARENT_DIR}_pqc_test ${${PARENT_DIR}_pqc_tests} ${OAP_TEST_SOURCES})
set_source_files_properties(${OAP_TEST_SOURCES}
  TARGET_DIRECTORY ${PARENT_DIR}_pqc_test
  PROPERTIES COMPILE_DEFINITIONS "OAP_TEST_MODE"
)

disable_test_logging_for_target(${PARENT_DIR}_pqc_test)
target_link_libraries(${PARENT_DIR}_pqc_test ouroboros-irm)
target_include_directories(${PARENT_DIR}_pqc_test PRIVATE
  ${IRMD_SOURCE_DIR}
  ${IRMD_BINARY_DIR}
)

add_dependencies(build_tests ${PARENT_DIR}_test ${PARENT_DIR}_pqc_test)

# Regular tests
ouroboros_register_tests(TARGET ${PARENT_DIR}_test TESTS ${${PARENT_DIR}_tests})

# PQC tests
ouroboros_register_tests(TARGET ${PARENT_DIR}_pqc_test TESTS ${${PARENT_DIR}_pqc_tests})
