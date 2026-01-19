get_filename_component(tmp ".." ABSOLUTE)
get_filename_component(src_folder "${tmp}" NAME)

compute_test_prefix()

create_test_sourcelist(${src_folder}_tests test_suite.c
  # Add new tests here
  oap_test.c
)

create_test_sourcelist(${src_folder}_pqc_tests test_suite_pqc.c
  # PQC-specific tests
  oap_test_pqc.c
)

# OAP test needs io.c compiled with OAP_TEST_MODE
set(OAP_TEST_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/../io.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../hdr.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../auth.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../srv.c
  ${CMAKE_CURRENT_SOURCE_DIR}/../cli.c
  ${CMAKE_CURRENT_SOURCE_DIR}/common.c
)

# Regular test executable (ECDSA)
add_executable(${src_folder}_test ${${src_folder}_tests} ${OAP_TEST_SOURCES})
set_source_files_properties(${OAP_TEST_SOURCES}
  PROPERTIES COMPILE_DEFINITIONS "OAP_TEST_MODE"
)

disable_test_logging_for_target(${src_folder}_test)
target_link_libraries(${src_folder}_test ouroboros-irm)
target_include_directories(${src_folder}_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_BINARY_DIR}/../..
)

# PQC test executable (ML-DSA)
add_executable(${src_folder}_pqc_test ${${src_folder}_pqc_tests} ${OAP_TEST_SOURCES})
set_source_files_properties(${OAP_TEST_SOURCES}
  TARGET_DIRECTORY ${src_folder}_pqc_test
  PROPERTIES COMPILE_DEFINITIONS "OAP_TEST_MODE"
)

disable_test_logging_for_target(${src_folder}_pqc_test)
target_link_libraries(${src_folder}_pqc_test ouroboros-irm)
target_include_directories(${src_folder}_pqc_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/../..
  ${CMAKE_CURRENT_BINARY_DIR}/../..
)

add_dependencies(build_tests ${src_folder}_test ${src_folder}_pqc_test)

# Regular tests
set(tests_to_run ${${src_folder}_tests})
if(CMAKE_VERSION VERSION_LESS "3.29.0")
  remove(tests_to_run test_suite.c)
else ()
  list(POP_FRONT tests_to_run)
endif()

foreach(test ${tests_to_run})
  get_filename_component(test_name ${test} NAME_WE)
  add_test(${TEST_PREFIX}/${test_name} ${CMAKE_CURRENT_BINARY_DIR}/${src_folder}_test ${test_name})
endforeach(test)

# PQC tests
set(pqc_tests_to_run ${${src_folder}_pqc_tests})
if(CMAKE_VERSION VERSION_LESS "3.29.0")
  remove(pqc_tests_to_run test_suite_pqc.c)
else ()
  list(POP_FRONT pqc_tests_to_run)
endif()

foreach(test ${pqc_tests_to_run})
  get_filename_component(test_name ${test} NAME_WE)
  add_test(${TEST_PREFIX}/${test_name} ${CMAKE_CURRENT_BINARY_DIR}/${src_folder}_pqc_test ${test_name})
endforeach(test)

set_property(TEST ${TEST_PREFIX}/oap_test PROPERTY SKIP_RETURN_CODE 1)
set_property(TEST ${TEST_PREFIX}/oap_test_pqc PROPERTY SKIP_RETURN_CODE 1)
