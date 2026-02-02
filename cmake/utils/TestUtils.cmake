# Compute test name prefix from directory structure
function(compute_test_prefix)
  file(RELATIVE_PATH _prefix "${CMAKE_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}")
  string(REGEX REPLACE "/tests$" "" _prefix "${_prefix}")
  set(TEST_PREFIX "${_prefix}" PARENT_SCOPE)
endfunction()

# Register tests from a test executable with the test framework
# Usage: ouroboros_register_tests(TARGET <target> TESTS <test_list> [ENVIRONMENT <env>])
# The TESTS argument should be the test list variable created by create_test_sourcelist
function(ouroboros_register_tests)
  cmake_parse_arguments(PARSE_ARGV 0 ARG "" "TARGET;ENVIRONMENT" "TESTS")

  if(NOT ARG_TARGET)
    message(FATAL_ERROR "ouroboros_register_tests: TARGET required")
  endif()

  if(NOT ARG_TESTS)
    message(FATAL_ERROR "ouroboros_register_tests: TESTS required")
  endif()

  # First entry is the test driver, skip it
  set(_tests ${ARG_TESTS})
  list(POP_FRONT _tests)

  foreach (test_src ${_tests})
    get_filename_component(test_name ${test_src} NAME_WE)
    add_test(${TEST_PREFIX}/${test_name}
             ${CMAKE_CURRENT_BINARY_DIR}/${ARG_TARGET} ${test_name})
    # All Ouroboros tests support skip return code
    set_property(TEST ${TEST_PREFIX}/${test_name} PROPERTY SKIP_RETURN_CODE 1)
    # Optional environment variables
    if(ARG_ENVIRONMENT)
      set_property(TEST ${TEST_PREFIX}/${test_name}
                   PROPERTY ENVIRONMENT "${ARG_ENVIRONMENT}")
    endif()
  endforeach ()
endfunction()
