# Creates the coverage target for test coverage analysis
# Requires HAVE_GCOV to be set (from dependencies/gcov.cmake)
# Uses HAVE_LCOV for optional HTML generation (from dependencies/lcov.cmake)

# Filter patterns for lcov --remove
set(LCOV_FILTERS '*_test.c' '*.h')

# Ignore inconsistent coverage: legitimate gaps in error paths and
# edge cases that are difficult to exercise in unit tests.
function(get_html_coverage_commands OUTPUT_VAR)
  if(HAVE_LCOV)
    set(COMMANDS
      COMMAND ${LCOV_PATH}
        --capture --directory .
        --output-file coverage.info
        > /dev/null 2>&1
      COMMAND ${LCOV_PATH}
        --remove coverage.info ${LCOV_FILTERS}
        --output-file coverage_filtered.info
        --ignore-errors inconsistent
        > /dev/null 2>&1
      COMMAND ${GENHTML_PATH}
        coverage_filtered.info
        --output-directory coverage_html
        > /dev/null 2>&1
      COMMAND ${CMAKE_COMMAND} -E echo ""
      COMMAND ${CMAKE_COMMAND} -E echo "HTML report: ${CMAKE_BINARY_DIR}/coverage_html/index.html"
      COMMAND ${CMAKE_COMMAND} -E echo ""
    )
    set(${OUTPUT_VAR} "${COMMANDS}" PARENT_SCOPE)
  else()
    set(${OUTPUT_VAR} "" PARENT_SCOPE)
  endif()
endfunction()

function(create_informational_target)
  # MESSAGE lines are passed as ARGV, last arg is COMMENT
  list(LENGTH ARGV NUM_ARGS)
  math(EXPR COMMENT_IDX "${NUM_ARGS} - 1")
  list(GET ARGV ${COMMENT_IDX} COMMENT_TEXT)

  # Build command list
  set(COMMANDS
    COMMAND ${CMAKE_COMMAND} -E echo ""
  )
  foreach(i RANGE 0 ${COMMENT_IDX})
    if(NOT i EQUAL ${COMMENT_IDX})
      list(GET ARGV ${i} LINE)
      list(APPEND COMMANDS COMMAND ${CMAKE_COMMAND} -E echo "${LINE}")
    endif()
  endforeach()
  list(APPEND COMMANDS COMMAND ${CMAKE_COMMAND} -E echo "")

  add_custom_target(coverage
    ${COMMANDS}
    COMMENT "${COMMENT_TEXT}"
  )
endfunction()

function(create_coverage_target)
  if(HAVE_GCOV AND NOT DISABLE_COVERAGE)
    get_html_coverage_commands(HTML_COVERAGE_COMMANDS)

    add_custom_target(coverage
      COMMAND ${CMAKE_CTEST_COMMAND} -D ExperimentalStart > /dev/null 2>&1
      COMMAND ${CMAKE_CTEST_COMMAND} -D ExperimentalConfigure > /dev/null 2>&1
      COMMAND ${CMAKE_CTEST_COMMAND} -D ExperimentalBuild > /dev/null 2>&1
      COMMAND ${CMAKE_CTEST_COMMAND} -D ExperimentalTest > /dev/null 2>&1
      COMMAND ${CMAKE_CTEST_COMMAND} -D ExperimentalCoverage > /dev/null 2>&1
      COMMAND ${CMAKE_COMMAND}
        -DPROJECT_SOURCE_DIR=${CMAKE_SOURCE_DIR}
        -DPROJECT_BINARY_DIR=${CMAKE_BINARY_DIR}
        -P ${CMAKE_SOURCE_DIR}/cmake/utils/PrintCoverage.cmake
      ${HTML_COVERAGE_COMMANDS}
      WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
      DEPENDS build_tests
      COMMENT "Running tests with coverage analysis using CTest"
    )
  elseif(HAVE_GCOV)
    create_informational_target(
      "Coverage is currently disabled"
      "To enable coverage analysis, reconfigure with"
      "  cmake -DDISABLE_COVERAGE=OFF .."
      "Coverage disabled"
    )
    message(STATUS "Coverage disabled. Use 'make coverage' for instructions to enable.")
  else()
    create_informational_target(
      "Coverage analysis is not available"
      "Install gcov to enable coverage support"
      "Coverage not available"
    )
  endif()
endfunction()
