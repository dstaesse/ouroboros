include(CTest) # Sets BUILD_TESTING by default to on.
include(utils/TestUtils)

# Test configuration options
include(config/tests)
include(utils/DisableTestLogging)

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
  set(BUILD_TESTS ON)
else()
  set(BUILD_TESTS OFF)
endif()

add_custom_target(build_tests)

if(BUILD_TESTS)
  add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
  add_dependencies(check build_tests)
endif()

# Test subdirectories are added from their parent CMakeLists.txt files
# via add_subdirectory(tests) - keeping tests with their source code

# Coverage target setup (called after all targets are defined)
function(setup_coverage_target)
  if(BUILD_TESTS)
    include(utils/GenCoverage)
    create_coverage_target()
  endif()
endfunction()
