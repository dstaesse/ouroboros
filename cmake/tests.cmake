include(CTest) # Sets BUILD_TESTING by default to on.
include(utils/TestUtils)

include(utils/DisableTestLogging)

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME AND BUILD_TESTING)
  set(BUILD_TESTS ON)
else ()
  set(BUILD_TESTS OFF)
endif()

add_custom_target(build_tests)

if (BUILD_TESTS)
  add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
  add_dependencies(check build_tests)

  # Add test subdirectories
  add_subdirectory(src/lib/tests)
  add_subdirectory(src/lib/ssm/tests)
  add_subdirectory(src/irmd/oap/tests)
  add_subdirectory(src/ipcpd/unicast/pff/tests)
  add_subdirectory(src/ipcpd/unicast/routing/tests)
  add_subdirectory(src/ipcpd/unicast/dir/tests)
  add_subdirectory(src/irmd/reg/tests)

  # Create coverage target if gcov is available
  include(utils/GenCoverage)
  create_coverage_target()
endif ()
