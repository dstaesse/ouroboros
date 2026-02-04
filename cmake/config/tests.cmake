# Test configuration options

set(DISABLE_TESTS_LOGGING TRUE CACHE BOOL
  "Disable Ouroboros log output in tests")
if(DISABLE_TESTS_LOGGING)
  message(STATUS "Ouroboros logging in test output disabled")
else()
  message(STATUS "Ouroboros logging in test output enabled")
endif()

set(DISABLE_TESTS_CORE_DUMPS TRUE CACHE BOOL
  "Disable core dumps for tests")
if(DISABLE_TESTS_CORE_DUMPS)
  message(STATUS "Core dumps in tests disabled")
else()
  message(STATUS "Core dumps in tests enabled")
endif()
