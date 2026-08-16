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

set(MB_ECN_LAB_FULL FALSE CACHE BOOL
  "Run the full mb-ecn lab rate sweep, up to 10 Gb/s")
if(MB_ECN_LAB_FULL)
  message(STATUS "Full mb-ecn lab rate sweep enabled")
endif()
