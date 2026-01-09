find_program(GCOV_PATH gcov)

if (GCOV_PATH)
  set(HAVE_GCOV TRUE CACHE INTERNAL "")
  message(STATUS "gcov found - coverage analysis available")
else ()
  set(HAVE_GCOV FALSE CACHE INTERNAL "")
  message(STATUS "gcov not found - coverage analysis not available")
endif ()

mark_as_advanced(GCOV_PATH)
