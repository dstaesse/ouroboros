# Compute test name prefix from directory structure
function(compute_test_prefix)
  file(RELATIVE_PATH _prefix "${CMAKE_SOURCE_DIR}/src" "${CMAKE_CURRENT_SOURCE_DIR}")
  string(REGEX REPLACE "/tests$" "" _prefix "${_prefix}")
  set(TEST_PREFIX "${_prefix}" PARENT_SCOPE)
endfunction(compute_test_prefix)
