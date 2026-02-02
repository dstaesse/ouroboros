# Macro to apply test logging settings to a target
# Configuration options are in cmake/config/tests.cmake

macro(disable_test_logging_for_target target)
  if(DISABLE_TESTS_LOGGING)
    target_compile_definitions(${target} PRIVATE OUROBOROS_DISABLE_LOGGING)
  endif()
  if(DISABLE_TESTS_CORE_DUMPS)
    target_compile_definitions(${target} PRIVATE DISABLE_TESTS_CORE_DUMPS)
  endif()
endmacro()
