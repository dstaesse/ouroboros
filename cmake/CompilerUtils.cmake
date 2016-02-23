include(CheckCCompilerFlag)

function(test_and_set_c_compiler_flag_global _flag)

  string(REGEX REPLACE "-" "_" _sflag ${_flag})
  check_c_compiler_flag(${_flag} COMPILER_SUPPORTS_FLAG_${_sflag})

  if(COMPILER_SUPPORTS_FLAG_${_sflag})
    message(STATUS "Compiler supports flag ${_flag}, added globally")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_flag}" PARENT_SCOPE)
  else(${_retval})
      message(STATUS "Compiler does not support flag ${_flag}, discarded")
  endif()

endfunction(test_and_set_c_compiler_flag_global)
