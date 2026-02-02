include(CheckCCompilerFlag)

function(test_and_set_c_compiler_flag_global _flag)
  string(REGEX REPLACE "-" "_" _sflag ${_flag})
  string(REGEX REPLACE "=" "_" _sflag ${_sflag})
  # Use -Werror during test so clang rejects unknown flags
  set(CMAKE_REQUIRED_FLAGS "-Werror ${_flag}")
  check_c_compiler_flag(${_flag} COMPILER_SUPPORTS_FLAG_${_sflag})

  if(COMPILER_SUPPORTS_FLAG_${_sflag})
    add_compile_options(${_flag})
  endif()
endfunction()
