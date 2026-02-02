# - add_compile_flags(<target> <flags>...)
# Add compile flags to a target using modern CMake

macro(add_compile_flags _target)
  target_compile_options(${_target} PRIVATE ${ARGN})
endmacro()
