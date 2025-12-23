function(PROTOBUF_GENERATE_C SRCS HDRS)
  if (NOT ARGN)
    message(SEND_ERROR "Error: PROTOBUF_GENERATE_C() called without any proto files")
    return()
  endif ()

  if (PROTOBUF_GENERATE_C_APPEND_PATH)
    # Create an include path for each file specified
    foreach (FIL ${ARGN})
      get_filename_component(ABS_FIL ${FIL} ABSOLUTE)
      get_filename_component(ABS_PATH ${ABS_FIL} PATH)
      list(FIND _protobuf_include_path ${ABS_PATH} _contains_already)
      if (${_contains_already} EQUAL -1)
        list(APPEND _protobuf_include_path -I ${ABS_PATH})
      endif ()
    endforeach ()
  else ()
    set(_protobuf_include_path -I ${CMAKE_CURRENT_SOURCE_DIR})
  endif ()

  set(${SRCS})
  set(${HDRS})
  foreach(FIL ${ARGN})
    get_filename_component(ABS_FIL ${FIL} ABSOLUTE)
    get_filename_component(FIL_WE ${FIL} NAME_WE)

    list(APPEND ${SRCS} "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb-c.c")
    list(APPEND ${HDRS} "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb-c.h")

    add_custom_command(
      OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb-c.c"
      "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb-c.h"
      COMMAND  ${PROTOBUF_PROTOC_C_EXECUTABLE}
      ARGS --c_out=${CMAKE_CURRENT_BINARY_DIR} ${_protobuf_include_path} ${ABS_FIL}
      DEPENDS ${ABS_FIL} ${PROTOBUF_PROTOC_C_EXECUTABLE}
      COMMENT "Running C protocol buffer compiler on ${FIL}"
      VERBATIM )
  endforeach()

  set_source_files_properties(${${SRCS}} ${${HDRS}} PROPERTIES GENERATED TRUE)
  set(${SRCS} ${${SRCS}} PARENT_SCOPE)
  set(${HDRS} ${${HDRS}} PARENT_SCOPE)
endfunction()

# By default have PROTOBUF_GENERATE_C macro pass -I to protoc
# for each directory where a proto file is referenced.
if (NOT DEFINED PROTOBUF_GENERATE_C_APPEND_PATH)
  set(PROTOBUF_GENERATE_C_APPEND_PATH TRUE)
endif ()

# Find library
find_library(PROTOBUF_C_LIBRARY
  NAMES libprotobuf-c.so libprotobuf-c libprotobuf-c.dylib
  )
mark_as_advanced(PROTOBUF_C_LIBRARY)

# Find the include directory
find_path(PROTOBUF_C_INCLUDE_DIR
  google/protobuf-c/protobuf-c.h
  )
mark_as_advanced(PROTOBUF_C_INCLUDE_DIR)

# Find the protoc-c Executable
find_program(PROTOBUF_PROTOC_C_EXECUTABLE
  NAMES protoc protoc-c
  DOC "The Google Protocol Buffers C Compiler"
  )
mark_as_advanced(PROTOBUF_PROTOC_C_EXECUTABLE)

find_package(PackageHandleStandardArgs)
find_package_handle_standard_args(ProtobufC DEFAULT_MSG
  PROTOBUF_C_LIBRARY PROTOBUF_C_INCLUDE_DIR PROTOBUF_PROTOC_C_EXECUTABLE)

set(PROTOBUF_C_INCLUDE_DIRS ${PROTOBUF_C_INCLUDE_DIR})
