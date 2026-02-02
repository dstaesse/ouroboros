list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake/utils")

find_package(ProtobufC QUIET)
if(NOT (PROTOBUF_C_INCLUDE_DIRS AND PROTOBUF_C_LIBRARY
         AND PROTOBUF_PROTOC_C_EXECUTABLE))
  message(FATAL_ERROR "Protobuf C compiler required but not found. "
                      "Please install Google Protocol Buffers.")
else()
  message(STATUS "Found protobuf C compiler in ${PROTOBUF_PROTOC_C_EXECUTABLE}")
endif()

# Note: Include dirs are added per-target via target_include_directories
# using ${PROTOBUF_C_INCLUDE_DIRS}
