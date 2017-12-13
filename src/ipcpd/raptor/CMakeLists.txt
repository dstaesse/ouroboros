get_filename_component(CURRENT_SOURCE_PARENT_DIR
  ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(CURRENT_BINARY_PARENT_DIR
  ${CMAKE_CURRENT_BINARY_DIR} DIRECTORY)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CURRENT_SOURCE_PARENT_DIR})
include_directories(${CURRENT_BINARY_PARENT_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

protobuf_generate_c(RAPTOR_PROTO_SRCS RAPTOR_PROTO_HDRS
  raptor_messages.proto)

set(IPCP_RAPTOR_TARGET ipcpd-raptor
  CACHE STRING "IPCP_RAPTOR_TARGET")

set(RAPTOR_SOURCES
  # Add source files here
  ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

add_executable(ipcpd-raptor ${RAPTOR_SOURCES} ${IPCP_SOURCES}
  ${RAPTOR_PROTO_SRCS})
target_link_libraries(ipcpd-raptor LINK_PUBLIC ouroboros
  ${PROTOBUF_C_LIBRARY})

test_and_set_c_compiler_flag_global(-std=c99)

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  add_compile_flags(ipcpd-raptor -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ipcpd-raptor RUNTIME DESTINATION sbin)
