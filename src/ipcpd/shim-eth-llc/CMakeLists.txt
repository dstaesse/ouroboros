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

protobuf_generate_c(SHIM_ETH_LLC_PROTO_SRCS SHIM_ETH_LLC_PROTO_HDRS
  shim_eth_llc_messages.proto)

set(IPCP_SHIM_ETH_LLC_TARGET ipcpd-shim-eth-llc
  CACHE STRING "IPCP_SHIM_ETH_LLC_TARGET")

set(SHIM_ETH_LLC_SOURCES
  # Add source files here
  ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

add_executable(ipcpd-shim-eth-llc ${SHIM_ETH_LLC_SOURCES} ${IPCP_SOURCES}
  ${SHIM_ETH_LLC_PROTO_SRCS})
target_link_libraries(ipcpd-shim-eth-llc LINK_PUBLIC ouroboros
  ${PROTOBUF_C_LIBRARY})

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  add_compile_flags(ipcpd-shim-eth-llc -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ipcpd-shim-eth-llc RUNTIME DESTINATION sbin)
