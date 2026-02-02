# IPCP (IPC Process) daemons build configuration
# Configuration options and validation are in cmake/config/ipcp/*.cmake

# Common sources shared by all IPCPs (absolute paths for subdirectories)
set(IPCP_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/ipcp.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shim-data.c
)

set(COMMON_SOURCES
  ${CMAKE_CURRENT_SOURCE_DIR}/common/enroll.c
)

set(IPCP_INCLUDE_DIRS
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

add_subdirectory(local)
add_subdirectory(broadcast)
add_subdirectory(unicast)
if(HAVE_ETH)
  add_subdirectory(eth)
endif()
add_subdirectory(udp)
