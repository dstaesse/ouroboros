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

SET(IPCP_LOCAL_TARGET ipcpd-local CACHE STRING "IPCP_LOCAL")

set(SHIM_LOCAL_SOURCES
  # Add source files here
  ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

add_executable (ipcpd-local ${SHIM_LOCAL_SOURCES} ${IPCP_SOURCES})
target_link_libraries (ipcpd-local LINK_PUBLIC ouroboros)

include(MacroAddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  MACRO_ADD_COMPILE_FLAGS(ipcpd-local -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ipcpd-local RUNTIME DESTINATION bin)

# Enable once ipcp-local has tests
# add_subdirectory(tests)