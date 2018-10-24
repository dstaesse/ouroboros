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

set(IPCP_BROADCAST_TARGET ipcpd-broadcast CACHE INTERNAL "")

set(SOURCE_FILES
  # Add source files here
  connmgr.c
  dt.c
  enroll.c
  main.c
  )

add_executable(ipcpd-broadcast ${SOURCE_FILES} ${IPCP_SOURCES}
  ${LAYER_CONFIG_PROTO_SRCS})
target_link_libraries(ipcpd-broadcast LINK_PUBLIC ouroboros-dev)

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(ipcpd-broadcast -DCONFIG_OUROBOROS_DEBUG)
endif ()

install(TARGETS ipcpd-broadcast RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
