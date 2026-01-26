set(BROADCAST_SOURCE_DIR "${IPCP_SOURCE_DIR}/broadcast")

set(IPCP_BROADCAST_TARGET ipcpd-broadcast CACHE INTERNAL "")

set(IPCP_BROADCAST_MPL 100 CACHE STRING
  "Default maximum packet lifetime for the Broadcast IPCP, in ms")

set(BROADCAST_SOURCES
  "${BROADCAST_SOURCE_DIR}/connmgr.c"
  "${BROADCAST_SOURCE_DIR}/dt.c"
  "${BROADCAST_SOURCE_DIR}/main.c"
)

add_executable(${IPCP_BROADCAST_TARGET}
  ${BROADCAST_SOURCES}
  ${IPCP_SOURCES}
  ${COMMON_SOURCES}
)

target_include_directories(${IPCP_BROADCAST_TARGET} PRIVATE ${IPCP_INCLUDE_DIRS})
target_link_libraries(${IPCP_BROADCAST_TARGET} PUBLIC ouroboros-dev)

include(utils/AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(${IPCP_BROADCAST_TARGET} -DCONFIG_OUROBOROS_DEBUG)
endif ()

install(TARGETS ${IPCP_BROADCAST_TARGET} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
