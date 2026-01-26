set(LOCAL_SOURCE_DIR "${IPCP_SOURCE_DIR}/local")

set(IPCP_LOCAL_TARGET ipcpd-local CACHE INTERNAL "")

set(IPCP_LOCAL_MPL 100 CACHE STRING
  "Default maximum packet lifetime for the Local IPCP, in ms")

set(IPCP_LOCAL_POLLING FALSE CACHE BOOL
  "Enable active polling in the Local IPCP for low-latency mode")

add_executable(${IPCP_LOCAL_TARGET} "${LOCAL_SOURCE_DIR}/main.c" ${IPCP_SOURCES})
target_include_directories(${IPCP_LOCAL_TARGET} PRIVATE ${IPCP_INCLUDE_DIRS})
target_link_libraries(${IPCP_LOCAL_TARGET} PUBLIC ouroboros-dev)

include(utils/AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(${IPCP_LOCAL_TARGET} -DCONFIG_OUROBOROS_DEBUG)
endif ()

if (IPCP_LOCAL_POLLING)
  add_compile_flags(${IPCP_LOCAL_TARGET} -DCONFIG_IPCP_LOCAL_POLLING)
endif ()

if (IPCP_LOCAL_POLLING)
  add_compile_flags(${IPCP_LOCAL_TARGET} -DCONFIG_IPCP_LOCAL_POLLING)
endif ()

install(TARGETS ${IPCP_LOCAL_TARGET} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
