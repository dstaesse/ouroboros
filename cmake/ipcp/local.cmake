set(LOCAL_SOURCE_DIR "${IPCP_SOURCE_DIR}/local")

set(IPCP_LOCAL_TARGET ipcpd-local CACHE INTERNAL "")

set(IPCP_LOCAL_MPL 100 CACHE STRING
  "Default maximum packet lifetime for the Local IPCP, in ms")

add_executable(${IPCP_LOCAL_TARGET} "${LOCAL_SOURCE_DIR}/main.c" ${IPCP_SOURCES})
target_include_directories(${IPCP_LOCAL_TARGET} PRIVATE ${IPCP_INCLUDE_DIRS})
target_link_libraries(${IPCP_LOCAL_TARGET} PUBLIC ouroboros-dev)
install(TARGETS ${IPCP_LOCAL_TARGET} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
