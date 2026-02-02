# Broadcast IPCP build configuration

set(IPCP_BROADCAST_TARGET ipcpd-broadcast)

set(BROADCAST_SOURCES
  connmgr.c
  dt.c
  main.c
)

add_executable(${IPCP_BROADCAST_TARGET}
  ${BROADCAST_SOURCES}
  ${IPCP_SOURCES}
  ${COMMON_SOURCES}
)

target_include_directories(${IPCP_BROADCAST_TARGET} PRIVATE ${IPCP_INCLUDE_DIRS})
target_link_libraries(${IPCP_BROADCAST_TARGET} PRIVATE ouroboros-dev)

ouroboros_target_debug_definitions(${IPCP_BROADCAST_TARGET})

install(TARGETS ${IPCP_BROADCAST_TARGET} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
