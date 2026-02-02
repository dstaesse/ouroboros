# Local IPCP build configuration

set(IPCP_LOCAL_TARGET ipcpd-local)

add_executable(${IPCP_LOCAL_TARGET}
  main.c
  ${IPCP_SOURCES}
)

target_include_directories(${IPCP_LOCAL_TARGET} PRIVATE ${IPCP_INCLUDE_DIRS})
target_link_libraries(${IPCP_LOCAL_TARGET} PRIVATE ouroboros-dev)

ouroboros_target_debug_definitions(${IPCP_LOCAL_TARGET})

if(IPCP_LOCAL_POLLING)
  target_compile_definitions(${IPCP_LOCAL_TARGET} PRIVATE CONFIG_IPCP_LOCAL_POLLING)
endif()

install(TARGETS ${IPCP_LOCAL_TARGET} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
