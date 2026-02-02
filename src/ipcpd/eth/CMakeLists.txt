# Ethernet IPCPs build configuration (LLC and DIX)
# HAVE_ETH detection is in cmake/dependencies.cmake

set(IPCP_ETH_LLC_TARGET ipcpd-eth-llc)
set(IPCP_ETH_DIX_TARGET ipcpd-eth-dix)

add_executable(${IPCP_ETH_LLC_TARGET} llc.c ${IPCP_SOURCES})
add_executable(${IPCP_ETH_DIX_TARGET} dix.c ${IPCP_SOURCES})

foreach(target ${IPCP_ETH_LLC_TARGET} ${IPCP_ETH_DIX_TARGET})
  target_include_directories(${target} PRIVATE ${IPCP_INCLUDE_DIRS})
  if(HAVE_BPF AND NOT APPLE)
    target_include_directories(${target} PRIVATE ${BPF_C_INCLUDE_DIR})
  endif()
  if(HAVE_NETMAP AND NOT APPLE)
    target_compile_options(${target} PRIVATE -std=c99)
    target_include_directories(${target} PRIVATE ${NETMAP_C_INCLUDE_DIR})
  endif()
  target_link_libraries(${target} PRIVATE ouroboros-dev)
  ouroboros_target_debug_definitions(${target})
endforeach()

install(TARGETS ${IPCP_ETH_LLC_TARGET} ${IPCP_ETH_DIX_TARGET}
        RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
