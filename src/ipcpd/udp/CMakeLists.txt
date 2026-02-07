# UDP IPCPs build configuration (UDP4 and UDP6)
# DDNS detection is in cmake/dependencies/udp/ddns.cmake

add_executable(${IPCP_UDP4_TARGET} udp4.c ${IPCP_SOURCES})
add_executable(${IPCP_UDP6_TARGET} udp6.c ${IPCP_SOURCES})

foreach(target ${IPCP_UDP4_TARGET} ${IPCP_UDP6_TARGET})
  target_include_directories(${target} PRIVATE ${IPCP_INCLUDE_DIRS})
  target_link_libraries(${target} PRIVATE ouroboros-dev)
  ouroboros_target_debug_definitions(${target})
endforeach()

install(TARGETS ${IPCP_UDP4_TARGET} ${IPCP_UDP6_TARGET}
        RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
