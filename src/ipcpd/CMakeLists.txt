set(IPCP_SOURCES
        # Add source files here
        ${CMAKE_CURRENT_SOURCE_DIR}/ipcp.c
        ${CMAKE_CURRENT_SOURCE_DIR}/ipcp-data.c
        ${CMAKE_CURRENT_SOURCE_DIR}/timerwheel.c
)

add_subdirectory(local)
add_subdirectory(normal)
add_subdirectory(shim-udp)
if(NOT APPLE)
  add_subdirectory(shim-eth-llc)
endif()
add_subdirectory(tests)
