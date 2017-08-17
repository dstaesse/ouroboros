set(IPCP_SOURCES
  # Add source files here
  ${CMAKE_CURRENT_SOURCE_DIR}/ipcp.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shim-data.c
  ${CMAKE_CURRENT_SOURCE_DIR}/timerwheel.c
  )

add_subdirectory(local)
add_subdirectory(normal)
add_subdirectory(shim-udp)
add_subdirectory(shim-eth-llc)
if (NOT APPLE)
  add_subdirectory(tests)
endif ()
