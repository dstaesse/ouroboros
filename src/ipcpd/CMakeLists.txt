set(IPCP_ACCEPT_TIMEOUT 100 CACHE STRING
  "Timeout for accept in IPCP mainloop threads (ms)")
set(IPCP_SCHED_THREADS 2 CACHE STRING
  "Number of scheduler threads in the normal IPCP")
set(IPCP_MIN_THREADS 4 CACHE STRING
  "Minimum number of worker threads in the IPCP")
set(IPCP_ADD_THREADS 4 CACHE STRING
  "Number of extra threads to start when an IPCP faces thread starvation")

set(IPCP_SOURCES
  # Add source files here
  ${CMAKE_CURRENT_SOURCE_DIR}/ipcp.c
  ${CMAKE_CURRENT_SOURCE_DIR}/shim-data.c
  )

add_subdirectory(local)
add_subdirectory(normal)
add_subdirectory(shim-udp)
add_subdirectory(shim-eth-llc)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)
