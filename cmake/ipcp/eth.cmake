set(ETH_SOURCE_DIR "${IPCP_SOURCE_DIR}/eth")

set(IPCP_ETH_LLC_TARGET ipcpd-eth-llc CACHE INTERNAL "")
set(IPCP_ETH_DIX_TARGET ipcpd-eth-dix CACHE INTERNAL "")

set(IPCP_ETH_RD_THR 1 CACHE STRING
  "Number of reader threads in Ethernet IPCP")
set(IPCP_ETH_WR_THR 1 CACHE STRING
  "Number of writer threads in Ethernet IPCP")
set(IPCP_ETH_QDISC_BYPASS false CACHE BOOL
  "Bypass the Qdisc in the kernel when using raw sockets")
set(IPCP_ETH_LO_MTU 9000 CACHE STRING
  "Restrict Ethernet MTU over loopback interfaces")
set(IPCP_ETH_MGMT_FRAME_SIZE 9000 CACHE STRING
  "Management frame buffer size for Ethernet IPCPs")
set(IPCP_ETH_MPL 100 CACHE STRING
  "Default maximum packet lifetime for the Ethernet IPCPs, in ms")

if (HAVE_RAW_SOCKETS OR HAVE_BPF OR HAVE_NETMAP)
  set(HAVE_ETH TRUE)
else ()
  unset(HAVE_ETH)
endif ()

if (HAVE_ETH)
  add_executable(${IPCP_ETH_LLC_TARGET} "${ETH_SOURCE_DIR}/llc.c" ${IPCP_SOURCES})
  add_executable(${IPCP_ETH_DIX_TARGET} "${ETH_SOURCE_DIR}/dix.c" ${IPCP_SOURCES})

  foreach(target ${IPCP_ETH_LLC_TARGET} ${IPCP_ETH_DIX_TARGET})
    target_include_directories(${target} PRIVATE ${IPCP_INCLUDE_DIRS})
    if (HAVE_BPF AND NOT APPLE)
      target_include_directories(${target} PRIVATE ${BPF_C_INCLUDE_DIR})
    endif ()
    if (HAVE_NETMAP AND NOT APPLE)
      set_target_properties(${target} PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS} -std=c99")
      target_include_directories(${target} PRIVATE ${NETMAP_C_INCLUDE_DIR})
    endif ()
    target_link_libraries(${target} PUBLIC ouroboros-dev)
  endforeach()

  install(TARGETS ${IPCP_ETH_LLC_TARGET} ${IPCP_ETH_DIX_TARGET} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
endif ()
