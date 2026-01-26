set(UDP_SOURCE_DIR "${IPCP_SOURCE_DIR}/udp")

set(IPCP_UDP4_TARGET ipcpd-udp4 CACHE INTERNAL "")
set(IPCP_UDP6_TARGET ipcpd-udp6 CACHE INTERNAL "")

set(IPCP_UDP_RD_THR 3 CACHE STRING
  "Number of reader threads in UDP IPCPs")
set(IPCP_UDP_WR_THR 3 CACHE STRING
  "Number of writer threads in UDP IPCPs")
set(IPCP_UDP_MPL 5000 CACHE STRING
    "Default maximum packet lifetime for the UDP IPCPs, in ms")

# Find nsupdate and nslookup for DDNS support
find_program(NSUPDATE_EXECUTABLE
  NAMES nsupdate
  DOC "The nsupdate tool that enables DDNS")

find_program(NSLOOKUP_EXECUTABLE
  NAMES nslookup
  DOC "The nslookup tool that resolves DNS names")

mark_as_advanced(NSLOOKUP_EXECUTABLE NSUPDATE_EXECUTABLE)

if (NSLOOKUP_EXECUTABLE AND NSUPDATE_EXECUTABLE)
  set(DISABLE_DDNS FALSE CACHE BOOL "Disable DDNS support")
  if (NOT DISABLE_DDNS)
    message(STATUS "DDNS support enabled")
    set(HAVE_DDNS TRUE CACHE INTERNAL "")
  else ()
    message(STATUS "DDNS support disabled by user")
    unset(HAVE_DDNS CACHE)
  endif ()
else ()
  if (NSLOOKUP_EXECUTABLE)
    message(STATUS "Install nsupdate to enable DDNS support")
  elseif (NSUPDATE_EXECUTABLE)
    message(STATUS "Install nslookup to enable DDNS support")
  else ()
    message(STATUS "Install nslookup and nsupdate to enable DDNS support")
  endif ()
endif ()

add_executable(${IPCP_UDP4_TARGET} "${UDP_SOURCE_DIR}/udp4.c" ${IPCP_SOURCES})
add_executable(${IPCP_UDP6_TARGET} "${UDP_SOURCE_DIR}/udp6.c" ${IPCP_SOURCES})

foreach(target ${IPCP_UDP4_TARGET} ${IPCP_UDP6_TARGET})
  target_include_directories(${target} PRIVATE ${IPCP_INCLUDE_DIRS})
  target_link_libraries(${target} PUBLIC ouroboros-dev)
endforeach()

include(utils/AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(${IPCP_UDP4_TARGET} -DCONFIG_OUROBOROS_DEBUG)
  add_compile_flags(${IPCP_UDP6_TARGET} -DCONFIG_OUROBOROS_DEBUG)
endif ()

install(TARGETS ${IPCP_UDP4_TARGET} ${IPCP_UDP6_TARGET} RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
