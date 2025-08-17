get_filename_component(CURRENT_SOURCE_PARENT_DIR
  ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(CURRENT_BINARY_PARENT_DIR
  ${CMAKE_CURRENT_BINARY_DIR} DIRECTORY)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CURRENT_SOURCE_PARENT_DIR})
include_directories(${CURRENT_BINARY_PARENT_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(IPCP_UDP4_TARGET ipcpd-udp4 CACHE INTERNAL "")
set(IPCP_UDP6_TARGET ipcpd-udp6 CACHE INTERNAL "")

set(UDP4_SOURCES
  # Add source files here
  udp4.c
)

set(UDP6_SOURCES
  # Add source files here
  udp6.c
)

add_executable(ipcpd-udp4 ${UDP4_SOURCES} ${IPCP_SOURCES})
target_link_libraries(ipcpd-udp4 LINK_PUBLIC ouroboros-dev)

add_executable(ipcpd-udp6 ${UDP6_SOURCES} ${IPCP_SOURCES})
target_link_libraries(ipcpd-udp6 LINK_PUBLIC ouroboros-dev)


# Find the nsupdate executable
find_program(NSUPDATE_EXECUTABLE
  NAMES nsupdate
  DOC "The nsupdate tool that enables DDNS")

# Find the nslookup executable
find_program(NSLOOKUP_EXECUTABLE
  NAMES nslookup
  DOC "The nslookup tool that resolves DNS names")

mark_as_advanced(NSLOOKUP_EXECUTABLE NSUPDATE_EXECUTABLE)

if (NSLOOKUP_EXECUTABLE AND NSUPDATE_EXECUTABLE)
  set(DISABLE_DDNS FALSE CACHE BOOL "Disable DDNS support")
  if (NOT DISABLE_DNS)
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

set(IPCP_UDP_RD_THR 3 CACHE STRING
  "Number of reader threads in UDP IPCPs")
set(IPCP_UDP_WR_THR 3 CACHE STRING
  "Number of writer threads in UDP IPCPs")
set(IPCP_UDP_MPL 5000 CACHE STRING
    "Default maximum packet lifetime for the UDP IPCPs, in ms")

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(ipcpd-udp4 -DCONFIG_OUROBOROS_DEBUG)
  add_compile_flags(ipcpd-udp6 -DCONFIG_OUROBOROS_DEBUG)
endif ()

install(TARGETS ipcpd-udp4 RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(TARGETS ipcpd-udp6 RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

