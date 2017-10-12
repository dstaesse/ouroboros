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

protobuf_generate_c(SHIM_UDP_PROTO_SRCS SHIM_UDP_PROTO_HDRS
  shim_udp_messages.proto)

set(IPCP_SHIM_UDP_TARGET ipcpd-shim-udp CACHE INTERNAL "")

set(SHIM_UDP_SOURCES
  # Add source files here
  ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

add_executable(ipcpd-shim-udp ${SHIM_UDP_SOURCES} ${IPCP_SOURCES}
  ${SHIM_UDP_PROTO_SRCS})
target_link_libraries(ipcpd-shim-udp LINK_PUBLIC ouroboros-common ouroboros-dev
  ${PROTOBUF_C_LIBRARY})

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

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  add_compile_flags(ipcpd-shim-udp -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ipcpd-shim-udp RUNTIME DESTINATION sbin)
