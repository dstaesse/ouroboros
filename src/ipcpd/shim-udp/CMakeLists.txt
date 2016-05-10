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

# Find library needed for gethostbyname.
include(CheckFunctionExists)
CHECK_FUNCTION_EXISTS("gethostbyname" CMAKE_HAVE_GETHOSTBYNAME)
IF(NOT CMAKE_HAVE_GETHOSTBYNAME)
  CHECK_LIBRARY_EXISTS("nsl" "gethostbyname" "" CMAKE_LIB_NSL_HAS_GETHOSTBYNAME)
  IF (CMAKE_LIB_NSL_HAS_GETHOSTBYNAME)
    SET (X11_X_EXTRA_LIBS ${X11_X_EXTRA_LIBS} -lnsl)
  ELSE (CMAKE_LIB_NSL_HAS_GETHOSTBYNAME)
    CHECK_LIBRARY_EXISTS("bsd" "gethostbyname" ""
      CMAKE_LIB_BSD_HAS_GETHOSTBYNAME)
    IF (CMAKE_LIB_BSD_HAS_GETHOSTBYNAME)
      SET (X11_X_EXTRA_LIBS ${X11_X_EXTRA_LIBS} -lbsd)
    ENDIF (CMAKE_LIB_BSD_HAS_GETHOSTBYNAME)
  ENDIF (CMAKE_LIB_NSL_HAS_GETHOSTBYNAME)
ENDIF(NOT CMAKE_HAVE_GETHOSTBYNAME)

# Enable DNS by default
if (NOT DISABLE_DNS MATCHES True)
  # Find the nsupdate executable
  find_program(NSUPDATE_EXECUTABLE
    NAMES nsupdate
    DOC "The nsupdate tool that enables DDNS")

  if (${NSUPDATE_EXECUTABLE} STREQUAL "NSUPDATE_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "Could not find nsupdate, which is needed for DDNS")
  else()
    message("-- Found nsupdate: ${NSUPDATE_EXECUTABLE}")
  endif()

  # Find the nslookup executable
  find_program(NSLOOKUP_EXECUTABLE
    NAMES nslookup
    DOC "The nslookup tool that resolves DNS names")

  if (${NSLOOKUP_EXECUTABLE} STREQUAL "NSLOOKUP_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR
      "Could not find nslookup, which is needed for DNS resolution")
  else()
    message("-- Found nslookup: ${NSLOOKUP_EXECUTABLE}")
  endif()
endif()

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/shim_udp_config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/shim_udp_config.h")

SET(IPCP_SHIM_UDP_TARGET ipcpd-shim-udp CACHE STRING "IPCP_SHIM_UDP_TARGET")

set(SHIM_UDP_SOURCES
  # Add source files here
  ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

add_executable (ipcpd-shim-udp ${SHIM_UDP_SOURCES} ${IPCP_SOURCES}
  "${CMAKE_CURRENT_BINARY_DIR}/shim_udp_config.h")
target_link_libraries (ipcpd-shim-udp LINK_PUBLIC ouroboros)

# Enable DNS by default
if (NOT DISABLE_DNS MATCHES True)
  MACRO_ADD_COMPILE_FLAGS(ipcpd-shim-udp -DCONFIG_OUROBOROS_ENABLE_DNS)
endif()

include(MacroAddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  MACRO_ADD_COMPILE_FLAGS(ipcpd-shim-udp -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ipcpd-shim-udp RUNTIME DESTINATION bin)

# Enable once ipcp-shim-udp has tests
add_subdirectory(tests)
