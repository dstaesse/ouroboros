get_filename_component(CURRENT_SOURCE_PARENT_DIR ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(CURRENT_BINARY_PARENT_DIR ${CMAKE_CURRENT_BINARY_DIR} DIRECTORY)

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
    CHECK_LIBRARY_EXISTS("bsd" "gethostbyname" "" CMAKE_LIB_BSD_HAS_GETHOSTBYNAME)
    IF (CMAKE_LIB_BSD_HAS_GETHOSTBYNAME)
      SET (X11_X_EXTRA_LIBS ${X11_X_EXTRA_LIBS} -lbsd)
    ENDIF (CMAKE_LIB_BSD_HAS_GETHOSTBYNAME)
  ENDIF (CMAKE_LIB_NSL_HAS_GETHOSTBYNAME)
ENDIF(NOT CMAKE_HAVE_GETHOSTBYNAME)

# Find the nsupdate executable
find_program(NSUPDATE_EXECUTABLE
  NAMES nsupdate
  DOC "The nsupdate tool that enables DDNS")

if (${NSUPDATE_EXECUTABLE} STREQUAL "NSUPDATE_EXECUTABLE-NOTFOUND")
  message(FATAL_ERROR "Could not find nsupdate, which is needed for DDNS")
else()
  message("-- Found nsupdate: ${NSUPDATE_EXECUTABLE}")
endif()

SET(IPCP_SHIM_UDP_TARGET ipcpd-shim-udp CACHE STRING "IPCP_SHIM_UDP_TARGET")

set(SHIM_UDP_SOURCES
  # Add source files here
  ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

add_executable (ipcpd-shim-udp ${SHIM_UDP_SOURCES} ${IPCP_SOURCES})
target_link_libraries (ipcpd-shim-udp LINK_PUBLIC ouroboros)

include(MacroAddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  MACRO_ADD_COMPILE_FLAGS(ipcpd-shim-udp -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ipcpd-shim-udp RUNTIME DESTINATION bin)

# Enable once ipcp-shim-udp has tests
add_subdirectory(tests)
