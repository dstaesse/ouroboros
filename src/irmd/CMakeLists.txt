include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

find_library(LIBTOML_LIBRARIES toml QUIET)
if (LIBTOML_LIBRARIES)
  set(DISABLE_CONFIGFILE FALSE CACHE BOOL
    "Disable configuration file support")
  if (NOT DISABLE_CONFIGFILE)
    set(OUROBOROS_CONFIG_DIR /etc/ouroboros/ CACHE STRING
      "Configuration directory")
    set(OUROBOROS_CONFIG_FILE irmd.conf CACHE STRING
      "Name of the IRMd configuration file")
    set(HAVE_TOML TRUE)
    message(STATUS "Found TOML C99 library: " ${LIBTOML_LIBRARIES})
    message(STATUS "Configuration file support enabled")
    message(STATUS "Configuration directory: ${OUROBOROS_CONFIG_DIR}")
    set(INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}")
    configure_file("${CMAKE_SOURCE_DIR}/irmd.conf.in"
      "${CMAKE_BINARY_DIR}/irmd.conf.example" @ONLY)
    install(FILES "${CMAKE_BINARY_DIR}/irmd.conf.example"
      DESTINATION "${OUROBOROS_CONFIG_DIR}")
    unset(INSTALL_DIR)
    find_path(LIBTOML_INCLUDE toml.h)
    mark_as_advanced(LIBTOML_LIBRARIES LIBTOML_INCLUDE)
  else ()
    message(STATUS "Configuration file support disabled by user")
    unset(OUROBOROS_CONFIG_FILE CACHE)
    unset(OUROBOROS_CONFIG_DIR CACHE)
    set(HAVE_TOML FALSE)
  endif ()
else ()
  message(STATUS "Install tomlc99 for config file support")
  message(STATUS "     https://github.com/cktan/tomlc99")
  set(LIBTOML_LIBRARIES "")
  unset(DISABLE_CONFIGFILE CACHE)
  unset(HAVE_TOML)
endif ()

set(IRMD_REQ_ARR_TIMEOUT 1000 CACHE STRING
  "Timeout for an application to respond to a new flow (ms)")

set(BOOTSTRAP_TIMEOUT 5000 CACHE STRING
  "Timeout for an IPCP to bootstrap (ms)")
set(ENROLL_TIMEOUT 20000 CACHE STRING
  "Timeout for an IPCP to enroll (ms)")
set(REG_TIMEOUT 20000 CACHE STRING
  "Timeout for registering a name (ms)")
set(QUERY_TIMEOUT 200 CACHE STRING
  "Timeout to query a name with an IPCP (ms)")
set(CONNECT_TIMEOUT 20000 CACHE STRING
  "Timeout to connect an IPCP to another IPCP (ms)")
set(FLOW_ALLOC_TIMEOUT 20000 CACHE STRING
  "Timeout for a flow allocation response (ms)")
set(IRMD_MIN_THREADS 8 CACHE STRING
  "Minimum number of worker threads in the IRMd")
set(IRMD_ADD_THREADS 8 CACHE STRING
  "Number of extra threads to start when the IRMD faces thread starvation")
set(IRMD_PKILL_TIMEOUT 30 CACHE STRING
  "Number of seconds to wait before sending SIGKILL to subprocesses on exit")
set(IRMD_KILL_ALL_PROCESSES TRUE CACHE BOOL
  "Kill all processes on exit")
set(DEBUG_PROTO_OAP FALSE CACHE BOOL
  "Add Flow allocation protocol message output to IRMd debug logging")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

set(SOURCE_FILES
  # Add source files here
  ipcp.c
  configfile.c
  main.c
  oap.c
  reg/flow.c
  reg/ipcp.c
  reg/proc.c
  reg/prog.c
  reg/name.c
  reg/reg.c
  )

add_executable (irmd ${SOURCE_FILES})

target_link_libraries (irmd LINK_PUBLIC ouroboros-common
  ${LIBTOML_LIBRARIES})

if (HAVE_TOML)
  target_include_directories(irmd PUBLIC ${LIBTOML_INCLUDE})
endif ()

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(irmd -DCONFIG_OUROBOROS_DEBUG)
endif ()

install(TARGETS irmd RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

add_subdirectory(reg)
add_subdirectory(tests)
