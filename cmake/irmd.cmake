set(IRMD_SOURCE_DIR "${CMAKE_SOURCE_DIR}/src/irmd")
set(IRMD_BINARY_DIR "${CMAKE_BINARY_DIR}/src/irmd")

set(OUROBOROS_CONFIG_DIR /etc/ouroboros CACHE STRING
  "Configuration directory (should be absolute)")

# Configuration file support
set(OUROBOROS_SECURITY_DIR "${OUROBOROS_CONFIG_DIR}/security" CACHE STRING
  "Security directory holding authentication information")
set(OUROBOROS_CA_CRT_DIR "${OUROBOROS_SECURITY_DIR}/cacert" CACHE STRING
  "Directory holding trusted CA certificates")
set(OUROBOROS_SRV_CRT_DIR "${OUROBOROS_SECURITY_DIR}/server" CACHE STRING
  "Directory holding server certificates")
set(OUROBOROS_CLI_CRT_DIR "${OUROBOROS_SECURITY_DIR}/client" CACHE STRING
  "Directory holding client certificates")
set(OUROBOROS_UNTRUSTED_DIR "${OUROBOROS_SECURITY_DIR}/untrusted" CACHE STRING
  "Directory holding untrusted intermediate certificates")

# IRMd timeouts and parameters
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
set(OAP_REPLAY_TIMER 20 CACHE STRING
  "OAP replay protection window (s)")
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

# Configuration file support (libtoml)
if (LIBTOML_LIBRARIES)
  set(DISABLE_CONFIGFILE FALSE CACHE BOOL
    "Disable configuration file support")
  if (NOT DISABLE_CONFIGFILE)
    set(OUROBOROS_CONFIG_FILE irmd.conf CACHE STRING
      "Name of the IRMd configuration file")
    set(HAVE_TOML TRUE)
    message(STATUS "Configuration file support enabled")
    message(STATUS "Configuration directory: ${OUROBOROS_CONFIG_DIR}")
    set(INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}")
    configure_file("${CMAKE_SOURCE_DIR}/irmd.conf.in"
      "${CMAKE_BINARY_DIR}/${OUROBOROS_CONFIG_FILE}.example" @ONLY)
    configure_file("${CMAKE_SOURCE_DIR}/enc.conf.in"
      "${CMAKE_BINARY_DIR}/enc.conf.example" @ONLY)
    install(FILES "${CMAKE_BINARY_DIR}/${OUROBOROS_CONFIG_FILE}.example"
      DESTINATION "${OUROBOROS_CONFIG_DIR}")
    install(FILES "${CMAKE_BINARY_DIR}/enc.conf.example"
      DESTINATION "${OUROBOROS_CONFIG_DIR}")
    install(CODE "
      if (NOT EXISTS \"${OUROBOROS_CONFIG_DIR}/${OUROBOROS_CONFIG_FILE}\")
        file(WRITE \"${OUROBOROS_CONFIG_DIR}/${OUROBOROS_CONFIG_FILE}\" \"\")
      endif()
    ")
    unset(INSTALL_DIR)
  else ()
    message(STATUS "Configuration file support disabled by user")
    unset(OUROBOROS_CONFIG_FILE CACHE)
    set(HAVE_TOML FALSE)
  endif ()
else ()
  message(STATUS "Install tomlc99 for config file support")
  message(STATUS "     https://github.com/cktan/tomlc99")
  unset(HAVE_TOML)
endif ()

configure_file("${IRMD_SOURCE_DIR}/config.h.in"
  "${IRMD_BINARY_DIR}/config.h" @ONLY)

set(IRMD_SOURCES
  "${IRMD_SOURCE_DIR}/ipcp.c"
  "${IRMD_SOURCE_DIR}/configfile.c"
  "${IRMD_SOURCE_DIR}/main.c"
  "${IRMD_SOURCE_DIR}/oap/io.c"
  "${IRMD_SOURCE_DIR}/oap/hdr.c"
  "${IRMD_SOURCE_DIR}/oap/auth.c"
  "${IRMD_SOURCE_DIR}/oap/srv.c"
  "${IRMD_SOURCE_DIR}/oap/cli.c"
  "${IRMD_SOURCE_DIR}/reg/flow.c"
  "${IRMD_SOURCE_DIR}/reg/ipcp.c"
  "${IRMD_SOURCE_DIR}/reg/pool.c"
  "${IRMD_SOURCE_DIR}/reg/proc.c"
  "${IRMD_SOURCE_DIR}/reg/prog.c"
  "${IRMD_SOURCE_DIR}/reg/name.c"
  "${IRMD_SOURCE_DIR}/reg/reg.c"
)

add_executable(irmd ${IRMD_SOURCES})

target_include_directories(irmd PRIVATE
  "${IRMD_SOURCE_DIR}"
  "${IRMD_BINARY_DIR}"
  "${CMAKE_SOURCE_DIR}/include"
  "${CMAKE_BINARY_DIR}/include")

target_link_libraries(irmd PUBLIC ouroboros-common)
if (LIBTOML_LIBRARIES)
  target_link_libraries(irmd PUBLIC ${LIBTOML_LIBRARIES})
endif ()

if (HAVE_TOML)
  target_include_directories(irmd PRIVATE ${LIBTOML_INCLUDE})
endif ()

include(utils/AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(irmd -DCONFIG_OUROBOROS_DEBUG)
endif ()

install(TARGETS irmd RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
