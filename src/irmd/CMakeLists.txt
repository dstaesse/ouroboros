include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(IRMD_ACCEPT_TIMEOUT 100 CACHE STRING
  "Timeout for accept in IRMD mainloop threads (ms)")
set(IRMD_REQ_ARR_TIMEOUT 500 CACHE STRING
  "Timeout for an application to respond to a new flow (ms)")
set(IRMD_FLOW_TIMEOUT 5000 CACHE STRING
  "Timeout for a flow allocation response (ms)")
set(BOOTSTRAP_TIMEOUT 5000 CACHE STRING
  "Timeout for an IPCP to bootstrap (ms)")
set(ENROLL_TIMEOUT 60000 CACHE STRING
  "Timeout for an IPCP to enroll (ms)")
set(REG_TIMEOUT 10000 CACHE STRING
  "Timeout for registering a name (ms)")
set(QUERY_TIMEOUT 3000 CACHE STRING
  "Timeout to query a name with an IPCP (ms)")
set(CONNECT_TIMEOUT 5000 CACHE STRING
  "Timeout to connect an IPCP to another IPCP (ms)")
set(IRMD_MIN_THREADS 8 CACHE STRING
  "Minimum number of worker threads in the IRMd.")
set(IRMD_ADD_THREADS 8 CACHE STRING
  "Number of extra threads to start when the IRMD faces thread starvation")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

set(SOURCE_FILES
  # Add source files here
  api_table.c
  apn_table.c
  ipcp.c
  irm_flow.c
  main.c
  registry.c
  utils.c
  )

add_executable (irmd ${SOURCE_FILES})

target_link_libraries (irmd LINK_PUBLIC ouroboros)

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  add_compile_flags(irmd -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS irmd RUNTIME DESTINATION sbin)

# Enable once irmd has tests
# add_subdirectory(tests)
