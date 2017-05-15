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

set(IPCP_NORMAL_TARGET ipcpd-normal CACHE STRING "IPCP_NORMAL_TARGET")

protobuf_generate_c(FLOW_ALLOC_SRCS FLOW_ALLOC_HDRS flow_alloc.proto)
# Add GPB sources of policies last
protobuf_generate_c(FSO_SRCS FSO_HDRS pol/fso.proto)

set(SOURCE_FILES
  # Add source files here
  addr_auth.c
  connmgr.c
  dir.c
  dt.c
  dt_pci.c
  enroll.c
  fa.c
  gam.c
  main.c
  neighbors.c
  pff.c
  ribmgr.c
  routing.c
  sdu_sched.c
  # Add policies last
  pol/complete.c
  pol/flat.c
  pol/link_state.c
  pol/graph.c
  )

add_executable(ipcpd-normal ${SOURCE_FILES} ${IPCP_SOURCES}
  ${FLOW_ALLOC_SRCS} ${FSO_SRCS})
target_link_libraries(ipcpd-normal LINK_PUBLIC ouroboros)

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  add_compile_flags(ipcpd-normal -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ipcpd-normal RUNTIME DESTINATION sbin)

add_subdirectory(pol/tests)
