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

set(SOURCE_FILES
  # Add source files here
  addr_auth.c
  cdap_flow.c
  connmgr.c
  dir.c
  enroll.c
  fmgr.c
  frct.c
  gam.c
  main.c
  pff.c
  ribmgr.c
  shm_pci.c
  # Add policies last
  pol/complete.c
  pol/flat.c
  )

add_executable (ipcpd-normal ${SOURCE_FILES} ${IPCP_SOURCES}
  ${FLOW_ALLOC_SRCS})
target_link_libraries (ipcpd-normal LINK_PUBLIC ouroboros)

include(MacroAddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  macro_add_compile_flags(ipcpd-normal -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ipcpd-normal RUNTIME DESTINATION sbin)

# Enable once ipcp-normal has tests
# add_subdirectory(tests)
