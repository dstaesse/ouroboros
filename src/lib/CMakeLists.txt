include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

protobuf_generate_c(IRM_PROTO_SRCS IRM_PROTO_HDRS irmd_messages.proto)
protobuf_generate_c(IPCP_PROTO_SRCS IPCP_PROTO_HDRS ipcpd_messages.proto)
protobuf_generate_c(DIF_CONFIG_PROTO_SRCS DIF_CONFIG_PROTO_HDRS
  dif_config.proto)
protobuf_generate_c(CDAP_PROTO_SRCS CDAP_PROTO_HDRS
  cdap.proto)

if(NOT APPLE)
  find_library(LIBRT_LIBRARIES rt)
  if(NOT LIBRT_LIBRARIES)
    message(FATAL_ERROR "librt not found")
  endif()
else()
  set(LIBRT_LIBRARIES "")
endif()

find_library(LIBPTHREAD_LIBRARIES pthread)
if(NOT LIBPTHREAD_LIBRARIES)
  message(FATAL_ERROR "libpthread not found")
endif()

set(SOURCE_FILES
  # Add source files here
  bitmap.c
  cdap.c
  cdap_req.c
  dev.c
  hashtable.c
  irm.c
  list.c
  lockfile.c
  logs.c
  nsm.c
  sha3.c
  shm_flow_set.c
  shm_rbuff.c
  shm_rdrbuff.c
  sockets.c
  time_utils.c
  utils.c
  )

add_library(ouroboros SHARED ${SOURCE_FILES}
  ${IRM_PROTO_SRCS} ${IPCP_PROTO_SRCS}
  ${DIF_CONFIG_PROTO_SRCS} ${CDAP_PROTO_SRCS})

target_link_libraries(ouroboros ${LIBRT_LIBRARIES}
  ${LIBPTHREAD_LIBRARIES} ${PROTOBUF_C_LIBRARY})

include(MacroAddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  MACRO_ADD_COMPILE_FLAGS(ouroboros -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ouroboros LIBRARY DESTINATION usr/lib)

target_include_directories(ouroboros PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(tests)
