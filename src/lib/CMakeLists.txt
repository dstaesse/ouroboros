include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

find_package(ProtobufC REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})
protobuf_generate_c(IRM_PROTO_SRCS IRM_PROTO_HDRS irmd_messages.proto)
protobuf_generate_c(IPCP_PROTO_SRCS IPCP_PROTO_HDRS ipcpd_messages.proto)
protobuf_generate_c(DIF_CONFIG_PROTO_SRCS DIF_CONFIG_PROTO_HDRS
                                          dif_config.proto)

find_library(LIBRT_LIBRARIES rt)
if(NOT LIBRT_LIBRARIES)
  message(FATAL_ERROR "librt not found")
endif()

find_library(LIBPTHREAD_LIBRARIES pthread)
if(NOT LIBPTHREAD_LIBRARIES)
  message(FATAL_ERROR "libpthread not found")
endif()

set(SOURCE_FILES
  # Add source files here
  bitmap.c
  cdap.c
  da.c
  dev.c
  du_buff.c
  instance_name.c
  ipcp.c
  irm.c
  list.c
  rw_lock.c
  shm_ap_rbuff.c
  shm_du_map.c
  sockets.c
  utils.c
  )

add_library(ouroboros SHARED ${SOURCE_FILES}
  ${IRM_PROTO_SRCS} ${IPCP_PROTO_SRCS} ${DIF_CONFIG_PROTO_SRCS})

target_link_libraries(ouroboros ${LIBRT_LIBRARIES}
  ${LIBPTHREAD_LIBRARIES} ${PROTOBUF_C_LIBRARY})

include(MacroAddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  MACRO_ADD_COMPILE_FLAGS(ouroboros -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ouroboros LIBRARY DESTINATION lib)

target_include_directories(ouroboros PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(tests)
