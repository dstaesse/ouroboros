# Common library configuration

set(LIB_SOURCE_DIR "${CMAKE_SOURCE_DIR}/src/lib")
set(LIB_BINARY_DIR "${CMAKE_BINARY_DIR}/src/lib")

# Protobuf files
set_source_files_properties(
  "${LIB_SOURCE_DIR}/pb/model.proto"
  "${LIB_SOURCE_DIR}/pb/ipcp_config.proto"
  "${LIB_SOURCE_DIR}/pb/enroll.proto"
  "${LIB_SOURCE_DIR}/pb/cep.proto"
  "${LIB_SOURCE_DIR}/pb/irm.proto"
  "${LIB_SOURCE_DIR}/pb/ipcp.proto"
  PROPERTIES
  COMPILE_FLAGS "-I${LIB_SOURCE_DIR}/pb"
)

protobuf_generate_c(MODEL_PROTO_SRCS MODEL_PROTO_HDRS
  "${LIB_SOURCE_DIR}/pb/model.proto")
protobuf_generate_c(IPCP_CONFIG_PROTO_SRCS IPCP_CONFIG_PROTO_HDRS
  "${LIB_SOURCE_DIR}/pb/ipcp_config.proto")
protobuf_generate_c(ENROLL_PROTO_SRCS ENROLL_PROTO_HDRS
  "${LIB_SOURCE_DIR}/pb/enroll.proto")
protobuf_generate_c(CEP_PROTO_SRCS CEP_PROTO_HDRS
  "${LIB_SOURCE_DIR}/pb/cep.proto")
protobuf_generate_c(IRM_PROTO_SRCS IRM_PROTO_HDRS
  "${LIB_SOURCE_DIR}/pb/irm.proto")
protobuf_generate_c(IPCP_PROTO_SRCS IPCP_PROTO_HDRS
  "${LIB_SOURCE_DIR}/pb/ipcp.proto")

# Common library source files
set(SOURCE_FILES_COMMON
  bitmap.c
  btree.c
  crc32.c
  crypt.c
  hash.c
  list.c
  lockfile.c
  logs.c
  md5.c
  notifier.c
  protobuf.c
  qoscube.c
  random.c
  rib.c
  serdes-irm.c
  serdes-oep.c
  sha3.c
  shm_flow_set.c
  shm_rbuff.c
  shm_rdrbuff.c
  sockets.c
  tpm.c
  utils.c
)

# Convert relative paths to absolute
set(SOURCE_FILES_COMMON_ABS)
foreach(src ${SOURCE_FILES_COMMON})
  list(APPEND SOURCE_FILES_COMMON_ABS "${LIB_SOURCE_DIR}/${src}")
endforeach()

if (HAVE_OPENSSL)
  set(OPENSSL_SOURCES "${LIB_SOURCE_DIR}/crypt/openssl.c")
else()
  set(OPENSSL_SOURCES "")
endif()

add_library(ouroboros-common SHARED
  ${SOURCE_FILES_COMMON_ABS}
  ${IRM_PROTO_SRCS}
  ${IPCP_PROTO_SRCS}
  ${IPCP_CONFIG_PROTO_SRCS}
  ${MODEL_PROTO_SRCS}
  ${ENROLL_PROTO_SRCS}
  ${OPENSSL_SOURCES})

set_target_properties(ouroboros-common PROPERTIES
  VERSION ${PACKAGE_VERSION}
  SOVERSION ${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR})

include(utils/AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(ouroboros-common -DCONFIG_OUROBOROS_DEBUG)
endif ()

target_include_directories(ouroboros-common PUBLIC
  ${LIB_SOURCE_DIR}
  ${LIB_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
  ${CMAKE_BINARY_DIR}
  ${PROTOBUF_C_INCLUDE_DIRS}
  ${SYS_RND_HDR})

if (LIBGCRYPT_INCLUDE_DIR)
  target_include_directories(ouroboros-common PUBLIC ${LIBGCRYPT_INCLUDE_DIR})
endif ()

if (OPENSSL_INCLUDE_DIR)
  target_include_directories(ouroboros-common PUBLIC ${OPENSSL_INCLUDE_DIR})
endif ()


target_link_libraries(ouroboros-common
  ${LIBRT_LIBRARIES}
  ${LIBPTHREAD_LIBRARIES}
  ${PROTOBUF_C_LIBRARY})

if (OPENSSL_CRYPTO_LIBRARY)
  target_link_libraries(ouroboros-common ${OPENSSL_CRYPTO_LIBRARY})
endif ()

if (LIBGCRYPT_LIBRARIES)
  target_link_libraries(ouroboros-common ${LIBGCRYPT_LIBRARIES})
endif ()

if (FUSE_LIBRARIES)
  target_link_libraries(ouroboros-common ${FUSE_LIBRARIES})
endif ()

install(TARGETS ouroboros-common LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

