# Ouroboros libraries build configuration
# Configuration options are in cmake/config/lib.cmake

protobuf_generate_c(MODEL_PROTO_SRCS MODEL_PROTO_HDRS
  "${CMAKE_CURRENT_SOURCE_DIR}/pb/model.proto")
protobuf_generate_c(IPCP_CONFIG_PROTO_SRCS IPCP_CONFIG_PROTO_HDRS
  "${CMAKE_CURRENT_SOURCE_DIR}/pb/ipcp_config.proto")
protobuf_generate_c(ENROLL_PROTO_SRCS ENROLL_PROTO_HDRS
  "${CMAKE_CURRENT_SOURCE_DIR}/pb/enroll.proto")
protobuf_generate_c(CEP_PROTO_SRCS CEP_PROTO_HDRS
  "${CMAKE_CURRENT_SOURCE_DIR}/pb/cep.proto")
protobuf_generate_c(IRM_PROTO_SRCS IRM_PROTO_HDRS
  "${CMAKE_CURRENT_SOURCE_DIR}/pb/irm.proto")
protobuf_generate_c(IPCP_PROTO_SRCS IPCP_PROTO_HDRS
  "${CMAKE_CURRENT_SOURCE_DIR}/pb/ipcp.proto")

set(SOURCE_FILES_COMMON
  bitmap.c
  btree.c
  crc32.c
  crypt.c
  hash.c
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
  ssm/flow_set.c
  ssm/rbuff.c
  ssm/pool.c
  sockets.c
  tpm.c
  utils.c
)

if(HAVE_OPENSSL)
  list(APPEND SOURCE_FILES_COMMON crypt/openssl.c)
endif()

add_library(ouroboros-common SHARED
  ${SOURCE_FILES_COMMON}
  ${IRM_PROTO_SRCS}
  ${IPCP_PROTO_SRCS}
  ${IPCP_CONFIG_PROTO_SRCS}
  ${MODEL_PROTO_SRCS}
  ${ENROLL_PROTO_SRCS})

set_target_properties(ouroboros-common PROPERTIES
  VERSION ${PACKAGE_VERSION}
  SOVERSION ${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR})

ouroboros_target_debug_definitions(ouroboros-common)

target_include_directories(ouroboros-common
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
    $<BUILD_INTERFACE:${CMAKE_BINARY_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${SYS_RND_HDR}
    ${APPLE_INCLUDE_DIRS})

target_link_libraries(ouroboros-common
  PRIVATE
    ${LIBRT_LIBRARIES}
    Threads::Threads
  PUBLIC
    ProtobufC::ProtobufC)

if(HAVE_OPENSSL)
  target_link_libraries(ouroboros-common PUBLIC OpenSSL::Crypto)
endif()

if(HAVE_LIBGCRYPT)
  target_link_libraries(ouroboros-common PUBLIC Gcrypt::Gcrypt)
endif()

if(HAVE_FUSE)
  target_link_libraries(ouroboros-common PRIVATE Fuse::Fuse)
endif()

install(TARGETS ouroboros-common
  EXPORT OuroborosTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

set(SOURCE_FILES_DEV
  cep.c
  dev.c
)

add_library(ouroboros-dev SHARED
  ${SOURCE_FILES_DEV}
  ${CEP_PROTO_SRCS})

set_target_properties(ouroboros-dev PROPERTIES
  VERSION ${PACKAGE_VERSION}
  SOVERSION ${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR})

ouroboros_target_debug_definitions(ouroboros-dev)

target_include_directories(ouroboros-dev
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${SYS_RND_HDR})

target_link_libraries(ouroboros-dev PUBLIC ouroboros-common)

install(TARGETS ouroboros-dev
  EXPORT OuroborosTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

add_library(ouroboros-irm SHARED irm.c)

set_target_properties(ouroboros-irm PROPERTIES
  VERSION ${PACKAGE_VERSION}
  SOVERSION ${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR})

ouroboros_target_debug_definitions(ouroboros-irm)

target_include_directories(ouroboros-irm
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_BINARY_DIR}
    ${SYS_RND_HDR})

target_link_libraries(ouroboros-irm PUBLIC ouroboros-common)

install(TARGETS ouroboros-irm
  EXPORT OuroborosTargets
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/ssm/ssm.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/ssm.h" @ONLY)

if(BUILD_TESTS)
  add_subdirectory(tests)
  add_subdirectory(ssm/tests)
endif()
