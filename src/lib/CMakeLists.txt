include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

protobuf_generate_c(IRM_PROTO_SRCS IRM_PROTO_HDRS irmd_messages.proto)
protobuf_generate_c(IPCP_PROTO_SRCS IPCP_PROTO_HDRS ipcpd_messages.proto)
protobuf_generate_c(DIF_CONFIG_PROTO_SRCS DIF_CONFIG_PROTO_HDRS
  ipcp_config.proto)
protobuf_generate_c(CDAP_PROTO_SRCS CDAP_PROTO_HDRS cdap.proto)
protobuf_generate_c(RO_PROTO_SRCS RO_PROTO_HDRS ro.proto)
protobuf_generate_c(CACEP_PROTO_SRCS CACEP_PROTO_HDRS cacep.proto)
protobuf_generate_c(FRCT_ENROLL_SRCS FRCT_ENROLL_HDRS frct_enroll.proto)

if (NOT APPLE)
  find_library(LIBRT_LIBRARIES rt)
  if (NOT LIBRT_LIBRARIES)
    message(FATAL_ERROR "Could not find librt.")
  endif ()
else ()
  set(LIBRT_LIBRARIES "")
endif ()

find_library(LIBPTHREAD_LIBRARIES pthread)
if (NOT LIBPTHREAD_LIBRARIES)
  message(FATAL_ERROR "Could not find libpthread.")
endif ()

find_path(LINUX_RND_HDR
  sys/random.h
  HINTS /usr/include /usr/local/include
  )

set(SOURCE_FILES
  # Add source files here
  bitmap.c
  btree.c
  cacep.c
  cdap.c
  cdap_req.c
  crc32.c
  dev.c
  hash.c
  hashtable.c
  irm.c
  list.c
  lockfile.c
  logs.c
  md5.c
  nsm.c
  qos.c
  qoscube.c
  random.c
  rib.c
  sha3.c
  shm_flow_set.c
  shm_rbuff.c
  shm_rdrbuff.c
  sockets.c
  time_utils.c
  tpm.c
  utils.c
  )

add_library(ouroboros SHARED ${SOURCE_FILES} ${IRM_PROTO_SRCS}
  ${IPCP_PROTO_SRCS} ${DIF_CONFIG_PROTO_SRCS} ${CDAP_PROTO_SRCS}
  ${CACEP_PROTO_SRCS} ${RO_PROTO_SRCS} ${FRCT_ENROLL_SRCS})

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  add_compile_flags(ouroboros -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

if (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  message(STATUS "Found FreeBSD, using arc4random.")
else()
  if (${LINUX_RND_HDR} STREQUAL "LINUX_RND_HDR-NOTFOUND")
    find_package(OpenSSL)
    if (NOT OPENSSL_FOUND)
      message(STATUS "No secure random generation, please install OpenSSL.")
    else()
      message(STATUS "OpenSSL found")
      include_directories($OPENSSL_INCLUDE_DIR})
      add_compile_flags(ouroboros -DHAVE_OPENSSL)
    endif()
  else ()
    message(STATUS "Found linux random header in ${LINUX_RND_HDR}.")
    include_directories(${LINUX_RND_HDR})
    add_compile_flags(ouroboros -DHAVE_SYS_RANDOM)
  endif ()
endif()

target_link_libraries(ouroboros ${LIBRT_LIBRARIES}
  ${LIBPTHREAD_LIBRARIES} ${PROTOBUF_C_LIBRARY} ${OPENSSL_LIBRARIES})

install(TARGETS ouroboros LIBRARY DESTINATION usr/lib)

target_include_directories(ouroboros PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(tests)
