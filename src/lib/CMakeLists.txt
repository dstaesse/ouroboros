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

include(CheckSymbolExists)
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_POSIX_C_SOURCE=200809L)
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D__XSI_VISIBLE=500)
list(APPEND CMAKE_REQUIRED_LIBRARIES pthread)
check_symbol_exists(pthread_mutexattr_setrobust pthread.h HAVE_ROBUST_MUTEX)
set(HAVE_ROBUST_MUTEX CACHE STRING "Have robust mutexes")

find_library(LIBGCRYPT_LIBRARIES gcrypt)
if (LIBGCRYPT_LIBRARIES)
  find_path(LIBGCRYPT_INCLUDE_DIR gcrypt.h HINTS /usr/include /usr/local/include)
  if (NOT LIBGCRYPT_INCLUDE_DIR STREQUAL "GRYPT_INCLUDE_DIR-NOTFOUND")
    file(STRINGS ${LIBGCRYPT_INCLUDE_DIR}/gcrypt.h GCSTR
      REGEX "^#define GCRYPT_VERSION ")
    string(REGEX REPLACE "^#define GCRYPT_VERSION \"(.*)\".*$" "\\1"
      GCVER "${GCSTR}")
    message(STATUS "Found libgcrypt: ${LIBGCRYPT_LIBRARIES} (found version \"${GCVER}\")")
    if (NOT GCVER VERSION_LESS "1.7.0")
      set(HAVE_LIBGCRYPT "1" CACHE STRING "Have libgcrypt")
    endif()
  endif ()
else ()
  set(LIBGCRYPT_LIBRARIES "")
  set(LIBGCRYPT_INCLUDE_DIR "")
endif ()

find_package(OpenSSL)
if (OPENSSL_FOUND)
  set(HAVE_OPENSSL "1" CACHE STRING "Have OpenSSL")
else ()
  set (OPENSSL_INCLUDE_DIR "")
endif ()

if (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  set(SYS_RND_HDR "")
else ()
  find_path(SYS_RND_HDR sys/random.h PATH /usr/include/ /usr/local/include/)
  if (NOT SYS_RND_HDR STREQUAL "SYS_RND_HDR-NOTFOUND")
    message(STATUS "Found sys/random.h in ${SYS_RND_HDR}")
    set(HAVE_SYS_RANDOM "1" CACHE STRING "Have random header")
  else ()
    set(SYS_RND_HDR "")
  endif ()
endif()

if (NOT ((CMAKE_SYSTEM_NAME STREQUAL "FreeBSD") OR APPLE OR
  HAVE_SYS_RANDOM OR HAVE_OPENSSL OR HAVE_LIBGCRYPT))
  message(FATAL_ERROR "No secure random generator found, "
                      "please install libgcrypt (> 1.7.0) or OpenSSL"
    )
endif ()

set(SOURCE_FILES
  # Add source files here
  bitmap.c
  btree.c
  cacep.c
  cdap.c
  cdap_req.c
  crc32.c
  dev.c
  frct_pci.c
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
  timerwheel.c
  tpm.c
  utils.c
  )

add_library(ouroboros SHARED ${SOURCE_FILES} ${IRM_PROTO_SRCS}
  ${IPCP_PROTO_SRCS} ${DIF_CONFIG_PROTO_SRCS} ${CDAP_PROTO_SRCS}
  ${CACEP_PROTO_SRCS} ${RO_PROTO_SRCS})

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  add_compile_flags(ouroboros -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

target_link_libraries(ouroboros ${LIBRT_LIBRARIES}
  ${LIBPTHREAD_LIBRARIES} ${PROTOBUF_C_LIBRARY} ${OPENSSL_LIBRARIES}
  ${LIBGCRYPT_LIBRARIES})

install(TARGETS ouroboros LIBRARY DESTINATION usr/lib)

target_include_directories(ouroboros PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
  ${SYS_RND_HDR} ${LIBGCRYPT_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})

add_subdirectory(tests)
