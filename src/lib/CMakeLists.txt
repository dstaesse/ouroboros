include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

protobuf_generate_c(QOSSPEC_PROTO_SRCS QOSSPEC_PROTO_HDRS
  pb/qos.proto)
protobuf_generate_c(IPCP_CONFIG_PROTO_SRCS IPCP_CONFIG_PROTO_HDRS
  pb/ipcp_config.proto)
protobuf_generate_c(ENROLL_PROTO_SRCS ENROLL_PROTO_HDRS
  pb/enroll.proto)
protobuf_generate_c(CACEP_PROTO_SRCS CACEP_PROTO_HDRS
  pb/cacep.proto)
protobuf_generate_c(IRM_PROTO_SRCS IRM_PROTO_HDRS
  pb/irm.proto)
protobuf_generate_c(IPCP_PROTO_SRCS IPCP_PROTO_HDRS
  pb/ipcp.proto)

if (NOT APPLE)
  find_library(LIBRT_LIBRARIES rt)
  if (NOT LIBRT_LIBRARIES)
    message(FATAL_ERROR "Could not find librt")
  endif ()
else ()
  set(LIBRT_LIBRARIES "")
endif ()

find_library(LIBPTHREAD_LIBRARIES pthread)
if (NOT LIBPTHREAD_LIBRARIES)
  message(FATAL_ERROR "Could not find libpthread")
endif ()

include(CheckSymbolExists)
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D_POSIX_C_SOURCE=200809L)
list(APPEND CMAKE_REQUIRED_DEFINITIONS -D__XSI_VISIBLE=500)
list(APPEND CMAKE_REQUIRED_LIBRARIES pthread)
check_symbol_exists(pthread_mutexattr_setrobust pthread.h HAVE_ROBUST_MUTEX)

if (HAVE_ROBUST_MUTEX)
  set(DISABLE_ROBUST_MUTEXES FALSE CACHE BOOL "Disable robust mutex support")
  if (NOT DISABLE_ROBUST_MUTEXES)
    message(STATUS "Robust mutex support enabled")
    set(HAVE_ROBUST_MUTEX TRUE)
  else ()
    message(STATUS "Robust mutex support disabled by user")
    unset(HAVE_ROBUST_MUTEX)
  endif ()
endif ()

find_library(FUSE_LIBRARIES fuse QUIET)
if (FUSE_LIBRARIES)
  #FIXME: Check for version >= 2.6
  set(DISABLE_FUSE FALSE CACHE BOOL "Disable FUSE support")
  if (NOT DISABLE_FUSE)
    message(STATUS "FUSE support enabled")
    set(FUSE_PREFIX "/tmp/ouroboros" CACHE STRING
    "Mountpoint for RIB filesystem")
    set(HAVE_FUSE TRUE CACHE INTERNAL "")
  else ()
    message(STATUS "FUSE support disabled by user")
    unset(HAVE_FUSE CACHE)
  endif ()
else ()
  message(STATUS "Install FUSE version > 2.6 to enable RIB access")
endif ()

if (NOT HAVE_FUSE)
  set(FUSE_LIBRARIES "")
  set(FUSE_INCLUDE_DIR "")
endif ()

mark_as_advanced(FUSE_LIBRARIES)

find_library(LIBGCRYPT_LIBRARIES gcrypt QUIET)
if (LIBGCRYPT_LIBRARIES)
  find_path(LIBGCRYPT_INCLUDE_DIR gcrypt.h
            HINTS /usr/include /usr/local/include)
  if (LIBGCRYPT_INCLUDE_DIR)
    file(STRINGS ${LIBGCRYPT_INCLUDE_DIR}/gcrypt.h GCSTR
      REGEX "^#define GCRYPT_VERSION ")
    string(REGEX REPLACE "^#define GCRYPT_VERSION \"(.*)\".*$" "\\1"
      GCVER "${GCSTR}")
    if (NOT GCVER VERSION_LESS "1.7.0")
      set(DISABLE_LIBGCRYPT FALSE CACHE BOOL "Disable libgcrypt support")
      if (NOT DISABLE_LIBGCRYPT)
        message(STATUS "libgcrypt support enabled")
        set(HAVE_LIBGCRYPT TRUE CACHE INTERNAL "")
      else ()
        message(STATUS "libgcrypt support disabled by user")
        unset(HAVE_LIBGCRYPT CACHE)
      endif()
    else ()
      message(STATUS "Install version >= \"1.7.0\" to enable libgcrypt support "
                     "(found version \"${GCVER}\")")
    endif()
  endif ()
endif ()

if (NOT HAVE_LIBGCRYPT)
  set(LIBGCRYPT_LIBRARIES "")
  set(LIBGCRYPT_INCLUDE_DIR "")
endif ()

find_package(OpenSSL QUIET)
if (OPENSSL_FOUND)
  set(HAVE_OPENSSL_RNG TRUE)
  if (OPENSSL_VERSION VERSION_LESS "1.1.0")
    message(STATUS "Install version >= \"1.1.0\" to enable OpenSSL support "
                   "(found version \"${OPENSSL_VERSION}\")")
  else ()
    set(DISABLE_OPENSSL FALSE CACHE BOOL "Disable OpenSSL support")
    if (NOT DISABLE_OPENSSL)
      message(STATUS "OpenSSL support enabled")
      set(HAVE_OPENSSL TRUE)
    else()
      message(STATUS "OpenSSL support disabled")
      unset(HAVE_OPENSSL)
    endif()
  endif ()
endif ()

if (NOT HAVE_OPENSSL_RNG)
  set(OPENSSL_INCLUDE_DIR "")
  set(OPENSSL_LIBRARIES "")
  set(OPENSSL_CRYPTO_LIBRARY "")
endif ()

if (APPLE OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  set(SYS_RND_HDR "")
else ()
  find_path(SYS_RND_HDR sys/random.h PATH /usr/include/ /usr/local/include/)
  if (SYS_RND_HDR)
    message(STATUS "Found sys/random.h in ${SYS_RND_HDR}")
    set(HAVE_SYS_RANDOM TRUE)
  else ()
    set(SYS_RND_HDR "")
    unset(HAVE_SYS_RANDOM)
  endif ()
endif()

if (NOT ((CMAKE_SYSTEM_NAME STREQUAL "FreeBSD") OR APPLE OR
  HAVE_SYS_RANDOM OR HAVE_OPENSSL_RNG OR HAVE_LIBGCRYPT))
  message(FATAL_ERROR "No secure random generator found, "
                      "please install libgcrypt (> 1.7.0) or OpenSSL")
endif ()

mark_as_advanced(LIBRT_LIBRARIES LIBPTHREAD_LIBRARIES
  LIBGCRYPT_LIBRARIES OPENSSL_LIBRARIES OPENSSL_CRYPTO_LIBRARY
  SYS_RND_INCLUDE_DIR LIBGCRYPT_INCLUDE_DIR SYS_RND_HDR)

set(SHM_BUFFER_SIZE 4096 CACHE STRING
    "Number of blocks in packet buffer, must be a power of 2")
set(SHM_RBUFF_SIZE 1024 CACHE STRING
    "Number of blocks in rbuff buffer, must be a power of 2")
set(SYS_MAX_FLOWS 10240 CACHE STRING
  "Maximum number of total flows for this system")
set(PROG_MAX_FLOWS 4096 CACHE STRING
  "Maximum number of flows in an application")
set(PROG_RES_FDS 64 CACHE STRING
  "Number of reserved flow descriptors per application")
set(PROG_MAX_FQUEUES 32 CACHE STRING
  "Maximum number of flow sets per application")
set(DU_BUFF_HEADSPACE 256 CACHE STRING
  "Bytes of headspace to reserve for future headers")
set(DU_BUFF_TAILSPACE 32 CACHE STRING
  "Bytes of tailspace to reserve for future tails")
if (NOT APPLE)
  set(PTHREAD_COND_CLOCK "CLOCK_MONOTONIC" CACHE STRING
    "Clock to use for condition variable timing")
else ()
  set(PTHREAD_COND_CLOCK "CLOCK_REALTIME" CACHE INTERNAL
    "Clock to use for condition variable timing")
endif ()
set(SOCKET_TIMEOUT 500 CACHE STRING
  "Default timeout for responses from IPCPs (ms)")
set(SHM_PREFIX "ouroboros" CACHE STRING
  "String to prepend to POSIX shared memory filenames")
set(SHM_RBUFF_PREFIX "/${SHM_PREFIX}.rbuff." CACHE INTERNAL
  "Prefix for rbuff POSIX shared memory filenames")
set(SHM_LOCKFILE_NAME "/${SHM_PREFIX}.lockfile" CACHE INTERNAL
  "Filename for the POSIX shared memory lockfile")
set(SHM_FLOW_SET_PREFIX "/${SHM_PREFIX}.set." CACHE INTERNAL
  "Prefix for the POSIX shared memory flow set")
set(SHM_RDRB_NAME "/${SHM_PREFIX}.rdrb" CACHE INTERNAL
  "Name for the main POSIX shared memory buffer")
set(SHM_RDRB_BLOCK_SIZE "sysconf(_SC_PAGESIZE)" CACHE STRING
  "Packet buffer block size, multiple of pagesize for performance")
set(SHM_RDRB_MULTI_BLOCK TRUE CACHE BOOL
  "Packet buffer multiblock packet support")
set(SHM_RBUFF_LOCKLESS FALSE CACHE BOOL
  "Enable shared memory lockless rbuff support")
set(QOS_DISABLE_CRC TRUE CACHE BOOL
  "Ignores ber setting on all QoS cubes")
set(DELTA_T_MPL 60 CACHE STRING
  "Maximum packet lifetime (s)")
set(DELTA_T_ACK 10 CACHE STRING
  "Maximum time to acknowledge a packet (s)")
set(DELTA_T_RTX 120 CACHE STRING
  "Maximum time to retransmit a packet (s)")
set(FRCT_REORDER_QUEUE_SIZE 256 CACHE STRING
  "Size of the reordering queue, must be a power of 2")
set(FRCT_START_WINDOW 64 CACHE STRING
  "Start window, must be a power of 2")
set(FRCT_LINUX_RTT_ESTIMATOR TRUE CACHE BOOL
  "Use Linux RTT estimator formula instead of the TCP RFC formula")
set(FRCT_RTO_MDEV_MULTIPLIER 2 CACHE STRING
  "Multiplier for deviation term in the RTO: RTO = sRTT + (mdev << X)")
set(FRCT_RTO_INC_FACTOR 0 CACHE STRING
  "Divisor for RTO increase after timeout: RTO += RTX >> X, 0: Karn/Partridge")
set(FRCT_RTO_MIN 250 CACHE STRING
  "Minimum Retransmission Timeout (RTO) for FRCT (us)")
set(FRCT_TICK_TIME 5000 CACHE STRING
  "Tick time for FRCT activity (retransmission, acknowledgments) (us)")
set(RXM_BUFFER_ON_HEAP FALSE CACHE BOOL
  "Store packets for retransmission on the heap instead of in packet buffer")
set(RXM_BLOCKING TRUE CACHE BOOL
  "Use blocking writes for retransmission")
set(RXM_MIN_RESOLUTION 20 CACHE STRING
  "Minimum retransmission delay (ns), as a power to 2")
set(RXM_WHEEL_MULTIPLIER 4 CACHE STRING
  "Factor for retransmission wheel levels as a power to 2")
set(RXM_WHEEL_LEVELS 3 CACHE STRING
  "Number of levels in the retransmission wheel")
set(RXM_WHEEL_SLOTS_PER_LEVEL 256 CACHE STRING
  "Number of slots per level in the retransmission wheel, must be a power of 2")
set(ACK_WHEEL_SLOTS 256 CACHE STRING
  "Number of slots in the acknowledgment wheel, must be a power of 2")
set(ACK_WHEEL_RESOLUTION 18 CACHE STRING
  "Minimum acknowledgment delay (ns), as a power to 2")

if (HAVE_FUSE)
  set(PROC_FLOW_STATS TRUE CACHE BOOL
    "Enable flow statistics tracking for application flows")
    if (PROC_FLOW_STATS)
       message(STATUS "Application flow statistics enabled")
    else ()
       message(STATUS "Application flow statistics disabled")
    endif ()
endif ()

set(SOURCE_FILES_DEV
  # Add source files here
  cacep.c
  dev.c
  )

set(SOURCE_FILES_IRM
  irm.c
)

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
  serdes-oep.c
  sha3.c
  shm_flow_set.c
  shm_rbuff.c
  shm_rdrbuff.c
  sockets.c
  tpm.c
  utils.c
)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

add_library(ouroboros-common SHARED ${SOURCE_FILES_COMMON} ${IRM_PROTO_SRCS}
  ${IPCP_PROTO_SRCS} ${IPCP_CONFIG_PROTO_SRCS} ${QOSSPEC_PROTO_SRCS}
  ${ENROLL_PROTO_SRCS})

add_library(ouroboros-dev SHARED ${SOURCE_FILES_DEV} ${CACEP_PROTO_SRCS})

add_library(ouroboros-irm SHARED ${SOURCE_FILES_IRM})

set_target_properties(ouroboros-common PROPERTIES
  VERSION ${PACKAGE_VERSION}
  SOVERSION ${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR})
set_target_properties(ouroboros-dev PROPERTIES
  VERSION ${PACKAGE_VERSION}
  SOVERSION ${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR})
set_target_properties(ouroboros-irm PROPERTIES
  VERSION ${PACKAGE_VERSION}
  SOVERSION ${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR})

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(ouroboros-common -DCONFIG_OUROBOROS_DEBUG)
  add_compile_flags(ouroboros-dev -DCONFIG_OUROBOROS_DEBUG)
  add_compile_flags(ouroboros-irm -DCONFIG_OUROBOROS_DEBUG)
endif ()

target_link_libraries(ouroboros-common ${LIBRT_LIBRARIES}
  ${LIBPTHREAD_LIBRARIES} ${PROTOBUF_C_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY}
  ${LIBGCRYPT_LIBRARIES} ${FUSE_LIBRARIES})

target_link_libraries(ouroboros-dev ouroboros-common)
target_link_libraries(ouroboros-irm ouroboros-common)

install(TARGETS ouroboros-common LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS ouroboros-dev LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(TARGETS ouroboros-irm LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})

target_include_directories(ouroboros-common PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
  ${SYS_RND_HDR} ${LIBGCRYPT_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})

target_include_directories(ouroboros-dev PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
  ${SYS_RND_HDR} ${LIBGCRYPT_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})

target_include_directories(ouroboros-irm PUBLIC ${CMAKE_CURRENT_BINARY_DIR}
  ${SYS_RND_HDR} ${LIBGCRYPT_INCLUDE_DIR} ${OPENSSL_INCLUDE_DIR})

add_subdirectory(tests)
