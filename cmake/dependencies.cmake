find_package(PkgConfig QUIET)
include(CheckSymbolExists)

# System libraries and features
include(dependencies/system/protobufc)
include(dependencies/system/libraries)
include(dependencies/system/explicit_bzero)
include(dependencies/system/robustmutex)
include(dependencies/system/fuse)
include(dependencies/system/sysrandom)

# Cryptography
include(dependencies/crypt/openssl)
include(dependencies/crypt/libgcrypt)

# IRMd
include(dependencies/irmd/libtoml)

# Ethernet IPCP backends
include(dependencies/eth/rawsockets)
include(dependencies/eth/bpf)
include(dependencies/eth/netmap)
if(HAVE_RAW_SOCKETS OR HAVE_BPF OR HAVE_NETMAP)
  set(HAVE_ETH TRUE CACHE INTERNAL "Ethernet IPCP support available")
else()
  unset(HAVE_ETH CACHE)
endif()

# UDP IPCP
include(dependencies/udp/ddns)

# Coverage tools
include(dependencies/coverage/gcov)
include(dependencies/coverage/lcov)

# Validate that at least one secure random generator is available
if(NOT ((CMAKE_SYSTEM_NAME STREQUAL "FreeBSD") OR APPLE OR
  HAVE_SYS_RANDOM OR HAVE_OPENSSL_RNG OR HAVE_LIBGCRYPT))
  message(FATAL_ERROR "No secure random generator found, "
                      "please install libgcrypt (> 1.7.0) or OpenSSL")
endif()


