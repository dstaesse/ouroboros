find_package(PkgConfig QUIET)
include(CheckSymbolExists)

# System libraries and features
include(dependencies/system/protobufc)
include(dependencies/system/libraries)
include(dependencies/system/explicit_bzero)
include(dependencies/system/robustmutex)
include(dependencies/system/fuse)
include(dependencies/system/liburcu)
include(dependencies/system/sysrandom)

# Cryptography
include(dependencies/crypt/openssl)
include(dependencies/crypt/libgcrypt)

# IRMd
include(dependencies/irmd/libtoml)

# Ethernet PoA backends. netmap is last: it overrides the others.
include(dependencies/eth/rawsockets)
include(dependencies/eth/bpf)
include(dependencies/eth/netmap)

# The Ethernet PoA needs a backend to send and receive frames.
if(HAVE_RAW_SOCKETS OR HAVE_BPF OR HAVE_NETMAP)
  set(HAVE_ETH TRUE)
else()
  message(STATUS "No Ethernet backend, Ethernet PoAs disabled")
  unset(HAVE_ETH)
endif()

# Coverage tools
include(dependencies/coverage/gcov)
include(dependencies/coverage/lcov)

# Validate that at least one secure random generator is available
if(NOT ((CMAKE_SYSTEM_NAME STREQUAL "FreeBSD") OR APPLE OR
  HAVE_SYS_RANDOM OR HAVE_OPENSSL_RNG OR HAVE_LIBGCRYPT))
  message(FATAL_ERROR "No secure random generator found, "
                      "please install libgcrypt (> 1.7.0) or OpenSSL")
endif()


