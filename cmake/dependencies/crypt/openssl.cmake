find_package(OpenSSL QUIET)
if(NOT OPENSSL_FOUND)
  message(STATUS "Install OpenSSL version >= 3.0.0 to enable OpenSSL support")
  unset(HAVE_OPENSSL_RNG)
  unset(HAVE_OPENSSL CACHE)
  return()
endif()

set(HAVE_OPENSSL_RNG TRUE)

if(OPENSSL_VERSION VERSION_LESS "3.0.0")
  message(STATUS "Install version >= 3.0.0 to enable OpenSSL support "
                 "(found version \"${OPENSSL_VERSION}\")")
  return()
endif()

set(DISABLE_OPENSSL FALSE CACHE BOOL "Disable OpenSSL support")
if(DISABLE_OPENSSL)
  message(STATUS "OpenSSL support disabled")
  unset(HAVE_OPENSSL CACHE)
  return()
endif()

message(STATUS "OpenSSL support enabled, found version ${OPENSSL_VERSION}")
set(HAVE_OPENSSL TRUE CACHE INTERNAL
  "OpenSSL cryptography support available")

if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.4.0")
  set(DISABLE_ML_KEM FALSE CACHE BOOL
    "Disable ML-KEM support")
  set(DISABLE_ML_DSA FALSE CACHE BOOL
    "Disable ML-DSA support")
  if(NOT DISABLE_ML_KEM)
    set(HAVE_OPENSSL_ML_KEM TRUE CACHE INTERNAL
      "OpenSSL ML-KEM available")
    message(STATUS "OpenSSL ML-KEM support enabled")
  else()
    message(STATUS "OpenSSL ML-KEM support disabled")
    unset(HAVE_OPENSSL_ML_KEM CACHE)
  endif()
  if(NOT DISABLE_ML_DSA)
    set(HAVE_OPENSSL_ML_DSA TRUE CACHE INTERNAL
      "OpenSSL ML-DSA available")
    message(STATUS "OpenSSL ML-DSA support enabled")
  else()
    message(STATUS "OpenSSL ML-DSA support disabled")
    unset(HAVE_OPENSSL_ML_DSA CACHE)
  endif()
else()
  message(STATUS
    "Install OpenSSL >= 3.4.0 for ML-KEM/ML-DSA")
  unset(HAVE_OPENSSL_ML_KEM CACHE)
  unset(HAVE_OPENSSL_ML_DSA CACHE)
endif()

if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.5.0")
  set(DISABLE_SLH_DSA FALSE CACHE BOOL
    "Disable SLH-DSA support")
  if(NOT DISABLE_SLH_DSA)
    set(HAVE_OPENSSL_SLH_DSA TRUE CACHE INTERNAL
      "OpenSSL SLH-DSA available")
    message(STATUS "OpenSSL SLH-DSA support enabled")
  else()
    message(STATUS "OpenSSL SLH-DSA support disabled")
    unset(HAVE_OPENSSL_SLH_DSA CACHE)
  endif()
else()
  message(STATUS
    "Install OpenSSL >= 3.5.0 for SLH-DSA")
  unset(HAVE_OPENSSL_SLH_DSA CACHE)
endif()

# Secure memory options are in cmake/config/global.cmake
