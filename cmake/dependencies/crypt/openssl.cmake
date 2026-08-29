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

if(OPENSSL_VERSION VERSION_GREATER_EQUAL "3.5.0")
  set(DISABLE_ML FALSE CACHE BOOL
    "Disable ML-KEM/ML-DSA support")
  set(DISABLE_SLH FALSE CACHE BOOL
    "Disable SLH-DSA support")
  if(NOT DISABLE_ML)
    set(HAVE_ML TRUE CACHE INTERNAL
      "OpenSSL ML-KEM/ML-DSA available")
    message(STATUS "OpenSSL ML-KEM/ML-DSA support enabled")
  else()
    message(STATUS "OpenSSL ML-KEM/ML-DSA support disabled")
    unset(HAVE_ML CACHE)
  endif()
  if(NOT DISABLE_SLH)
    set(HAVE_SLH TRUE CACHE INTERNAL
      "OpenSSL SLH-DSA available")
    message(STATUS "OpenSSL SLH-DSA support enabled")
  else()
    message(STATUS "OpenSSL SLH-DSA support disabled")
    unset(HAVE_SLH CACHE)
  endif()
else()
  message(STATUS
    "Install OpenSSL >= 3.5.0 for PQC (ML-KEM/ML-DSA/SLH-DSA)")
  unset(HAVE_ML CACHE)
  unset(HAVE_SLH CACHE)
endif()

if(OPENSSL_VERSION VERSION_GREATER_EQUAL "4.1.0")
  set(HAVE_OPENSSL_4_1 TRUE CACHE INTERNAL
    "OpenSSL 4.1 or later")
else()
  unset(HAVE_OPENSSL_4_1 CACHE)
endif()

# Secure memory options are in cmake/config/global.cmake
