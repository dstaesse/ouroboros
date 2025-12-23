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

# Validate that at least one secure random generator is available
if (NOT ((CMAKE_SYSTEM_NAME STREQUAL "FreeBSD") OR APPLE OR
  HAVE_SYS_RANDOM OR HAVE_OPENSSL_RNG OR HAVE_LIBGCRYPT))
  message(FATAL_ERROR "No secure random generator found, "
                      "please install libgcrypt (> 1.7.0) or OpenSSL")
endif ()

mark_as_advanced(SYS_RND_HDR)
