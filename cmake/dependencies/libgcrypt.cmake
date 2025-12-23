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

mark_as_advanced(LIBGCRYPT_LIBRARIES LIBGCRYPT_INCLUDE_DIR)
