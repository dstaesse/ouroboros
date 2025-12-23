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
