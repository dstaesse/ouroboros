# Userspace RCU (liburcu) - optional. Enables lock-free data-plane key
# rotation; absent => per-flow rwlock fallback. The "bulletproof" flavour
# (urcu-bp) auto-registers reader threads, so application threads need no
# RCU lifecycle plumbing.
if(PkgConfig_FOUND)
  pkg_check_modules(URCU_PKG QUIET IMPORTED_TARGET liburcu-bp)
  if(URCU_PKG_FOUND AND NOT TARGET Urcu::Urcu)
    add_library(Urcu::Urcu ALIAS PkgConfig::URCU_PKG)
  endif()
endif()

if(NOT URCU_PKG_FOUND)
  find_library(URCU_BP_LIBRARY urcu-bp QUIET)
  find_library(URCU_COMMON_LIBRARY urcu-common QUIET)
  find_path(URCU_INCLUDE_DIR urcu-bp.h QUIET)
  if(URCU_BP_LIBRARY AND URCU_COMMON_LIBRARY AND URCU_INCLUDE_DIR)
    set(URCU_PKG_FOUND TRUE)
    if(NOT TARGET Urcu::Urcu)
      add_library(Urcu::Urcu INTERFACE IMPORTED)
      set_target_properties(Urcu::Urcu PROPERTIES
        INTERFACE_LINK_LIBRARIES "${URCU_BP_LIBRARY};${URCU_COMMON_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${URCU_INCLUDE_DIR}")
    endif()
  endif()
endif()

if(URCU_PKG_FOUND)
  set(DISABLE_LIBURCU FALSE CACHE BOOL "Disable liburcu (RCU) support")
  if(NOT DISABLE_LIBURCU)
    if(URCU_PKG_VERSION)
      message(STATUS "liburcu (RCU) support enabled (version ${URCU_PKG_VERSION})")
    else()
      message(STATUS "liburcu (RCU) support enabled")
    endif()
    set(HAVE_LIBURCU TRUE CACHE INTERNAL "Userspace RCU (liburcu) available")
  else()
    message(STATUS "liburcu (RCU) support disabled by user")
    unset(HAVE_LIBURCU CACHE)
  endif()
else()
  message(STATUS "Install liburcu (urcu-bp) for lock-free data-plane re-keying")
  unset(HAVE_LIBURCU CACHE)
endif()

mark_as_advanced(URCU_BP_LIBRARY URCU_COMMON_LIBRARY URCU_INCLUDE_DIR)
