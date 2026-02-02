find_library(LIBTOML_LIBRARY toml QUIET)
if(LIBTOML_LIBRARY)
  find_path(LIBTOML_INCLUDE_DIR toml.h)
  set(DISABLE_CONFIGFILE FALSE CACHE BOOL
    "Disable configuration file support")
  if(NOT DISABLE_CONFIGFILE)
    set(OUROBOROS_CONFIG_FILE irmd.conf CACHE STRING
      "Name of the IRMd configuration file")
    set(HAVE_TOML TRUE CACHE INTERNAL "TOML configuration file support available")
    message(STATUS "Configuration file support enabled")
    message(STATUS "Configuration directory: ${OUROBOROS_CONFIG_DIR}")
    # Create imported target for consistency with other dependencies
    if(NOT TARGET toml::toml)
      add_library(toml::toml UNKNOWN IMPORTED)
      set_target_properties(toml::toml PROPERTIES
        IMPORTED_LOCATION "${LIBTOML_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${LIBTOML_INCLUDE_DIR}")
    endif()
  else()
    message(STATUS "Configuration file support disabled by user")
    unset(OUROBOROS_CONFIG_FILE CACHE)
    unset(HAVE_TOML CACHE)
  endif()
  mark_as_advanced(LIBTOML_LIBRARY LIBTOML_INCLUDE_DIR)
else()
  message(STATUS "Install tomlc99 for config file support")
  message(STATUS "     https://github.com/cktan/tomlc99")
  unset(HAVE_TOML CACHE)
endif()
