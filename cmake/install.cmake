# Installation configuration

include(CMakePackageConfigHelpers)

# Public headers
install(FILES ${PUBLIC_HEADER_FILES}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ouroboros)

# Man pages
if(GZIP_EXECUTABLE)
  foreach(_man ${MAN_FILES})
    string(REGEX REPLACE "^.+[.]([1-9]).gz" "\\1" _mansect ${_man})
    install(FILES ${_man} DESTINATION "${CMAKE_INSTALL_MANDIR}/man${_mansect}")
  endforeach()
endif()

# pkg-config files
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ouroboros-dev.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ouroboros-irm.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

set(OUROBOROS_CMAKE_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/Ouroboros")

install(EXPORT OuroborosTargets
  FILE OuroborosTargets.cmake
  NAMESPACE Ouroboros::
  DESTINATION ${OUROBOROS_CMAKE_DIR})

configure_package_config_file(
  "${CMAKE_SOURCE_DIR}/cmake/OuroborosConfig.cmake.in"
  "${CMAKE_BINARY_DIR}/OuroborosConfig.cmake"
  INSTALL_DESTINATION ${OUROBOROS_CMAKE_DIR})

write_basic_package_version_file(
  "${CMAKE_BINARY_DIR}/OuroborosConfigVersion.cmake"
  VERSION ${PACKAGE_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_BINARY_DIR}/OuroborosConfig.cmake"
  "${CMAKE_BINARY_DIR}/OuroborosConfigVersion.cmake"
  DESTINATION ${OUROBOROS_CMAKE_DIR})

# Systemd service file installation
set(SYSTEMD_INSTALL_FILES "DETECT" CACHE STRING
  "Install systemd .service files (NO (never), DETECT (use pkg-config - default),\
  FORCE (always - see SYSTEMD_UNITDIR_OVERRIDE))")
set(SYSTEMD_UNITDIR_OVERRIDE "" CACHE PATH
  "Path to install systemd files. When SYSTEMD_INSTALL_FILES == DETECT, this\
  can be empty to automatically determine the path. Cannot be empty when FORCE.")

if(SYSTEMD_INSTALL_FILES STREQUAL "DETECT" OR SYSTEMD_INSTALL_FILES STREQUAL "FORCE")
  if(SYSTEMD_INSTALL_FILES STREQUAL "DETECT")
    if(PkgConfig_FOUND)
      pkg_check_modules(SYSTEMD "systemd")
    endif()
    if(SYSTEMD_FOUND)
      if(SYSTEMD_UNITDIR_OVERRIDE STREQUAL "")
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE}
          --variable=systemdsystemunitdir systemd
          OUTPUT_VARIABLE SYSTEMD_UNITDIR_INTERNAL)
          string(REGEX REPLACE "[ \t\n]+" "" SYSTEMD_UNITDIR_INTERNAL
          "${SYSTEMD_UNITDIR_INTERNAL}"
        )
      else()
        set(SYSTEMD_UNITDIR_INTERNAL "${SYSTEMD_UNITDIR_OVERRIDE}")
      endif()
    else()
      set(SYSTEMD_UNITDIR_INTERNAL "")
    endif()
  elseif(SYSTEMD_INSTALL_FILES STREQUAL "FORCE")
    if(SYSTEMD_UNITDIR_OVERRIDE STREQUAL "")
      message(FATAL_ERROR "Systemd installation required by user, but no path\
             provided with SYSTEMD_UNITDIR_OVERRIDE.")
    else()
      set(SYSTEMD_UNITDIR_INTERNAL "${SYSTEMD_UNITDIR_OVERRIDE}")
    endif()
  endif()
  if(NOT SYSTEMD_UNITDIR_INTERNAL STREQUAL "")
    message(STATUS "Systemd service installation enabled to: ${SYSTEMD_UNITDIR_INTERNAL}")
    if(LIBTOML_LIBRARIES AND NOT DISABLE_CONFIGFILE)
      set (CONFIGURE_STRING "--config ${OUROBOROS_CONFIG_DIR}/${OUROBOROS_CONFIG_FILE}")
    else()
      set (CONFIGURE_STRING "")
    endif()
    configure_file("${CMAKE_SOURCE_DIR}/ouroboros.service.in"
      "${CMAKE_BINARY_DIR}/ouroboros.service" @ONLY)
    install(FILES "${CMAKE_BINARY_DIR}/ouroboros.service"
      DESTINATION "${SYSTEMD_UNITDIR_INTERNAL}")
  endif()
else()
  message(STATUS "Systemd service installation disabled by user")
endif()

configure_file("${CMAKE_SOURCE_DIR}/cmake/utils/CMakeUninstall.cmake.in"
  "${CMAKE_BINARY_DIR}/cmake/cmakeuninstall.cmake" @ONLY)

add_custom_target(uninstall
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake/cmakeuninstall.cmake)
