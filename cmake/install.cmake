# Installation configuration

# Install pkg-config files
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ouroboros-dev.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ouroboros-irm.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# Systemd service file installation
set(SYSTEMD_INSTALL_FILES "DETECT" CACHE STRING
  "Install systemd .service files (NO (never), DETECT (use pkg-config - default),\
  FORCE (always - see SYSTEMD_UNITDIR_OVERRIDE))")
set(SYSTEMD_UNITDIR_OVERRIDE "" CACHE PATH
  "Path to install systemd files. When SYSTEMD_INSTALL_FILES == DETECT, this\
  can be empty to automatically determine the path. Cannot be empty when FORCE.")

if (SYSTEMD_INSTALL_FILES STREQUAL "DETECT" OR SYSTEMD_INSTALL_FILES STREQUAL "FORCE")
  if (SYSTEMD_INSTALL_FILES STREQUAL "DETECT")
    pkg_check_modules(SYSTEMD "systemd")
    if (SYSTEMD_FOUND)
      if ("${SYSTEMD_UNITDIR_OVERRIDE}" STREQUAL "")
        execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE}
          --variable=systemdsystemunitdir systemd
          OUTPUT_VARIABLE SYSTEMD_UNITDIR_INTERNAL)
          string(REGEX REPLACE "[ \t\n]+" "" SYSTEMD_UNITDIR_INTERNAL
          "${SYSTEMD_UNITDIR_INTERNAL}"
        )
      else ()
        set(SYSTEMD_UNITDIR_INTERNAL "${SYSTEMD_UNITDIR_OVERRIDE}")
      endif ()
    else ()
      set(SYSTEMD_UNITDIR_INTERNAL "")
    endif ()
  elseif (SYSTEMD_INSTALL_FILES STREQUAL "FORCE")
    if ("${SYSTEMD_UNITDIR_OVERRIDE}" STREQUAL "")
      message(FATAL_ERROR "Systemd installation required by user, but no path\
             provided with SYSTEMD_UNITDIR_OVERRIDE.")
    else ()
      set(SYSTEMD_UNITDIR_INTERNAL "${SYSTEMD_UNITDIR_OVERRIDE}")
    endif ()
  endif()
  if (NOT ${SYSTEMD_UNITDIR_INTERNAL} STREQUAL "")
    message(STATUS "Systemd service installation enabled to: ${SYSTEMD_UNITDIR_INTERNAL}")
    if (LIBTOML_LIBRARIES AND NOT DISABLE_CONFIGFILE)
      set (CONFIGURE_STRING "--config ${OUROBOROS_CONFIG_DIR}/${OUROBOROS_CONFIG_FILE}")
    else ()
      set (CONFIGURE_STRING "")
    endif ()
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/ouroboros.service.in"
      "${CMAKE_CURRENT_BINARY_DIR}/ouroboros.service" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ouroboros.service"
      DESTINATION "${SYSTEMD_UNITDIR_INTERNAL}")
  endif ()
else ()
  message(STATUS "Systemd service installation disabled by user")
endif()

# Uninstall target
configure_file("${CMAKE_SOURCE_DIR}/cmake/utils/CMakeUninstall.cmake.in"
  "${CMAKE_BINARY_DIR}/cmake/cmakeuninstall.cmake" IMMEDIATE @ONLY)

add_custom_target(uninstall
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake/cmakeuninstall.cmake)
