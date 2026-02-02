# IRMd (IPC Resource Manager daemon) build configuration
# Configuration options are in cmake/config/global.cmake and cmake/config/irmd.cmake

# Generate and install configuration files if TOML support available
# HAVE_TOML is set in cmake/dependencies/irmd/libtoml.cmake
if(HAVE_TOML)
  set(INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}")
  configure_file("${CMAKE_SOURCE_DIR}/irmd.conf.in"
    "${CMAKE_BINARY_DIR}/${OUROBOROS_CONFIG_FILE}.example" @ONLY)
  configure_file("${CMAKE_SOURCE_DIR}/enc.conf.in"
    "${CMAKE_BINARY_DIR}/enc.conf.example" @ONLY)
  install(FILES "${CMAKE_BINARY_DIR}/${OUROBOROS_CONFIG_FILE}.example"
    DESTINATION "${OUROBOROS_CONFIG_DIR}")
  install(FILES "${CMAKE_BINARY_DIR}/enc.conf.example"
    DESTINATION "${OUROBOROS_CONFIG_DIR}")
  install(CODE "
    if(NOT EXISTS \"${OUROBOROS_CONFIG_DIR}/${OUROBOROS_CONFIG_FILE}\")
      file(WRITE \"${OUROBOROS_CONFIG_DIR}/${OUROBOROS_CONFIG_FILE}\" \"\")
    endif()
  ")
  unset(INSTALL_DIR)
endif()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

set(IRMD_SOURCES
  ipcp.c
  configfile.c
  main.c
  oap/io.c
  oap/hdr.c
  oap/auth.c
  oap/srv.c
  oap/cli.c
  reg/flow.c
  reg/ipcp.c
  reg/pool.c
  reg/proc.c
  reg/prog.c
  reg/name.c
  reg/reg.c
)

add_executable(irmd ${IRMD_SOURCES})

target_include_directories(irmd PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include)

target_link_libraries(irmd PRIVATE ouroboros-common)
if(HAVE_TOML)
  target_link_libraries(irmd PRIVATE toml::toml)
endif()

ouroboros_target_debug_definitions(irmd)

install(TARGETS irmd RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

if(BUILD_TESTS)
  add_subdirectory(oap/tests)
  add_subdirectory(reg/tests)
endif()
