# IRMd (IPC Resource Manager daemon) build configuration
# Configuration options are in cmake/config/global.cmake and cmake/config/irmd.cmake

# Generate and install configuration files if TOML support available
# HAVE_TOML is set in cmake/dependencies/irmd/libtoml.cmake
if(HAVE_TOML)
  set(INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}")
  configure_file("${CMAKE_SOURCE_DIR}/irmd.conf.in"
    "${CMAKE_BINARY_DIR}/${OUROBOROS_CONFIG_FILE}.example" @ONLY)
  configure_file("${CMAKE_SOURCE_DIR}/sec.conf.in"
    "${CMAKE_BINARY_DIR}/sec.conf.example" @ONLY)
  install(FILES "${CMAKE_BINARY_DIR}/${OUROBOROS_CONFIG_FILE}.example"
    DESTINATION "${OUROBOROS_CONFIG_DIR}")
  install(FILES "${CMAKE_BINARY_DIR}/sec.conf.example"
    DESTINATION "${OUROBOROS_CONFIG_DIR}")
  install(CODE "
    set(cfg \"\$ENV{DESTDIR}${OUROBOROS_CONFIG_DIR}/${OUROBOROS_CONFIG_FILE}\")
    if(NOT EXISTS \"\${cfg}\")
      file(WRITE \"\${cfg}\" \"\")
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

add_dependencies(irmd version_header)

target_include_directories(irmd PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include)

target_link_libraries(irmd PRIVATE ouroboros-common)
if(HAVE_TOML)
  target_link_libraries(irmd PRIVATE toml::toml)
  # tomlc17.h has // comments and inline functions
  set_source_files_properties(configfile.c PROPERTIES COMPILE_OPTIONS -std=c99)
endif()

ouroboros_target_debug_definitions(irmd)

install(TARGETS irmd RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})

# Certificate stores are public; server and client dirs hold private keys
set(SEC_DIR_PUB OWNER_READ OWNER_WRITE OWNER_EXECUTE
  GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE)
set(SEC_DIR_PRIV OWNER_READ OWNER_WRITE OWNER_EXECUTE)
foreach(dir CA_CRT UNTRUSTED SRV_CRT CLI_CRT)
  set(path "${OUROBOROS_${dir}_DIR}")
  get_filename_component(name "${path}" NAME)
  get_filename_component(parent "${path}" DIRECTORY)
  file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/security/${name}")
  if(dir STREQUAL "SRV_CRT" OR dir STREQUAL "CLI_CRT")
    set(perms ${SEC_DIR_PRIV})
  else()
    set(perms ${SEC_DIR_PUB})
  endif()
  install(DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/security/${name}"
    DESTINATION "${parent}" DIRECTORY_PERMISSIONS ${perms})
endforeach()

if(BUILD_TESTS)
  add_subdirectory(oap/tests)
  add_subdirectory(reg/tests)
endif()
