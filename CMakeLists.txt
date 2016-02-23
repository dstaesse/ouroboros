cmake_minimum_required(VERSION 3.0.0)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
#set(CMAKE_VERBOSE_MAKEFILE ON)

project(ouroboros)

include(GitVersionGen)
GIT_VERSION_GEN()

include(GNUInstallDirs)

set(PACKAGE_NAME        "${CMAKE_PROJECT_NAME}")
set(PACKAGE_DESCRIPTION "The Ouroboros prototype"
  CACHE STRING          "Package description")
set(PACKAGE_URL         "None"
  CACHE STRING          "Package URL")
set(PACKAGE_BUGREPORT   "None"
  CACHE STRING          "Packaged bug-report email")
set(PACKAGE_VERSION     "${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR}"
  CACHE STRING          "Package version")

message(STATUS "Package name is:            ${PACKAGE_NAME}")
message(STATUS "Package description is:     ${PACKAGE_DESCRIPTION}")
message(STATUS "Package version is:         ${PACKAGE_VERSION}")
message(STATUS "Package URL is:             ${PACKAGE_URL}")
message(STATUS "Package bug-report address: ${PACKAGE_BUGREPORT}")
message(STATUS "Package install prefix:     ${CMAKE_INSTALL_PREFIX}")

include(FindPkgConfig)

include(CompilerUtils)
test_and_set_cxx_compiler_flag_global(-Wall)
test_and_set_cxx_compiler_flag_global(-Werror)
test_and_set_cxx_compiler_flag_global(-Wundef)
test_and_set_cxx_compiler_flag_global(-fmax-errors=1)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/ouroboros.pc.in"
  "${CMAKE_CURRENT_BINARY_DIR}/ouroboros.pc"
  @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ouroboros.pc"
  DESTINATION "${CMAKE_INSTALL_FULL_LIBDIR}/pkgconfig")

add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(tests)

# We may have to move this to the subdirs
include(MacroAddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
   MACRO_ADD_COMPILE_FLAGS(ipcpd -DCONFIG_OUROBOROS_DEBUG)
   MACRO_ADD_COMPILE_FLAGS(irmd -DCONFIG_OUROBOROS_DEBUG)
   MACRO_ADD_COMPILE_FLAGS(dad -DCONFIG_OUROBOROS_DEBUG)
   MACRO_ADD_COMPILE_FLAGS(irm -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

include(FeatureSummary)
print_enabled_features()

# Uninstall target
configure_file(
  "${CMAKE_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
  "${CMAKE_BINARY_DIR}/cmake/cmake_uninstall.cmake"
  IMMEDIATE @ONLY)

add_custom_target(uninstall
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake/cmake_uninstall.cmake)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PACKAGE_DESCRIPTION}")
set(CPACK_PACKAGE_VENDOR              "Unknown")
set(CPACK_PACKAGE_DESCRIPTION_FILE    "${CMAKE_CURRENT_SOURCE_DIR}/README")
set(CPACK_RESOURCE_FILE_LICENSE       "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION_MAJOR       "${PACKAGE_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR       "${PACKAGE_VERSION_MINOR}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY   "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")

include(CPack)
