cmake_minimum_required(VERSION 2.8.12.2)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(ouroboros C)

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

SET(CMAKE_SKIP_BUILD_RPATH FALSE)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES
  "${CMAKE_INSTALL_PREFIX}/usr/lib" isSystemDir)
IF("${isSystemDir}" STREQUAL "-1")
   SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/usr/lib")
ENDIF("${isSystemDir}" STREQUAL "-1")

message(STATUS "Package name is:            ${PACKAGE_NAME}")
message(STATUS "Package description is:     ${PACKAGE_DESCRIPTION}")
message(STATUS "Package version is:         ${PACKAGE_VERSION}")
message(STATUS "Package URL is:             ${PACKAGE_URL}")
message(STATUS "Package bug-report address: ${PACKAGE_BUGREPORT}")
message(STATUS "Package install prefix:     ${CMAKE_INSTALL_PREFIX}")

include(FindPkgConfig)

include(CompilerUtils)
test_and_set_c_compiler_flag_global(-std=c89)
test_and_set_c_compiler_flag_global(-Wall)
test_and_set_c_compiler_flag_global(-Werror)
test_and_set_c_compiler_flag_global(-Wundef)
test_and_set_c_compiler_flag_global(-fmax-errors=5)

configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/ouroboros.pc.in"
  "${CMAKE_CURRENT_BINARY_DIR}/ouroboros.pc"
  @ONLY)
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ouroboros.pc"
  DESTINATION "/usr/lib/pkgconfig")

enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

# Log directory
set(LOG_DIR "var/log/ouroboros")
install(DIRECTORY DESTINATION ${LOG_DIR})

find_package(ProtobufC REQUIRED)
include_directories(${PROTOBUF_C_INCLUDE_DIRS})

add_subdirectory(src)
add_subdirectory(include)

# Uninstall target
configure_file(
  "${CMAKE_SOURCE_DIR}/cmake/cmake_uninstall.cmake.in"
  "${CMAKE_BINARY_DIR}/cmake/cmake_uninstall.cmake"
  IMMEDIATE @ONLY)

add_custom_target(uninstall
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake/cmake_uninstall.cmake)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PACKAGE_DESCRIPTION}")
set(CPACK_PACKAGE_DESCRIPTION_FILE    "${CMAKE_CURRENT_SOURCE_DIR}/README")
set(CPACK_RESOURCE_FILE_LICENSE       "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_VERSION_MAJOR       "${PACKAGE_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR       "${PACKAGE_VERSION_MINOR}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY
  "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
set(CPACK_GENERATOR                   "TGZ")
set(CPACK_SOURCE_GENERATOR            "TGZ")

include(CPack)

#include(FeatureSummary)
#print_enabled_features()
