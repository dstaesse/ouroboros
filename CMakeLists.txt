cmake_minimum_required(VERSION 2.8.12.2)
cmake_policy(VERSION ${CMAKE_VERSION})

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(ouroboros C)

include(GNUInstallDirs)

set(PACKAGE_VERSION_MAJOR  0)
set(PACKAGE_VERSION_MINOR 18)
set(PACKAGE_VERSION_PATCH  3)

set(PACKAGE_NAME        "${CMAKE_PROJECT_NAME}")
set(PACKAGE_DESCRIPTION "The Ouroboros prototype")
set(PACKAGE_URL         "http://ouroboros.rocks")
set(PACKAGE_BUGREPORT   "http://ouroboros.rocks/bugzilla/")
set(PACKAGE_VERSION
  "${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR}.${PACKAGE_VERSION_PATCH}")

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING
      "Build type (Release, Debug, DebugASan, DebugTSan, DebugLSan, DebugAnalyzer)" FORCE)
endif()

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "/usr" CACHE STRING "Installation Prefix" FORCE)
endif ()

if (APPLE)
  set(CMAKE_MACOSX_RPATH 1)
endif()

if (CMAKE_INSTALL_PREFIX STREQUAL "/usr")
  set(RPATH_PREFIX "")
else ()
  set(RPATH_PREFIX ${CMAKE_INSTALL_PREFIX})
endif ()

set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES
  "${RPATH_PREFIX}/lib" isSystemDir)
IF ("${isSystemDir}" STREQUAL "-1")
  set(CMAKE_INSTALL_RPATH "${RPATH_PREFIX}/lib")
ENDIF ("${isSystemDir}" STREQUAL "-1")

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
# -Wextra may fail on clobbered warning due to pthread_cleanup
test_and_set_c_compiler_flag_global(-Wno-clobbered)
test_and_set_c_compiler_flag_global(-Wextra)
# explicitly add other flags in -Wextra
test_and_set_c_compiler_flag_global(-Wempty-body)
test_and_set_c_compiler_flag_global(-Wignored-qualifiers)
test_and_set_c_compiler_flag_global(-Wimplicit-fallthrough=4)
test_and_set_c_compiler_flag_global(-Wmissing-field-initializers)
test_and_set_c_compiler_flag_global(-Wmissing-parameter-type)
test_and_set_c_compiler_flag_global(-Wold-style-declaration)
test_and_set_c_compiler_flag_global(-Woverride-init)
test_and_set_c_compiler_flag_global(-Wsign-compare)
test_and_set_c_compiler_flag_global(-Wtype-limits)
test_and_set_c_compiler_flag_global(-Wuninitialized)
test_and_set_c_compiler_flag_global(-Wshift-negative-value)
test_and_set_c_compiler_flag_global(-Wunused-parameter)
test_and_set_c_compiler_flag_global(-Wunused-but-set-parameter)
test_and_set_c_compiler_flag_global(-Werror)
test_and_set_c_compiler_flag_global(-Wundef)
test_and_set_c_compiler_flag_global(-Wpointer-arith)
test_and_set_c_compiler_flag_global(-Wstrict-prototypes)
test_and_set_c_compiler_flag_global(-Wvla)
test_and_set_c_compiler_flag_global(-Wswitch-default)
test_and_set_c_compiler_flag_global(-Wreturn-type)
test_and_set_c_compiler_flag_global(-Wunreachable-code)
test_and_set_c_compiler_flag_global(-Wdeclaration-after-statement)
test_and_set_c_compiler_flag_global(-Winfinite-recursion)
test_and_set_c_compiler_flag_global(-fmax-errors=5)
if (CMAKE_BUILD_TYPE STREQUAL "Release")
  test_and_set_c_compiler_flag_global(-O3)
else ()
  test_and_set_c_compiler_flag_global(-g)
endif ()
if (CMAKE_BUILD_TYPE STREQUAL "DebugASan")
  test_and_set_c_compiler_flag_global(-fsanitize=address)
elseif (CMAKE_BUILD_TYPE STREQUAL "DebugTSan")
  test_and_set_c_compiler_flag_global(-fsanitize=thread)
elseif (CMAKE_BUILD_TYPE STREQUAL "DebugLSan")
  test_and_set_c_compiler_flag_global(-fsanitize=leak)
elseif (CMAKE_BUILD_TYPE STREQUAL "DebugAnalyzer")
  test_and_set_c_compiler_flag_global(-fanalyzer)
endif ()

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/ouroboros-dev.pc.in"
  "${CMAKE_CURRENT_BINARY_DIR}/ouroboros-dev.pc" @ONLY)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/ouroboros-irm.pc.in"
  "${CMAKE_CURRENT_BINARY_DIR}/ouroboros-irm.pc" @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ouroboros-dev.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ouroboros-irm.pc"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig")

# modified from https://github.com/ximion/limba
pkg_check_modules(SYSTEMD "systemd")
if (SYSTEMD_FOUND)
  if ("${SYSTEMD_UNITDIR}" STREQUAL "")
    execute_process(COMMAND ${PKG_CONFIG_EXECUTABLE}
      --variable=systemdsystemunitdir systemd
      OUTPUT_VARIABLE SYSTEMD_UNITDIR)
      string(REGEX REPLACE "[ \t\n]+" "" SYSTEMD_UNITDIR
      "${SYSTEMD_UNITDIR}"
    )
  endif ()
  if (NOT ${SYSTEMD_UNITDIR} STREQUAL "")
    message(STATUS "Installing systemd service in: ${SYSTEMD_UNITDIR}")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/ouroboros.service.in"
      "${CMAKE_CURRENT_BINARY_DIR}/ouroboros.service" @ONLY)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/ouroboros.service"
      DESTINATION "${SYSTEMD_UNITDIR}")
  endif ()
endif ()

enable_testing()
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})

find_package(ProtobufC QUIET)
if (NOT (PROTOBUF_C_INCLUDE_DIRS AND PROTOBUF_C_LIBRARY
         AND PROTOBUF_PROTOC_C_EXECUTABLE))
  message(FATAL_ERROR "Protobuf C compiler required but not found. "
                      "Please install Google Protocol Buffers.")
endif ()
include_directories(${PROTOBUF_C_INCLUDE_DIRS})

add_subdirectory(include)
add_subdirectory(src)
add_subdirectory(doc)

# Uninstall target
configure_file("${CMAKE_SOURCE_DIR}/cmake/CmakeUninstall.cmake.in"
  "${CMAKE_BINARY_DIR}/cmake/CmakeUninstall.cmake" IMMEDIATE @ONLY)

add_custom_target(uninstall
  COMMAND ${CMAKE_COMMAND} -P ${CMAKE_BINARY_DIR}/cmake/CmakeUninstall.cmake)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PACKAGE_DESCRIPTION}")
set(CPACK_PACKAGE_DESCRIPTION_FILE    "${CMAKE_CURRENT_SOURCE_DIR}/README")
set(CPACK_PACKAGE_VERSION_MAJOR       "${PACKAGE_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR       "${PACKAGE_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH       "${PACKAGE_VERSION_PATCH}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY
  "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
set(CPACK_GENERATOR                   "TGZ")
set(CPACK_SOURCE_GENERATOR            "TGZ")

include(CPack)

#include(FeatureSummary)
#print_enabled_features()
