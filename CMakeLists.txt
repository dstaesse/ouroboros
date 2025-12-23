cmake_minimum_required(VERSION 2.8.12.2...4.0.3.0)
cmake_policy(VERSION ${CMAKE_VERSION})

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(ouroboros C)

include(GNUInstallDirs)

include(version)
include(package)

include(compiler)

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  if (APPLE)
    set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE STRING
      "Installation Prefix" FORCE)
  else()
    set(CMAKE_INSTALL_PREFIX "/usr" CACHE STRING
      "Installation Prefix" FORCE)
  endif()
endif ()

if (APPLE)
  set(CMAKE_MACOSX_RPATH 1)
  include_directories("/usr/local/include/")
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

include(dependencies)

include(include)
include(lib)
include(ipcp)
include(irmd)
include(tools)
include(tests)
include(doc)

include(install)
