cmake_minimum_required(VERSION 3.19)

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

project(ouroboros C)

include(GNUInstallDirs)

include(utils/DebugTargets)

include(version)
include(package)

include(compiler)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  if(APPLE)
    set(CMAKE_INSTALL_PREFIX "/usr/local" CACHE STRING
      "Installation Prefix" FORCE)
  else()
    set(CMAKE_INSTALL_PREFIX "/usr" CACHE STRING
      "Installation Prefix" FORCE)
  endif()
endif()

if(APPLE)
  set(CMAKE_MACOSX_RPATH 1)
  # Homebrew installs to /usr/local/include on Intel, /opt/homebrew/include on ARM
  set(APPLE_INCLUDE_DIRS "/usr/local/include" "/opt/homebrew/include"
      CACHE INTERNAL "Apple system include directories")
endif()

if(CMAKE_INSTALL_PREFIX STREQUAL "/usr")
  set(RPATH_PREFIX "")
else()
  set(RPATH_PREFIX ${CMAKE_INSTALL_PREFIX})
endif()

set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

list(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES
  "${RPATH_PREFIX}/${CMAKE_INSTALL_LIBDIR}" isSystemDir)
if(isSystemDir STREQUAL "-1")
  set(CMAKE_INSTALL_RPATH "${RPATH_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
endif()

include(dependencies)

# Configuration options (must be loaded before component modules)
include(config/global)
include(config/lib)
include(config/ssm)
include(config/irmd)
include(config/ipcp/common)
include(config/ipcp/unicast)
include(config/ipcp/broadcast)
include(config/ipcp/local)
include(config/ipcp/eth)
include(config/ipcp/udp)

include(tests)
include(include)
add_subdirectory(src/lib)
add_subdirectory(src/irmd)
add_subdirectory(src/ipcpd)
add_subdirectory(src/tools)
setup_coverage_target()
include(doc)

include(install)
