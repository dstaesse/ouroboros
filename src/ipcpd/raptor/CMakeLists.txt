get_filename_component(CURRENT_SOURCE_PARENT_DIR
  ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(CURRENT_BINARY_PARENT_DIR
  ${CMAKE_CURRENT_BINARY_DIR} DIRECTORY)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CURRENT_SOURCE_PARENT_DIR})
include_directories(${CURRENT_BINARY_PARENT_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  find_path(RAPTOR_KERNEL_MODULE
    NAMES
    raptor.ko.gz
    HINTS
    /lib/modules/${CMAKE_SYSTEM_VERSION}/extra
  )

  mark_as_advanced(RAPTOR_KERNEL_MODULE)

  if (RAPTOR_KERNEL_MODULE)
    set(DISABLE_RAPTOR FALSE CACHE BOOL
      "Disable support for raptor devices")
    if (NOT DISABLE_RAPTOR)
      message(STATUS "Kernel module for raptor found. Building raptor.")
      set(IPCP_RAPTOR_TARGET ipcpd-raptor CACHE INTERNAL "")

      set(RAPTOR_SOURCES
      # Add source files here
      ${CMAKE_CURRENT_SOURCE_DIR}/main.c)

      add_executable(ipcpd-raptor ${RAPTOR_SOURCES} ${IPCP_SOURCES})
      target_link_libraries(ipcpd-raptor LINK_PUBLIC ouroboros-dev)

      include(AddCompileFlags)
      if (CMAKE_BUILD_TYPE MATCHES "Debug*")
        add_compile_flags(ipcpd-raptor -DCONFIG_OUROBOROS_DEBUG)
      endif ()

      install(TARGETS ipcpd-raptor RUNTIME DESTINATION ${CMAKE_INSTALL_SBINDIR})
    else ()
      message(STATUS "Raptor support disabled by user")
    endif ()
  endif ()
endif ()
