include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(SOURCE_FILES
        # Add source files here
        main.c
        pci.c
)

add_executable (ipcpd ${SOURCE_FILES})

target_link_libraries (ipcpd LINK_PUBLIC ouroboros)

include(MacroAddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
   MACRO_ADD_COMPILE_FLAGS(ipcpd -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ipcpd RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
