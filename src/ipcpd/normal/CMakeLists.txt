get_filename_component(CURRENT_SOURCE_PARENT_DIR ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)
get_filename_component(CURRENT_BINARY_PARENT_DIR ${CMAKE_CURRENT_BINARY_DIR} DIRECTORY)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CURRENT_SOURCE_PARENT_DIR})
include_directories(${CURRENT_BINARY_PARENT_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

SET(IPCP_NORMAL_TARGET ipcpd-normal CACHE STRING "IPCP_NORMAL_TARGET")

set(SOURCE_FILES
        # Add source files here
        main.c
        pci.c
)

add_executable (ipcpd-normal ${SOURCE_FILES} ${IPCP_SOURCES})
target_link_libraries (ipcpd-normal LINK_PUBLIC ouroboros)

include(MacroAddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
   MACRO_ADD_COMPILE_FLAGS(ipcpd-normal -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ipcpd-normal RUNTIME DESTINATION bin)

# Enable once ipcp-normal has tests
# add_subdirectory(tests)
