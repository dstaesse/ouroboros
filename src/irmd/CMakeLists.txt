include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(SOURCE_FILES
        # Add source files here
        main.c
        utils.c
)

add_executable (irmd ${SOURCE_FILES})

target_link_libraries (irmd LINK_PUBLIC ouroboros)

include(MacroAddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
   MACRO_ADD_COMPILE_FLAGS(irmd -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS irmd RUNTIME DESTINATION /sbin)

# Enable once irmd has tests
# add_subdirectory(tests)
