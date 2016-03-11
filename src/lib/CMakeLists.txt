include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(SOURCE_FILES
        # Add source files here
        bitmap.c
        cdap.c
        da.c
        du_buff.c
        ipcp.c
        irm.c
        rina_name.c
        sockets.c
)

add_library(ouroboros SHARED ${SOURCE_FILES})

include(MacroAddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
   MACRO_ADD_COMPILE_FLAGS(ouroboros -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS ouroboros LIBRARY DESTINATION lib)

add_subdirectory(tests)
