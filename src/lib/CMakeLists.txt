include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(SOURCE_FILES
        # Add source files here
        bitmap.c
        cdap.c
        du_buff.c
        irm.c
        sockets.c
)

add_library(ouroboros SHARED ${SOURCE_FILES})

install(TARGETS ouroboros LIBRARY DESTINATION ${CMAKE_INSTALL_FULL_LIBDIR})
