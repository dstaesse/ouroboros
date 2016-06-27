include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(SOURCE_FILES
        # Add source files here
        echo.c
)

add_executable(echo-app ${SOURCE_FILES})

target_link_libraries(echo-app LINK_PUBLIC ouroboros)

install(TARGETS echo-app RUNTIME DESTINATION usr/bin)
