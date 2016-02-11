include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(SOURCE_FILES
        # Add source files here
        main.c
)

add_executable (da ${SOURCE_FILES})

target_link_libraries (da LINK_PUBLIC ouroboros)

install(TARGETS da RUNTIME DESTINATION ${CMAKE_INSTALL_FULL_BINDIR})
