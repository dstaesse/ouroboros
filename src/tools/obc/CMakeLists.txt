include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(SOURCE_FILES
  # Add source files here
  obc.c
  )

add_executable(obc ${SOURCE_FILES})

target_link_libraries(obc LINK_PUBLIC ouroboros-dev)

install(TARGETS obc RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
