include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(SOURCE_FILES
  # Add source files here
  oecho.c
  )

add_executable(oecho ${SOURCE_FILES})

target_link_libraries(oecho LINK_PUBLIC ouroboros-dev)

install(TARGETS oecho RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
