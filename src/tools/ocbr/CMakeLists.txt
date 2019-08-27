include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

get_filename_component(CURRENT_SOURCE_PARENT_DIR
  ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)

include_directories(${CURRENT_SOURCE_PARENT_DIR})

set(SOURCE_FILES
  # Add source files here
  ocbr.c
  )

add_executable(ocbr ${SOURCE_FILES})

target_link_libraries(ocbr LINK_PUBLIC ouroboros-dev)

install(TARGETS ocbr RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
