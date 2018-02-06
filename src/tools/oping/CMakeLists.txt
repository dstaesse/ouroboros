include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

find_library(LIBM_LIBRARIES m)
if(NOT LIBM_LIBRARIES)
  message(FATAL_ERROR "libm not found")
endif()

mark_as_advanced(LIBM_LIBRARIES)

set(SOURCE_FILES
  # Add source files here
  oping.c
  )

add_executable(oping ${SOURCE_FILES})

target_link_libraries(oping LINK_PUBLIC ${LIBM_LIBRARIES} ouroboros-dev)

install(TARGETS oping RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
