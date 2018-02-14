include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

get_filename_component(CURRENT_SOURCE_PARENT_DIR
  ${CMAKE_CURRENT_SOURCE_DIR} DIRECTORY)

include_directories(${CURRENT_SOURCE_PARENT_DIR})

find_library(LIBM_LIBRARIES m)
if(NOT LIBM_LIBRARIES)
  message(FATAL_ERROR "libm not found")
endif()

set(SOURCE_FILES
  # Add source files here
  operf.c
  )

add_executable(operf ${SOURCE_FILES})

target_link_libraries(operf LINK_PUBLIC ${LIBM_LIBRARIES} ouroboros-dev)

install(TARGETS operf RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
