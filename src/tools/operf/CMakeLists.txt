include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

find_library(LIBM_LIBRARIES m)
if(NOT LIBM_LIBRARIES)
  message(FATAL_ERROR "libm not found")
endif()

set(SOURCE_FILES
        # Add source files here
        operf.c
)

add_executable(operf ${SOURCE_FILES})

target_link_libraries(operf LINK_PUBLIC ${LIBM_LIBRARIES} ouroboros)

install(TARGETS operf RUNTIME DESTINATION usr/bin)
