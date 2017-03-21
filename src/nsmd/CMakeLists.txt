include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)

set(SOURCE_FILES
  # Add source files here
  main.c
  )

add_executable(nsmd ${SOURCE_FILES})

target_link_libraries(nsmd LINK_PUBLIC ouroboros)

include(AddCompileFlags)
if (CMAKE_BUILD_TYPE MATCHES Debug)
  add_compile_flags(nsmd -DCONFIG_OUROBOROS_DEBUG)
endif (CMAKE_BUILD_TYPE MATCHES Debug)

install(TARGETS nsmd RUNTIME DESTINATION sbin)

# Enable once nsmd has tests
# add_subdirectory(tests)
