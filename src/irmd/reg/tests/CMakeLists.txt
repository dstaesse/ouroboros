get_filename_component(tmp ".." ABSOLUTE)
get_filename_component(src_folder "${tmp}" NAME)

compute_test_prefix()

# Set include directories for tests
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/src/irmd)
include_directories(${CMAKE_BINARY_DIR}/src/irmd)

create_test_sourcelist(${src_folder}_tests test_suite.c
  # Add new tests here
  flow_test.c
  ipcp_test.c
  name_test.c
  proc_test.c
  prog_test.c
  reg_test.c
)

add_executable(${src_folder}_test ${${src_folder}_tests})

disable_test_logging_for_target(${src_folder}_test)
target_link_libraries(${src_folder}_test ouroboros-common)

if (CMAKE_BUILD_TYPE MATCHES "Debug*")
  add_compile_flags(${src_folder}_test -DCONFIG_OUROBOROS_DEBUG)
endif ()

add_dependencies(build_tests ${src_folder}_test)

set(tests_to_run ${${src_folder}_tests})
if(CMAKE_VERSION VERSION_LESS "3.29.0")
  remove(tests_to_run test_suite.c)
else ()
  list(POP_FRONT tests_to_run)
endif()

foreach(test ${tests_to_run})
  get_filename_component(test_name ${test} NAME_WE)
  add_test(${TEST_PREFIX}/${test_name} ${CMAKE_CURRENT_BINARY_DIR}/${src_folder}_test ${test_name})
endforeach(test)
