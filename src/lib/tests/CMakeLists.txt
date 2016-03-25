get_filename_component(tmp ".." ABSOLUTE)
get_filename_component(src_folder "${tmp}" NAME)

create_test_sourcelist(${src_folder}_tests test_suite.c
                       # Add new tests here
                       bitmap_test.c
                       du_buff_test.c
                       shm_du_map_test.c
)

add_executable(${src_folder}_test EXCLUDE_FROM_ALL ${${src_folder}_tests})
target_link_libraries(${src_folder}_test ouroboros)

add_dependencies(check ${src_folder}_test)

set(tests_to_run ${${src_folder}_tests})
remove(tests_to_run test_suite.c)

foreach(test ${tests_to_run})
  get_filename_component(test_name ${test} NAME_WE)
  add_test(${test_name} ${C_TEST_PATH}/${src_folder}_test ${test_name})
endforeach(test)
