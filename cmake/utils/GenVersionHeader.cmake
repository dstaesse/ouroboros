include(${CMAKE_CURRENT_LIST_DIR}/GetGitHash.cmake)
get_git_hash(${GIT_DIR} ${PACKAGE_VERSION_MAJOR} ${PACKAGE_VERSION_MINOR}
  ${PACKAGE_VERSION_PATCH} PACKAGE_VERSION_STRING)

configure_file(${INPUT_FILE} ${OUTPUT_FILE}.tmp @ONLY)

execute_process(
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
  ${OUTPUT_FILE}.tmp ${OUTPUT_FILE}
)

file(REMOVE ${OUTPUT_FILE}.tmp)
