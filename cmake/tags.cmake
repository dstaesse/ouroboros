find_program(CTAGS_EXECUTABLE
  NAMES ctags-universal universal-ctags ctags
  DOC "Generate a ctags index for source navigation: make tags")
mark_as_advanced(CTAGS_EXECUTABLE)

if(CTAGS_EXECUTABLE)
  add_custom_target(tags
    COMMAND ${CTAGS_EXECUTABLE}
            -R
            --languages=C
            --c-kinds=+p
            --fields=+S
            --exclude=build
            --exclude=build-claude
            --exclude=build_tmp
            --exclude=.git
            -f ${CMAKE_SOURCE_DIR}/tags
            ${CMAKE_SOURCE_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    COMMENT "Generating ctags index at ${CMAKE_SOURCE_DIR}/tags")
endif()
