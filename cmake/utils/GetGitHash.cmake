function(get_git_hash WORKING_DIR VERSION_MAJ VERSION_MIN VERSION_PAT OUTPUT_VAR)
  execute_process(
    COMMAND git describe --always --dirty
    WORKING_DIRECTORY ${WORKING_DIR}
    OUTPUT_VARIABLE _hash
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )

  if(NOT _hash)
    message(WARNING "Could not determine git hash")
    set(_hash "${VERSION_MAJ}.${VERSION_MIN}.${VERSION_PAT}-custom")
  endif()

  set(${OUTPUT_VAR} "${_hash}" PARENT_SCOPE)
endfunction()
