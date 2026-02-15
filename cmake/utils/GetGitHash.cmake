function(get_git_hash WORKING_DIR VERSION_MAJ VERSION_MIN VERSION_PAT OUTPUT_VAR)
  execute_process(
    COMMAND git describe --tags --always --dirty
      --match "[0-9]*.[0-9]*.[0-9]*"
    WORKING_DIRECTORY ${WORKING_DIR}
    OUTPUT_VARIABLE _hash
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )

  if(_hash MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+")
    # git describe returned a tag-based version string
  elseif(_hash)
    # No version tag found, construct full version string
    execute_process(
      COMMAND git rev-list --count HEAD
      WORKING_DIRECTORY ${WORKING_DIR}
      OUTPUT_VARIABLE _count
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    execute_process(
      COMMAND git describe --always --dirty
      WORKING_DIRECTORY ${WORKING_DIR}
      OUTPUT_VARIABLE _desc
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )
    set(_hash
      "${VERSION_MAJ}.${VERSION_MIN}.${VERSION_PAT}-${_count}-g${_desc}")
  elseif(EXISTS "${WORKING_DIR}/VERSION")
    # No git, use VERSION file (git archive / cgit snapshot)
    file(READ "${WORKING_DIR}/VERSION" _hash)
    string(STRIP "${_hash}" _hash)
  else()
    set(_hash "${VERSION_MAJ}.${VERSION_MIN}.${VERSION_PAT}")
  endif()

  set(${OUTPUT_VAR} "${_hash}" PARENT_SCOPE)
endfunction()
