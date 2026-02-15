function(parse_git_tag WORKING_DIR OUTPUT_MAJOR OUTPUT_MINOR OUTPUT_PATCH)

  # Check if we're in a git repo
  execute_process(
    COMMAND git rev-parse --git-dir
    WORKING_DIRECTORY ${WORKING_DIR}
    OUTPUT_VARIABLE _git_dir
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
  )

  if(_git_dir)
    # Get the latest version tag reachable from the current commit
    execute_process(
      COMMAND git describe --tags --abbrev=0
        --match "[0-9]*.[0-9]*.[0-9]*"
      WORKING_DIRECTORY ${WORKING_DIR}
      OUTPUT_VARIABLE _latest_tag
      OUTPUT_STRIP_TRAILING_WHITESPACE
      ERROR_QUIET
    )

    if(_latest_tag MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
      set(_major "${CMAKE_MATCH_1}")
      set(_minor "${CMAKE_MATCH_2}")
      set(_patch "${CMAKE_MATCH_3}")
      message(STATUS "Version from git tag: ${_latest_tag}")
    else()
      string(ASCII 27 _esc)
      set(_W "${_esc}[38;5;208m")
      set(_R "${_esc}[0m")
      message(STATUS "${_W}WARNING: No version tags found. "
        "Try: git fetch --tags${_R}")
    endif()
  elseif(EXISTS "${WORKING_DIR}/VERSION")
    # Not a git repo, try VERSION file (release tarball / git archive)
    file(READ "${WORKING_DIR}/VERSION" _ver)
    string(STRIP "${_ver}" _ver)
    if(_ver MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)")
      set(_major "${CMAKE_MATCH_1}")
      set(_minor "${CMAKE_MATCH_2}")
      set(_patch "${CMAKE_MATCH_3}")
      message(STATUS "Version from VERSION file: ${_ver}")
    endif()
  endif()

  if(NOT DEFINED _major)
    set(_major "0")
    set(_minor "0")
    set(_patch "0")
  endif()

  set(${OUTPUT_MAJOR} "${_major}" PARENT_SCOPE)
  set(${OUTPUT_MINOR} "${_minor}" PARENT_SCOPE)
  set(${OUTPUT_PATCH} "${_patch}" PARENT_SCOPE)
endfunction()
