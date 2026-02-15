include(utils/ParseGitTag)

# Parse version from git tag or use custom version if unavailable
parse_git_tag(${CMAKE_SOURCE_DIR} PACKAGE_VERSION_MAJOR PACKAGE_VERSION_MINOR
  PACKAGE_VERSION_PATCH)

set(PACKAGE_VERSION
  "${PACKAGE_VERSION_MAJOR}.${PACKAGE_VERSION_MINOR}.${PACKAGE_VERSION_PATCH}")

include(utils/GetGitHash)
get_git_hash(${CMAKE_SOURCE_DIR} ${PACKAGE_VERSION_MAJOR} ${PACKAGE_VERSION_MINOR}
 ${PACKAGE_VERSION_PATCH} PACKAGE_VERSION_STRING)

configure_file("${CMAKE_SOURCE_DIR}/include/ouroboros/version.h.in"
  "${CMAKE_BINARY_DIR}/include/ouroboros/version.h" @ONLY)

add_custom_target(version_header ALL
  COMMAND ${CMAKE_COMMAND}
    -DGIT_DIR=${CMAKE_SOURCE_DIR}
    -DINPUT_FILE=${CMAKE_SOURCE_DIR}/include/ouroboros/version.h.in
    -DOUTPUT_FILE=${CMAKE_BINARY_DIR}/include/ouroboros/version.h
    -DPACKAGE_VERSION_MAJOR=${PACKAGE_VERSION_MAJOR}
    -DPACKAGE_VERSION_MINOR=${PACKAGE_VERSION_MINOR}
    -DPACKAGE_VERSION_PATCH=${PACKAGE_VERSION_PATCH}
    -P ${CMAKE_SOURCE_DIR}/cmake/utils/GenVersionHeader.cmake
  COMMENT "Updating git hash in version.h"
)

add_custom_target(version
  COMMAND ${CMAKE_COMMAND}
    -DVERSION_HEADER=${CMAKE_BINARY_DIR}/include/ouroboros/version.h
    -P ${CMAKE_SOURCE_DIR}/cmake/utils/PrintVersion.cmake
  DEPENDS version_header
)
