set(PACKAGE_NAME        "${CMAKE_PROJECT_NAME}")
set(PACKAGE_DESCRIPTION "The Ouroboros prototype")
set(PACKAGE_URL         "http://ouroboros.rocks")
set(PACKAGE_BUGREPORT   "http://ouroboros.rocks/bugzilla/")

message(STATUS "Package name is:            ${PACKAGE_NAME}")
message(STATUS "Package description is:     ${PACKAGE_DESCRIPTION}")
message(STATUS "Package version is:         ${PACKAGE_VERSION}")
message(STATUS "Package URL is:             ${PACKAGE_URL}")
message(STATUS "Package bug-report address: ${PACKAGE_BUGREPORT}")
message(STATUS "Package install prefix:     ${CMAKE_INSTALL_PREFIX}")

configure_file("${CMAKE_SOURCE_DIR}/ouroboros-dev.pc.in"
  "${CMAKE_BINARY_DIR}/ouroboros-dev.pc" @ONLY)

configure_file("${CMAKE_SOURCE_DIR}/ouroboros-irm.pc.in"
  "${CMAKE_BINARY_DIR}/ouroboros-irm.pc" @ONLY)

set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "${PACKAGE_DESCRIPTION}")
set(CPACK_PACKAGE_DESCRIPTION_FILE    "${CMAKE_SOURCE_DIR}/README")
set(CPACK_PACKAGE_VERSION_MAJOR       "${PACKAGE_VERSION_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR       "${PACKAGE_VERSION_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH       "${PACKAGE_VERSION_PATCH}")
set(CPACK_PACKAGE_INSTALL_DIRECTORY
  "CMake ${CMake_VERSION_MAJOR}.${CMake_VERSION_MINOR}")
set(CPACK_GENERATOR                   "TGZ")
set(CPACK_SOURCE_GENERATOR            "TGZ")

include(CPack)
