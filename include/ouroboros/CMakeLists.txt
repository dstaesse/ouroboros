file(GLOB_RECURSE HEADER_FILES *.h)

install(FILES ${HEADER_FILES}
  DESTINATION ${CMAKE_INSTALL_FULL_INCLUDEDIR}/ouroboros)

add_custom_target(qtcreator-workaround SOURCES ${HEADER_FILES})
