configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/version.h" @ONLY)

set(HEADER_FILES
  cacep.h
  cdefs.h
  dev.h
  errno.h
  fccntl.h
  fqueue.h
  ipcp.h
  irm.h
  proto.h
  qos.h
  ${CMAKE_CURRENT_BINARY_DIR}/version.h
  )

install(FILES ${HEADER_FILES} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ouroboros)

add_subdirectory(wrap)
