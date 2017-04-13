configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h")

set(HEADER_FILES
  cacep.h
  cdap.h
  cdefs.h
  dev.h
  errno.h
  fcntl.h
  fqueue.h
  irm.h
  nsm.h
  qos.h)

install(FILES ${HEADER_FILES} DESTINATION usr/include/ouroboros)

add_subdirectory(wrap)
