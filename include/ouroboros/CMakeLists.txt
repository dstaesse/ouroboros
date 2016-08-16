configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h")

set(HEADER_FILES
  cdap.h
  dev.h
  errno.h
  flow.h
  irm.h
  irm_config.h
  nsm.h
  qos.h)

install(FILES ${HEADER_FILES} DESTINATION usr/include/ouroboros)

add_subdirectory(wrap)
