configure_file("${CMAKE_CURRENT_SOURCE_DIR}/version.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/version.h" @ONLY)

set(SOCK_BUF_SIZE 10240 CACHE STRING
    "Size of the buffer used by the UNIX sockets for local IPC")

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/sockets.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/sockets.h" @ONLY)

set(HEADER_FILES
  cep.h
  cdefs.h
  dev.h
  errno.h
  fccntl.h
  fqueue.h
  ipcp.h
  irm.h
  name.h
  proto.h
  qos.h
  ${CMAKE_CURRENT_BINARY_DIR}/version.h
  )

install(FILES ${HEADER_FILES} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ouroboros)
