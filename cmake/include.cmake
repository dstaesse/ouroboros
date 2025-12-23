set(HEADERS_SOURCE_DIR "${CMAKE_SOURCE_DIR}/include/ouroboros")

set(SOCK_BUF_SIZE 10240 CACHE STRING
    "Size of the buffer used by the UNIX sockets for local IPC")

configure_file("${CMAKE_SOURCE_DIR}/include/ouroboros/version.h.in"
  "${CMAKE_BINARY_DIR}/include/ouroboros/version.h" @ONLY)

configure_file("${CMAKE_SOURCE_DIR}/include/ouroboros/sockets.h.in"
  "${CMAKE_BINARY_DIR}/include/ouroboros/sockets.h" @ONLY)

set(PUBLIC_HEADER_FILES
  ${HEADERS_SOURCE_DIR}/cep.h
  ${HEADERS_SOURCE_DIR}/cdefs.h
  ${HEADERS_SOURCE_DIR}/dev.h
  ${HEADERS_SOURCE_DIR}/errno.h
  ${HEADERS_SOURCE_DIR}/fccntl.h
  ${HEADERS_SOURCE_DIR}/fqueue.h
  ${HEADERS_SOURCE_DIR}/ipcp.h
  ${HEADERS_SOURCE_DIR}/irm.h
  ${HEADERS_SOURCE_DIR}/name.h
  ${HEADERS_SOURCE_DIR}/proto.h
  ${HEADERS_SOURCE_DIR}/qos.h
  ${CMAKE_BINARY_DIR}/include/ouroboros/version.h
  )

install(FILES ${PUBLIC_HEADER_FILES}
  DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/ouroboros)
