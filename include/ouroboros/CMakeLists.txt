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
  qos.h)

install(FILES ${HEADER_FILES} DESTINATION usr/include/ouroboros)

add_subdirectory(wrap)
