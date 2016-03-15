configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h")

set(HEADER_FILES
        bitmap.h
        cdap.h
        common.h
        da.h
        dev.h
        du_buff.h
        ipcp.h
        irm.h
        list.h
        logs.h
        rina_name.h
        sockets.h
        utils.h
)

install(FILES ${HEADER_FILES} "${CMAKE_CURRENT_BINARY_DIR}/config.h"
  DESTINATION include/ouroboros)
