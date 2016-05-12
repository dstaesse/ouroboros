configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h")

set(HEADER_FILES
        bitmap.h
        cdap.h
        common.h
        da.h
        dev.h
        dif_config.h
        du_buff.h
        flow.h
        instance_name.h
        ipcp.h
        irm.h
        list.h
        logs.h
        shm_ap_rbuff.h
        shm_du_map.h
        sockets.h
        utils.h
)

install(FILES ${HEADER_FILES} "${CMAKE_CURRENT_BINARY_DIR}/config.h"
        DESTINATION include/ouroboros)
