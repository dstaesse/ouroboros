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
)

install(FILES ${HEADER_FILES}
  DESTINATION include/ouroboros)
