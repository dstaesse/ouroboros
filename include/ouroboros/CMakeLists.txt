configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h")

set(HEADER_FILES
        cdap.h
        dev.h
        dif_config.h
        errno.h
        flow.h
        instance_name.h
        irm.h
        nsm.h
        qos.h
)

install(FILES ${HEADER_FILES} DESTINATION /usr/include/ouroboros)
