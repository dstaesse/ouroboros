configure_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/config.h.in"
  "${CMAKE_CURRENT_BINARY_DIR}/config.h")

set(HEADER_FILES
        cdap.h
        da.h
        dev.h
        dif_config.h
        flow.h
        irm.h
        qos.h
)

install(FILES ${HEADER_FILES} "${CMAKE_CURRENT_BINARY_DIR}/config.h"
        DESTINATION include/ouroboros)
