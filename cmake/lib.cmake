include(lib/lib)
include(lib/common)
include(lib/dev)
include(lib/irm)

configure_file("${LIB_SOURCE_DIR}/config.h.in"
  "${LIB_BINARY_DIR}/config.h" @ONLY)
