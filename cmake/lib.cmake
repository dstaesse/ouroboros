include(lib/lib)
include(lib/common)
include(lib/dev)
include(lib/irm)
include(lib/ssm)

configure_file("${LIB_SOURCE_DIR}/config.h.in"
  "${LIB_BINARY_DIR}/config.h" @ONLY)

configure_file("${LIB_SOURCE_DIR}/ssm/ssm.h.in"
  "${LIB_BINARY_DIR}/ssm.h" @ONLY)
