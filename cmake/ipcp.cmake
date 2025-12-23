include(ipcp/ipcp)
include(ipcp/eth)
include(ipcp/udp)
include(ipcp/local)
include(ipcp/broadcast)
include(ipcp/unicast)

configure_file("${IPCP_SOURCE_DIR}/config.h.in"
  "${IPCP_BINARY_DIR}/config.h" @ONLY)

