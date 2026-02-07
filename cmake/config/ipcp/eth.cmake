# Ethernet IPCP configuration options for Ouroboros
# Options for eth-llc and eth-dix IPCPs

set(IPCP_ETH_LLC_TARGET ipcpd-eth-llc)
set(IPCP_ETH_DIX_TARGET ipcpd-eth-dix)

set(IPCP_ETH_RD_THR 1 CACHE STRING
  "Number of reader threads in Ethernet IPCP")
set(IPCP_ETH_WR_THR 1 CACHE STRING
  "Number of writer threads in Ethernet IPCP")
set(IPCP_ETH_QDISC_BYPASS false CACHE BOOL
  "Bypass the Qdisc in the kernel when using raw sockets")
set(IPCP_ETH_LO_MTU 9000 CACHE STRING
  "Restrict Ethernet MTU over loopback interfaces")
set(IPCP_ETH_MGMT_FRAME_SIZE 9000 CACHE STRING
  "Management frame buffer size for Ethernet IPCPs")
set(IPCP_ETH_MPL 100 CACHE STRING
  "Default maximum packet lifetime for the Ethernet IPCPs, in ms")
