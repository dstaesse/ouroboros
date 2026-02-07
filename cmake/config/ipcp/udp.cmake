# UDP IPCP configuration options for Ouroboros
# Options for udp4 and udp6 IPCPs

set(IPCP_UDP4_TARGET ipcpd-udp4)
set(IPCP_UDP6_TARGET ipcpd-udp6)

set(IPCP_UDP_RD_THR 3 CACHE STRING
  "Number of reader threads in UDP IPCPs")
set(IPCP_UDP_WR_THR 3 CACHE STRING
  "Number of writer threads in UDP IPCPs")
set(IPCP_UDP_MPL 5000 CACHE STRING
  "Default maximum packet lifetime for the UDP IPCPs, in ms")
