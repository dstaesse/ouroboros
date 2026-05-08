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
set(IPCP_UDP4_MTU 1472 CACHE STRING
  "Fallback UDP4 layer MTU when getsockopt(IP_MTU) is unavailable, in bytes")
set(IPCP_UDP6_MTU 1452 CACHE STRING
  "Fallback UDP6 layer MTU when getsockopt(IPV6_MTU) is unavailable, in bytes")
