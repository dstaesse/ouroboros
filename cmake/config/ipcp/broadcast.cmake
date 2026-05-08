# Broadcast IPCP configuration options for Ouroboros

set(IPCP_BROADCAST_TARGET ipcpd-broadcast)

set(IPCP_BROADCAST_MPL 100 CACHE STRING
  "Default maximum packet lifetime for the Broadcast IPCP, in ms")

set(IPCP_BROADCAST_MTU 1400 CACHE STRING
  "Layer MTU advertised by the Broadcast IPCP, in bytes")
