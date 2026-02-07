# Local IPCP configuration options for Ouroboros

set(IPCP_LOCAL_TARGET ipcpd-local)

set(IPCP_LOCAL_MPL 100 CACHE STRING
  "Default maximum packet lifetime for the Local IPCP, in ms")

set(IPCP_LOCAL_POLLING FALSE CACHE BOOL
  "Enable active polling in the Local IPCP for low-latency mode")
