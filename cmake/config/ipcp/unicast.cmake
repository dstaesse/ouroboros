# Unicast IPCP configuration options for Ouroboros

set(IPCP_UNICAST_TARGET ipcpd-unicast)

set(IPCP_UNICAST_MPL 100 CACHE STRING
  "Default maximum packet lifetime for the Unicast IPCP, in ms")
set(PFT_SIZE 256 CACHE STRING
  "Prefix forwarding table size for the Unicast IPCP")

# Protocol debugging
set(DEBUG_PROTO_DHT FALSE CACHE BOOL
  "Add DHT protocol debug logging")
set(DEBUG_PROTO_LS FALSE CACHE BOOL
  "Add link state protocol debug logging")
