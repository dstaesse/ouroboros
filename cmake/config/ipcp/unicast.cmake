# Unicast IPCP configuration options for Ouroboros

set(IPCP_UNICAST_TARGET ipcpd-unicast)

set(IPCP_UNICAST_MPL 100 CACHE STRING
  "Default maximum packet lifetime for the Unicast IPCP, in ms")
set(IPCP_UNICAST_MTU 1400 CACHE STRING
  "Layer MTU advertised by the Unicast IPCP, in bytes (TODO: derive per-flow from n-1 path MTU minus DT PCI)")
set(PFT_SIZE 256 CACHE STRING
  "Prefix forwarding table size for the Unicast IPCP")

# Aggregate congestion-avoidance context interning. One ctx is shared
# per (peer, qos cube); this is the hash table bucket count. Must be a
# power of two (the bucket index masks with CA_BUCKETS - 1).
set(IPCP_CA_BUCKETS 64 CACHE STRING
  "Hash buckets for aggregate CA context interning (power of two)")
math(EXPR IPCP_CA_BUCKETS_POW2 "${IPCP_CA_BUCKETS} & (${IPCP_CA_BUCKETS} - 1)")
if((IPCP_CA_BUCKETS LESS 1) OR (NOT IPCP_CA_BUCKETS_POW2 EQUAL 0))
  message(FATAL_ERROR "IPCP_CA_BUCKETS must be a positive power of two")
endif()

# Per-flow (non-aggregated) congestion avoidance. Aggregate CA per
# (peer, qos cube) is the production behaviour; enable this only to
# build the legacy per-flow reference for A/B testing and bisection.
set(IPCP_CA_PER_FLOW FALSE CACHE BOOL
  "Use per-flow congestion avoidance (testing only)")
if(IPCP_CA_PER_FLOW)
  message(STATUS "IPCP per-flow congestion avoidance (testing build)")
endif()

# Protocol debugging
set(DEBUG_PROTO_DHT FALSE CACHE BOOL
  "Add DHT protocol debug logging")
set(DEBUG_PROTO_LS FALSE CACHE BOOL
  "Add link state protocol debug logging")
