# Flow Point of attachment (poa) configuration for Ouroboros

set(POA_MGMT_FRAME_SIZE 16384 CACHE STRING
  "Maximum size of a flow endpoint management frame, in bytes")

# Management frames are retried or repeated, so a send never waits long.
set(POA_MGMT_SND_TIMEO 100 CACHE STRING
  "Deadline for sending a management frame, in ms")

# Flows on one PoA share its transmit queue, so congestion avoidance keys its link estimator on the
# PoA and needs a bound on their number.
set(POA_MAX_POAS 16 CACHE STRING
  "Maximum number of points of attachment per IPCP")

# UDP endpoints
set(POA_UDP_MPL 5000 CACHE STRING
  "Default maximum packet lifetime for UDP flow endpoints, in ms")
set(POA_UDP4_MTU 1472 CACHE STRING
  "Fallback UDP4 endpoint MTU when getsockopt(IP_MTU) is unavailable")
set(POA_UDP6_MTU 1452 CACHE STRING
  "Fallback UDP6 endpoint MTU when getsockopt(IPV6_MTU) is unavailable")
set(POA_UDP_RD_BUF 65535 CACHE STRING
  "UDP endpoint receive buffer in bytes. Bounds the advertised MTU")

# Ethernet endpoints
set(POA_ETH_MPL 100 CACHE STRING
  "Default maximum packet lifetime for Ethernet flow endpoints, in ms")
set(POA_ETH_QDISC_BYPASS false CACHE BOOL
  "Bypass the Qdisc in the kernel when using raw sockets")
set(POA_ETH_SNDBUF 0 CACHE STRING
  "Raw socket SO_SNDBUF in bytes (floored to one frame). 0 = kernel default")
set(POA_ETH_RCVBUF 0 CACHE STRING
  "Raw socket SO_RCVBUF in bytes. 0 = kernel default")
set(POA_ETH_LO_MTU 9000 CACHE STRING
  "Restrict Ethernet flow endpoint MTU over loopback interfaces")
set(POA_ETH_RD_BUF 16384 CACHE STRING
  "Cap on the Ethernet endpoint receive buffer and MTU, in bytes")
