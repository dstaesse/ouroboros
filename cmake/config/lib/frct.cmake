# FRCT configuration for Ouroboros Options for the flow and retransmission control protocol in
# src/lib/frct.c

# Delta-t protocol timers (Watson bound: 3*MPL + A + R).
# MPL is reported per IPCP (IPCP_*_MPL); A and R are FRCT-wide.
set(DELTA_T_ACK 1000 CACHE STRING
  "Maximum time to acknowledge a packet (ms)")
set(DELTA_T_RTX 32000 CACHE STRING
  "Maximum time to retransmit a packet (ms)")

# FRCT configuration
set(FRCT_REORDER_QUEUE_SIZE 128 CACHE STRING
  "Size of the reordering queue, must be a power of 2")
set(FRCT_START_WINDOW 128 CACHE STRING
  "Start window, must be a power of 2")
set(FRCT_LINUX_RTT_ESTIMATOR TRUE CACHE BOOL
  "Use Linux RTT estimator formula instead of the TCP RFC formula")
set(FRCT_RTO_MDEV_MULTIPLIER 2 CACHE STRING
  "Multiplier for deviation term in the RTO: RTO = sRTT + (mdev << X)")
set(FRCT_RTO_INC_FACTOR 0 CACHE STRING
  "Divisor for RTO increase after timeout: RTO += RTX >> X, 0: Karn/Partridge")
set(FRCT_RTO_MIN 250 CACHE STRING
  "Hard floor for Retransmission Timeout (RTO) for FRCT (us)")
set(FRCT_TICK_TIME 5000 CACHE STRING
  "Tick time for FRCT activity (retransmission, acknowledgments) (us)")
set(FRCT_DEBUG_STDOUT FALSE CACHE BOOL
  "Print FRCT final counters to stdout at flow teardown")

# Retransmission (RXM) configuration
set(RXM_MIN_RESOLUTION 20 CACHE STRING
  "Minimum retransmission delay (ns), as a power to 2")
set(RXM_WHEEL_MULTIPLIER 4 CACHE STRING
  "Factor for retransmission wheel levels as a power to 2")
set(RXM_WHEEL_LEVELS 3 CACHE STRING
  "Number of levels in the retransmission wheel")
set(RXM_WHEEL_SLOTS_PER_LEVEL 256 CACHE STRING
  "Number of slots per level in the retransmission wheel, must be a power of 2")

# Acknowledgment wheel configuration
set(ACK_WHEEL_SLOTS 256 CACHE STRING
  "Number of slots in the acknowledgment wheel, must be a power of 2")
set(ACK_WHEEL_RESOLUTION 18 CACHE STRING
  "Minimum acknowledgment delay (ns), as a power to 2")
