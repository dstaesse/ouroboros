# Library configuration options for Ouroboros
# Options affecting libouroboros-common, libouroboros-dev, libouroboros-irm

# Flow limits
set(SYS_MAX_FLOWS 10240 CACHE STRING
  "Maximum number of total flows for this system")
set(PROC_MAX_FLOWS 4096 CACHE STRING
  "Maximum number of flows in an application")
set(PROC_RES_FDS 64 CACHE STRING
  "Number of reserved flow descriptors per application")
set(PROC_MAX_FQUEUES 32 CACHE STRING
  "Maximum number of flow sets per application")

# Threading
if(NOT APPLE)
  set(PTHREAD_COND_CLOCK "CLOCK_MONOTONIC" CACHE STRING
    "Clock to use for condition variable timing")
else()
  set(PTHREAD_COND_CLOCK "CLOCK_REALTIME" CACHE INTERNAL
    "Clock to use for condition variable timing")
endif()

# Timeouts
set(SOCKET_TIMEOUT 500 CACHE STRING
  "Default timeout for responses from IPCPs (ms)")

# QoS settings
set(QOS_DISABLE_CRC TRUE CACHE BOOL
  "Ignores ber setting on all QoS cubes")

include(utils/CPUUtils)
detect_pclmul()
detect_pmull()
if(HAVE_PCLMUL)
  message(STATUS "CRC-64/NVMe backend: PCLMUL (x86 SSE4.1+PCLMUL)")
elseif(HAVE_PMULL)
  message(STATUS "CRC-64/NVMe backend: PMULL (aarch64 crypto)")
else()
  message(STATUS "CRC-64/NVMe backend: byte table (no acceleration)")
endif()

# Delta-t protocol timers (Watson bound: 3*MPL + A + R).
# MPL is reported per IPCP (IPCP_*_MPL); A and R are FRCT-wide.
set(DELTA_T_ACK 1000 CACHE STRING
  "Maximum time to acknowledge a packet (ms)")
set(DELTA_T_RTX 30000 CACHE STRING
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

# Thread pool manager (TPM) debugging
set(TPM_DEBUG_REPORT_INTERVAL 0 CACHE STRING
  "Interval at wich the TPM will report long running threads (s), 0 disables")
set(TPM_DEBUG_ABORT_TIMEOUT 0 CACHE STRING
  "TPM abort process after a thread reaches this timeout (s), 0 disables")

# Encryption
set(KEY_LEAF_BITS 20 CACHE STRING
  "Packets per leaf key as a power of two (2^20 = AEAD-safe default)")
set(KEY_NODE_BITS 6 CACHE STRING
  "Leaf keys per node key, power of two (2^6 = 64; leak compartment)")
set(KEY_NODE_COUNT 128 CACHE STRING
  "Node keys per batch (N); <= 4096, the 12-bit on-wire node index")
set(KEY_REKEY_WATERMARK 4 CACHE STRING
  "Re-key when this many node keys remain; 0 disables the count trigger")
set(KEY_REPLAY_WINDOW 2048 CACHE STRING
  "RX replay window in packets; power of two, >= 128")
set(KEY_REKEY_WM_CHECK_BITS 16 CACHE STRING
  "Re-key watermark is consulted once per 2^n flow writes")
if(NOT KEY_REPLAY_WINDOW MATCHES "^[0-9]+$")
  message(FATAL_ERROR "KEY_REPLAY_WINDOW must be a positive integer")
endif()
math(EXPR _krw_p2 "${KEY_REPLAY_WINDOW} & (${KEY_REPLAY_WINDOW} - 1)")
if(KEY_REPLAY_WINDOW LESS 128 OR NOT _krw_p2 EQUAL 0)
  message(FATAL_ERROR "KEY_REPLAY_WINDOW must be a power of two >= 128")
endif()

# Re-key must finish within its lead window - KEY_REKEY_WATERMARK node keys
# worth of packets - before the batch exhausts and TX fails closed. dev.c only
# evaluates the watermark once per FLOW_WM_CHECK writes, so a lead below ~2x
# that leaves a high-rate flow no room to complete the exchange. Production
# defaults are vast; this guards under-sized (test) geometries.
if(KEY_REKEY_WATERMARK GREATER 0)
  math(EXPR _rk_wm_check "1 << ${KEY_REKEY_WM_CHECK_BITS}")
  math(EXPR _rk_lead
    "${KEY_REKEY_WATERMARK} << (${KEY_LEAF_BITS} + ${KEY_NODE_BITS})")
  math(EXPR _rk_min "2 * ${_rk_wm_check}")
  if(_rk_lead LESS _rk_min)
    message(WARNING
      "Re-key lead is ${_rk_lead} packets vs the watermark check interval "
      "${_rk_wm_check}; a high-rate flow may exhaust its key batch before the "
      "re-key completes (TX fails closed until it does). Raise KEY_LEAF_BITS, "
      "KEY_NODE_BITS, or KEY_REKEY_WATERMARK.")
  endif()
endif()

# Flow statistics (requires FUSE)
if(HAVE_FUSE)
  set(PROC_FLOW_STATS TRUE CACHE BOOL
    "Enable flow statistics tracking for application flows")
  if(PROC_FLOW_STATS)
    message(STATUS "Application flow statistics enabled")
  else()
    message(STATUS "Application flow statistics disabled")
  endif()
endif()

