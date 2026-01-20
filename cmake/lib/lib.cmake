set(LIB_SOURCE_DIR "${CMAKE_SOURCE_DIR}/src/lib")
set(LIB_BINARY_DIR "${CMAKE_BINARY_DIR}/src/lib")

# Library configuration variables
set(SYS_MAX_FLOWS 10240 CACHE STRING
  "Maximum number of total flows for this system")
set(PROG_MAX_FLOWS 4096 CACHE STRING
  "Maximum number of flows in an application")
set(PROG_RES_FDS 64 CACHE STRING
  "Number of reserved flow descriptors per application")
set(PROG_MAX_FQUEUES 32 CACHE STRING
  "Maximum number of flow sets per application")

if (NOT APPLE)
  set(PTHREAD_COND_CLOCK "CLOCK_MONOTONIC" CACHE STRING
    "Clock to use for condition variable timing")
else ()
  set(PTHREAD_COND_CLOCK "CLOCK_REALTIME" CACHE INTERNAL
    "Clock to use for condition variable timing")
endif ()

set(SOCKET_TIMEOUT 500 CACHE STRING
  "Default timeout for responses from IPCPs (ms)")
set(SHM_PREFIX "ouroboros" CACHE STRING
  "String to prepend to POSIX shared memory filenames")
set(SHM_LOCKFILE_NAME "/${SHM_PREFIX}.lockfile" CACHE INTERNAL
  "Filename for the POSIX shared memory lockfile")

set(QOS_DISABLE_CRC TRUE CACHE BOOL
  "Ignores ber setting on all QoS cubes")
set(DELTA_T_MPL 60 CACHE STRING
  "Maximum packet lifetime (s)")
set(DELTA_T_ACK 10 CACHE STRING
  "Maximum time to acknowledge a packet (s)")
set(DELTA_T_RTX 120 CACHE STRING
  "Maximum time to retransmit a packet (s)")
set(FRCT_REORDER_QUEUE_SIZE 256 CACHE STRING
  "Size of the reordering queue, must be a power of 2")
set(FRCT_START_WINDOW 64 CACHE STRING
  "Start window, must be a power of 2")
set(FRCT_LINUX_RTT_ESTIMATOR TRUE CACHE BOOL
  "Use Linux RTT estimator formula instead of the TCP RFC formula")
set(FRCT_RTO_MDEV_MULTIPLIER 2 CACHE STRING
  "Multiplier for deviation term in the RTO: RTO = sRTT + (mdev << X)")
set(FRCT_RTO_INC_FACTOR 0 CACHE STRING
  "Divisor for RTO increase after timeout: RTO += RTX >> X, 0: Karn/Partridge")
set(FRCT_RTO_MIN 250 CACHE STRING
  "Minimum Retransmission Timeout (RTO) for FRCT (us)")
set(FRCT_TICK_TIME 5000 CACHE STRING
  "Tick time for FRCT activity (retransmission, acknowledgments) (us)")
set(RXM_BUFFER_ON_HEAP FALSE CACHE BOOL
  "Store packets for retransmission on the heap instead of in packet buffer")
set(RXM_BLOCKING TRUE CACHE BOOL
  "Use blocking writes for retransmission")
set(RXM_MIN_RESOLUTION 20 CACHE STRING
  "Minimum retransmission delay (ns), as a power to 2")
set(RXM_WHEEL_MULTIPLIER 4 CACHE STRING
  "Factor for retransmission wheel levels as a power to 2")
set(RXM_WHEEL_LEVELS 3 CACHE STRING
  "Number of levels in the retransmission wheel")
set(RXM_WHEEL_SLOTS_PER_LEVEL 256 CACHE STRING
  "Number of slots per level in the retransmission wheel, must be a power of 2")
set(ACK_WHEEL_SLOTS 256 CACHE STRING
  "Number of slots in the acknowledgment wheel, must be a power of 2")
set(ACK_WHEEL_RESOLUTION 18 CACHE STRING
  "Minimum acknowledgment delay (ns), as a power to 2")
set(TPM_DEBUG_REPORT_INTERVAL 0 CACHE STRING
  "Interval at wich the TPM will report long running threads (s), 0 disables")
set(TPM_DEBUG_ABORT_TIMEOUT 0 CACHE STRING
  "TPM abort process after a thread reaches this timeout (s), 0 disables")
set(KEY_ROTATION_BIT 20 CACHE STRING
  "Bit position in packet counter that triggers key rotation (default 20 = every 2^20 packets)")

if (HAVE_FUSE)
  set(PROC_FLOW_STATS TRUE CACHE BOOL
    "Enable flow statistics tracking for application flows")
    if (PROC_FLOW_STATS)
       message(STATUS "Application flow statistics enabled")
    else ()
       message(STATUS "Application flow statistics disabled")
    endif ()
endif ()
