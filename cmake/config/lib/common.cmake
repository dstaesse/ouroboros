# Library configuration options for Ouroboros Options affecting libouroboros-common,
# libouroboros-dev and libouroboros-irm as a whole; per-subsystem options sit beside this file

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

# Thread pool manager (TPM) debugging
set(TPM_DEBUG_REPORT_INTERVAL 0 CACHE STRING
  "Interval at wich the TPM will report long running threads (s), 0 disables")
set(TPM_DEBUG_ABORT_TIMEOUT 0 CACHE STRING
  "TPM abort process after a thread reaches this timeout (s), 0 disables")

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

