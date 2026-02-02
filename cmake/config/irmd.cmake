# IRMd configuration options for Ouroboros
# Options affecting the IPC Resource Manager daemon

# Timeouts (all in milliseconds unless noted)
set(IRMD_REQ_ARR_TIMEOUT 1000 CACHE STRING
  "Timeout for an application to respond to a new flow (ms)")
set(BOOTSTRAP_TIMEOUT 5000 CACHE STRING
  "Timeout for an IPCP to bootstrap (ms)")
set(ENROLL_TIMEOUT 20000 CACHE STRING
  "Timeout for an IPCP to enroll (ms)")
set(REG_TIMEOUT 20000 CACHE STRING
  "Timeout for registering a name (ms)")
set(QUERY_TIMEOUT 200 CACHE STRING
  "Timeout to query a name with an IPCP (ms)")
set(CONNECT_TIMEOUT 20000 CACHE STRING
  "Timeout to connect an IPCP to another IPCP (ms)")
set(FLOW_ALLOC_TIMEOUT 20000 CACHE STRING
  "Timeout for a flow allocation response (ms)")

# OAP (Ouroboros Authentication Protocol)
set(OAP_REPLAY_TIMER 20 CACHE STRING
  "OAP replay protection window (s)")
set(DEBUG_PROTO_OAP FALSE CACHE BOOL
  "Add Flow allocation protocol message output to IRMd debug logging")

# Threading
set(IRMD_MIN_THREADS 8 CACHE STRING
  "Minimum number of worker threads in the IRMd")
set(IRMD_ADD_THREADS 8 CACHE STRING
  "Number of extra threads to start when the IRMD faces thread starvation")

# Process management
set(IRMD_PKILL_TIMEOUT 30 CACHE STRING
  "Number of seconds to wait before sending SIGKILL to subprocesses on exit")
set(IRMD_KILL_ALL_PROCESSES TRUE CACHE BOOL
  "Kill all processes on exit")
