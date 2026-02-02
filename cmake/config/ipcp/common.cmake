# Common IPCP configuration options for Ouroboros
# Options affecting all IPC Process types

# Connection manager
set(CONNMGR_RCV_TIMEOUT 1000 CACHE STRING
  "Timeout for the connection manager to wait for OCEP info (ms).")

# Debugging
set(IPCP_DEBUG_LOCAL FALSE CACHE BOOL
  "Use PID as address for local debugging")

# QoS cube priorities (0-99, higher = more priority)
set(IPCP_QOS_CUBE_BE_PRIO 50 CACHE STRING
  "Priority for best effort QoS cube (0-99)")
set(IPCP_QOS_CUBE_VIDEO_PRIO 90 CACHE STRING
  "Priority for video QoS cube (0-99)")
set(IPCP_QOS_CUBE_VOICE_PRIO 99 CACHE STRING
  "Priority for voice QoS cube (0-99)")

# Validate QoS cube priorities
if((IPCP_QOS_CUBE_BE_PRIO LESS 0) OR (IPCP_QOS_CUBE_BE_PRIO GREATER 99))
  message(FATAL_ERROR "Invalid priority for best effort QoS cube (must be 0-99)")
endif()
if((IPCP_QOS_CUBE_VIDEO_PRIO LESS 0) OR (IPCP_QOS_CUBE_VIDEO_PRIO GREATER 99))
  message(FATAL_ERROR "Invalid priority for video QoS cube (must be 0-99)")
endif()
if((IPCP_QOS_CUBE_VOICE_PRIO LESS 0) OR (IPCP_QOS_CUBE_VOICE_PRIO GREATER 99))
  message(FATAL_ERROR "Invalid priority for voice QoS cube (must be 0-99)")
endif()

# Threading
set(IPCP_MIN_THREADS 4 CACHE STRING
  "Minimum number of worker threads in the IPCP")
set(IPCP_ADD_THREADS 4 CACHE STRING
  "Number of extra threads to start when an IPCP faces thread starvation")
set(IPCP_SCHED_THR_MUL 2 CACHE STRING
  "Number of scheduler threads per QoS cube")

# Linux-specific
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(IPCP_LINUX_TIMERSLACK_NS 100 CACHE STRING
      "Slack value for high resolution timers on Linux systems.")
endif()
