set(IPCP_SOURCE_DIR "${CMAKE_SOURCE_DIR}/src/ipcpd")
set(IPCP_BINARY_DIR "${CMAKE_BINARY_DIR}/src/ipcpd")

set(CONNMGR_RCV_TIMEOUT 1000 CACHE STRING
  "Timeout for the connection manager to wait for OCEP info (ms).")
set(IPCP_DEBUG_LOCAL FALSE CACHE BOOL
  "Use PID as address for local debugging")
set(IPCP_QOS_CUBE_BE_PRIO 50 CACHE STRING
  "Priority for best effort QoS cube (0-99)")
set(IPCP_QOS_CUBE_VIDEO_PRIO 90 CACHE STRING
  "Priority for video QoS cube (0-99)")
set(IPCP_QOS_CUBE_VOICE_PRIO 99 CACHE STRING
  "Priority for voice QoS cube (0-99)")
set(IPCP_MIN_THREADS 4 CACHE STRING
  "Minimum number of worker threads in the IPCP")
set(IPCP_ADD_THREADS 4 CACHE STRING
  "Number of extra threads to start when an IPCP faces thread starvation")
set(IPCP_SCHED_THR_MUL 2 CACHE STRING
  "Number of scheduler threads per QoS cube")
set(DISABLE_CORE_LOCK TRUE CACHE BOOL
  "Disable locking performance threads to a core")

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
   set(IPCP_LINUX_TIMERSLACK_NS 1000 CACHE STRING
       "Slack value for high resolution timers on Linux systems.")
endif ()

if ((IPCP_QOS_CUBE_BE_PRIO LESS 0) OR (IPCP_QOS_CUBE_BE_PRIO GREATER 99))
  message(FATAL_ERROR "Invalid priority for best effort QoS cube")
endif ()

if ((IPCP_QOS_CUBE_VIDEO_PRIO LESS 0) OR (IPCP_QOS_CUBE_VIDEO_PRIO GREATER 99))
  message(FATAL_ERROR "Invalid priority for video QoS cube")
endif ()

if ((IPCP_QOS_CUBE_VOICE_PRIO LESS 0) OR (IPCP_QOS_CUBE_VOICE_PRIO GREATER 99))
  message(FATAL_ERROR "Invalid priority for voice QoS cube")
endif ()

if ((DHT_ENROLL_SLACK LESS 0) OR (DHT_ENROLL_SLACK GREATER 999))
  message(FATAL_ERROR "Invalid DHT slack value")
endif ()

set(IPCP_SOURCES
  "${IPCP_SOURCE_DIR}/ipcp.c"
  "${IPCP_SOURCE_DIR}/shim-data.c"
)

set(COMMON_SOURCES
  "${IPCP_SOURCE_DIR}/common/enroll.c"
)

set(IPCP_INCLUDE_DIRS
  ${IPCP_SOURCE_DIR}
  ${IPCP_BINARY_DIR}
  ${CMAKE_SOURCE_DIR}/include
  ${CMAKE_BINARY_DIR}/include
)
