# Local IPCP configuration options for Ouroboros

set(IPCP_LOCAL_TARGET ipcpd-local)

set(IPCP_LOCAL_MPL 50 CACHE STRING
  "Default maximum packet lifetime for the Local IPCP, in ms")

set(IPCP_LOCAL_MTU 65000 CACHE STRING
  "Layer MTU advertised by the Local IPCP, in bytes")

set(IPCP_LOCAL_POLLING FALSE CACHE BOOL
  "Enable active polling in the Local IPCP for low-latency mode")

# IPCP_LOCAL_MTU must fit in the largest enabled GSPP and PUP class
# (sender-side allocation: daemons use GSPP, apps use PUP). Reserve a
# margin for sizeof(struct ssm_pk_buff) + HEADSPACE + TAILSPACE.
math(EXPR _ssm_pk_overhead
  "${SSM_PK_BUFF_HEADSPACE} + ${SSM_PK_BUFF_TAILSPACE} + 64")

foreach(_pool GSPP PUP)
    set(_largest 0)
    foreach(_pair "256;256" "512;512" "1K;1024" "2K;2048" "4K;4096"
                  "16K;16384" "64K;65536" "256K;262144" "1M;1048576")
        list(GET _pair 0 _name)
        list(GET _pair 1 _bytes)
        if(SSM_${_pool}_${_name}_BLOCKS GREATER 0
           AND _bytes GREATER _largest)
            set(_largest ${_bytes})
        endif()
    endforeach()
    math(EXPR _avail "${_largest} - ${_ssm_pk_overhead}")
    if(IPCP_LOCAL_MTU GREATER _avail)
        message(FATAL_ERROR
            "IPCP_LOCAL_MTU (${IPCP_LOCAL_MTU}) exceeds largest enabled "
            "SSM_${_pool} class minus per-block overhead "
            "(${_largest} - ${_ssm_pk_overhead} = ${_avail} bytes). "
            "Lower IPCP_LOCAL_MTU or enable a larger SSM_${_pool}_*_BLOCKS.")
    endif()
endforeach()
