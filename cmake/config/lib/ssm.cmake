# Secure Shared Memory (SSM) pool configuration for Ouroboros This file defines the allocation
# parameters for the secure shared memory pool allocator

# Shared memory pool naming configuration
set(SSM_PREFIX "ouroboros" CACHE STRING
    "Prefix for secure shared memory pools")

# Pool naming (internal)
set(SSM_GSPP_NAME "/${SSM_PREFIX}.gspp" CACHE INTERNAL
    "Name for the Global Shared Packet Pool")
set(SSM_PUP_NAME_FMT "/${SSM_PREFIX}.pup.%d" CACHE INTERNAL
    "Format string for Per-User Pool names (uid as argument)")

# Packet buffer configuration
set(SSM_POOL_NAME "/${SHM_PREFIX}.pool" CACHE INTERNAL
    "Name for the main POSIX shared memory pool")
set(SSM_PK_BUFF_HEADSPACE 256 CACHE STRING
    "Bytes of headspace to reserve for future headers")
set(SSM_PK_BUFF_TAILSPACE 32 CACHE STRING
    "Bytes of tailspace to reserve for future tails")
set(SSM_RBUFF_SIZE 1024 CACHE STRING
    "Number of slots in a flow's rbuff ring; must be a power of 2")
set(SSM_RBUFF_TXQ_DELAY 10 CACHE STRING
    "Queueing delay a flow's tx ring may hold (ms); 0 is unlimited")
set(SSM_RBUFF_PREFIX "/${SHM_PREFIX}.rbuff." CACHE INTERNAL
    "Prefix for rbuff POSIX shared memory filenames")
set(SSM_FLOW_SET_PREFIX "/${SHM_PREFIX}.set." CACHE INTERNAL
    "Prefix for the POSIX shared memory flow set")

# Number of shards per size class for reducing contention
set(SSM_POOL_SHARDS 4 CACHE STRING
    "Number of allocator shards per size class")
set(SSM_POOL_RECLAIM_AGE_S 60 CACHE STRING
    "Minimum age in seconds before a block is presumed stale and reclaimed")

# Global Shared Packet Pool (GSPP) - for privileged processes Shared by all processes in 'ouroboros'
# group (~60 MB total)
set(SSM_GSPP_256_BLOCKS 1024 CACHE STRING
    "GSPP: Number of 256B blocks")
set(SSM_GSPP_512_BLOCKS 2048 CACHE STRING
    "GSPP: Number of 512B blocks")
set(SSM_GSPP_1K_BLOCKS 512 CACHE STRING
    "GSPP: Number of 1KB blocks")
set(SSM_GSPP_2K_BLOCKS 384 CACHE STRING
    "GSPP: Number of 2KB blocks")
set(SSM_GSPP_4K_BLOCKS 256 CACHE STRING
    "GSPP: Number of 4KB blocks")
set(SSM_GSPP_16K_BLOCKS 128 CACHE STRING
    "GSPP: Number of 16KB blocks")
set(SSM_GSPP_64K_BLOCKS 64 CACHE STRING
    "GSPP: Number of 64KB blocks")
set(SSM_GSPP_256K_BLOCKS 32 CACHE STRING
    "GSPP: Number of 256KB blocks")
set(SSM_GSPP_1M_BLOCKS 16 CACHE STRING
    "GSPP: Number of 1MB blocks")

# Per-User Pool (PUP) - for unprivileged applications Each unprivileged app gets its own smaller
# pool (~7.5 MB total)
set(SSM_PUP_256_BLOCKS 512 CACHE STRING
    "PUP: Number of 256B blocks")
set(SSM_PUP_512_BLOCKS 512 CACHE STRING
    "PUP: Number of 512B blocks")
set(SSM_PUP_1K_BLOCKS 512 CACHE STRING
    "PUP: Number of 1KB blocks")
set(SSM_PUP_2K_BLOCKS 512 CACHE STRING
    "PUP: Number of 2KB blocks")
set(SSM_PUP_4K_BLOCKS 32 CACHE STRING
    "PUP: Number of 4KB blocks")
set(SSM_PUP_16K_BLOCKS 16 CACHE STRING
    "PUP: Number of 16KB blocks")
set(SSM_PUP_64K_BLOCKS 8 CACHE STRING
    "PUP: Number of 64KB blocks")
set(SSM_PUP_256K_BLOCKS 2 CACHE STRING
    "PUP: Number of 256KB blocks")
set(SSM_PUP_1M_BLOCKS 0 CACHE STRING
    "PUP: Number of 1MB blocks")

# Zero classes too small for spb header + HEADSPACE + TAILSPACE + 1 B.
math(EXPR _SSM_MIN_USEFUL_CLASS
    "32 + ${SSM_PK_BUFF_HEADSPACE} + ${SSM_PK_BUFF_TAILSPACE}")
foreach(_pair "256:256" "512:512" "1K:1024" "2K:2048")
    string(REPLACE ":" ";" _p "${_pair}")
    list(GET _p 0 _suffix)
    list(GET _p 1 _size)
    if(_size LESS _SSM_MIN_USEFUL_CLASS)
        set(SSM_GSPP_${_suffix}_BLOCKS 0)
        set(SSM_PUP_${_suffix}_BLOCKS 0)
    endif()
endforeach()
unset(_SSM_MIN_USEFUL_CLASS)
unset(_p)
unset(_suffix)
unset(_size)

# SSM pool size calculations
include(utils/HumanReadable)

math(EXPR SSM_GSPP_TOTAL_SIZE
    "(1 << 8) * ${SSM_GSPP_256_BLOCKS} + \
     (1 << 9) * ${SSM_GSPP_512_BLOCKS} + \
     (1 << 10) * ${SSM_GSPP_1K_BLOCKS} + \
     (1 << 11) * ${SSM_GSPP_2K_BLOCKS} + \
     (1 << 12) * ${SSM_GSPP_4K_BLOCKS} + \
     (1 << 14) * ${SSM_GSPP_16K_BLOCKS} + \
     (1 << 16) * ${SSM_GSPP_64K_BLOCKS} + \
     (1 << 18) * ${SSM_GSPP_256K_BLOCKS} + \
     (1 << 20) * ${SSM_GSPP_1M_BLOCKS}")

set(SSM_GSPP_TOTAL_SIZE ${SSM_GSPP_TOTAL_SIZE} CACHE INTERNAL
    "GSPP total size in bytes")

math(EXPR SSM_PUP_TOTAL_SIZE
    "(1 << 8) * ${SSM_PUP_256_BLOCKS} + \
     (1 << 9) * ${SSM_PUP_512_BLOCKS} + \
     (1 << 10) * ${SSM_PUP_1K_BLOCKS} + \
     (1 << 11) * ${SSM_PUP_2K_BLOCKS} + \
     (1 << 12) * ${SSM_PUP_4K_BLOCKS} + \
     (1 << 14) * ${SSM_PUP_16K_BLOCKS} + \
     (1 << 16) * ${SSM_PUP_64K_BLOCKS} + \
     (1 << 18) * ${SSM_PUP_256K_BLOCKS} + \
     (1 << 20) * ${SSM_PUP_1M_BLOCKS}")

set(SSM_PUP_TOTAL_SIZE ${SSM_PUP_TOTAL_SIZE} CACHE INTERNAL
    "PUP total size in bytes")

set(SSM_POOL_TOTAL_SIZE ${SSM_GSPP_TOTAL_SIZE} CACHE INTERNAL
    "Total shared memory pool size in bytes")

format_bytes_human_readable(${SSM_GSPP_TOTAL_SIZE} SSM_GSPP_SIZE_DISPLAY)
format_bytes_human_readable(${SSM_PUP_TOTAL_SIZE} SSM_PUP_SIZE_DISPLAY)

message(STATUS "Secure Shared Memory Pool Configuration:")
message(STATUS "  Pool prefix: ${SSM_PREFIX}")
message(STATUS "  Size classes: "
    "256B, 512B, 1KiB, 2KiB, 4KiB, 16KiB, 64KiB, 256KiB, 1MiB")
message(STATUS "  Max allocation: 1 MB")
message(STATUS "  Shards per class: ${SSM_POOL_SHARDS}")
message(STATUS "  GSPP (privileged): ${SSM_GSPP_SIZE_DISPLAY} "
    "(${SSM_GSPP_TOTAL_SIZE} bytes)")
message(STATUS "    Blocks: ${SSM_GSPP_256_BLOCKS}, ${SSM_GSPP_512_BLOCKS}, "
    "${SSM_GSPP_1K_BLOCKS}, ${SSM_GSPP_2K_BLOCKS}, ${SSM_GSPP_4K_BLOCKS}, "
    "${SSM_GSPP_16K_BLOCKS}, ${SSM_GSPP_64K_BLOCKS}, ${SSM_GSPP_256K_BLOCKS}, "
    "${SSM_GSPP_1M_BLOCKS}")
message(STATUS "  PUP (unprivileged): ${SSM_PUP_SIZE_DISPLAY} "
    "(${SSM_PUP_TOTAL_SIZE} bytes)")
message(STATUS "    Blocks: ${SSM_PUP_256_BLOCKS}, ${SSM_PUP_512_BLOCKS}, "
    "${SSM_PUP_1K_BLOCKS}, ${SSM_PUP_2K_BLOCKS}, ${SSM_PUP_4K_BLOCKS}, "
    "${SSM_PUP_16K_BLOCKS}, ${SSM_PUP_64K_BLOCKS}, ${SSM_PUP_256K_BLOCKS}, "
    "${SSM_PUP_1M_BLOCKS}")

# FRCT reorder queue must fit in every enabled size class. If RQ_SIZE >= any backing pool, the
# receiver advertises a window the pool cannot back; np1_flow_write fails under load and a single
# dropped fragment wedges the flow. Auto-zeroed classes are skipped.
foreach(_class 256 512 1K 2K)
    if(SSM_PUP_${_class}_BLOCKS GREATER 0
       AND NOT FRCT_REORDER_QUEUE_SIZE LESS SSM_PUP_${_class}_BLOCKS)
        message(FATAL_ERROR
            "FRCT_REORDER_QUEUE_SIZE (${FRCT_REORDER_QUEUE_SIZE}) must be "
            "< SSM_PUP_${_class}_BLOCKS (${SSM_PUP_${_class}_BLOCKS}): "
            "the FC window cannot exceed the pool that backs OOO stashing.")
    endif()
    if(SSM_GSPP_${_class}_BLOCKS GREATER 0
       AND NOT FRCT_REORDER_QUEUE_SIZE LESS SSM_GSPP_${_class}_BLOCKS)
        message(FATAL_ERROR
            "FRCT_REORDER_QUEUE_SIZE (${FRCT_REORDER_QUEUE_SIZE}) must be "
            "< SSM_GSPP_${_class}_BLOCKS (${SSM_GSPP_${_class}_BLOCKS}).")
    endif()
endforeach()
